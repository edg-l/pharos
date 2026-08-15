//! SSZ-snappy codec for Ethereum CL req-resp.
//!
//! Implements `libp2p::request_response::Codec` for the Ethereum Phase-0
//! req-resp protocol family. Each message is encoded as:
//!
//!   `<varint ssz_len><snappy_frame_compressed_ssz>`
//!
//! Responses are chunked: each chunk starts with a 1-byte result code
//! (`0` = success, `1` = invalid-request, `2` = server-error,
//! `3` = resource-unavailable), followed by a varint-length-prefixed
//! SSZ-snappy payload.
//!
//! Per `specs/phase0/p2p-interface.md:1264-1308`.

use std::io;
use std::marker::PhantomData;
use std::sync::Arc;

use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use pharos_ssz::{Decode, Encode};
use pharos_types::EthSpec;
use pharos_types::altair::MetaData as AltairMetaData;
use pharos_types::phase0::{
    BeaconBlocksByRangeRequest, BeaconBlocksByRootRequest, ErrorMessage, MetaData, Status,
};

use crate::codec::snappy_frame::encode_snappy_frame;
use crate::host::ForkContext;
use crate::rpc::protocol::RpcProtocol;
use crate::rpc::size_bounds::{MAX_SIGNED_BEACON_BLOCK_SSZ_BYTES, type_size_bounds};
use crate::rpc::types::{
    LightClientBootstrapRequest, LightClientUpdatesByRangeRequest, MAX_REQUEST_BLOCKS,
    MetaDataResponse, RpcRequest, RpcResponse,
};
use crate::rpc::varint::{read_varint, write_varint};
use crate::scoring::RpcMethod;
use crate::types::Fork;

// ── RpcCodec ──────────────────────────────────────────────────────────────────

/// The Ethereum CL req-resp codec.
///
/// Generic over `E: EthSpec` because `RpcResponse<E>` carries
/// `E::SignedBeaconBlock` values in `BlocksByRange` / `BlocksByRoot` variants.
///
/// `fork_context` is used to encode/decode the 4-byte context prefix on
/// response chunks for methods where `has_context_bytes()` returns `true`,
/// per `specs/altair/p2p-interface.md:445-461`. When `None`, context-bytes
/// methods fall back to treating every chunk as Phase-0 SSZ (safe for
/// unit tests that don't exercise context-bytes paths).
#[derive(Clone)]
pub struct RpcCodec<E: EthSpec> {
    fork_context: Option<Arc<dyn ForkContext>>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> Default for RpcCodec<E> {
    fn default() -> Self {
        Self {
            fork_context: None,
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec> RpcCodec<E> {
    /// Construct a codec with a `ForkContext` for context-bytes decoding.
    pub fn with_fork_context(ctx: Arc<dyn ForkContext>) -> Self {
        Self {
            fork_context: Some(ctx),
            _phantom: PhantomData,
        }
    }
}

// ── Codec impl ────────────────────────────────────────────────────────────────

#[async_trait]
impl<E: EthSpec + Send + Sync + 'static> libp2p::request_response::Codec for RpcCodec<E> {
    type Protocol = RpcProtocol;
    type Request = RpcRequest;
    type Response = RpcResponse<E>;

    async fn read_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let method = &protocol.0;

        // MetaData (v1 and v2) has no request body.
        if matches!(method, RpcMethod::MetaData) {
            return Ok(RpcRequest::MetaData);
        }
        if matches!(method, RpcMethod::MetaDataV1) {
            return Ok(RpcRequest::MetaDataV1);
        }
        // Light-client methods with no request body.
        if matches!(method, RpcMethod::LightClientFinalityUpdate) {
            return Ok(RpcRequest::LightClientFinalityUpdate);
        }
        if matches!(method, RpcMethod::LightClientOptimisticUpdate) {
            return Ok(RpcRequest::LightClientOptimisticUpdate);
        }

        let ssz_len = read_varint(io).await.map_err(io_err)? as usize;

        let (min, max) = type_size_bounds(method);
        if ssz_len < min || ssz_len > max {
            return Err(io::Error::other("ssz length out of bounds"));
        }

        let bytes = read_bounded_snappy(io, ssz_len).await?;
        decode_request(method, &bytes)
    }

    async fn read_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let method = &protocol.0;

        // Accumulators for streaming list methods.
        let mut blocks: Vec<E::SignedBeaconBlock> = Vec::new();
        let mut lc_updates: Vec<E::AltairLightClientUpdate> = Vec::new();
        let mut first_response: Option<RpcResponse<E>> = None;

        loop {
            // Try to read the result code byte. EOF before the first byte on a
            // list method means an empty list (zero blocks).
            let mut code_buf = [0u8; 1];
            if io.read(&mut code_buf).await? == 0 {
                break; // stream half-closed
            }
            let code = code_buf[0];

            if code != 0 {
                // Error chunk (codes 1, 2, 3): read ErrorMessage and return.
                let msg = read_ssz_snappy_payload::<_, ErrorMessage>(io, 256 + 8).await?;
                return Ok(RpcResponse::Error { code, message: msg });
            }

            // For methods with context bytes, read the 4-byte fork digest prefix
            // before the SSZ-snappy payload per `specs/altair/p2p-interface.md:445-461`.
            let chunk_fork: Option<Fork> = if method.has_context_bytes() {
                let mut ctx = [0u8; 4];
                io.read_exact(&mut ctx).await?;
                let fc = self.fork_context.as_ref().ok_or_else(|| {
                    io::Error::other("missing fork context: cannot decode context bytes")
                })?;
                match fc.fork_from_context(&ctx) {
                    Some(f) => Some(f),
                    None => {
                        return Err(io::Error::other("unknown context bytes in response chunk"));
                    }
                }
            } else {
                None
            };

            // For light-client methods, context bytes MUST indicate Altair or Capella.
            // Catch misbehaving peers that send wrong-fork context bytes for
            // LC methods per `specs/altair/light-client/p2p-interface.md` and
            // `specs/capella/light-client/p2p-interface.md`.
            match method {
                RpcMethod::LightClientBootstrap
                | RpcMethod::LightClientUpdatesByRange
                | RpcMethod::LightClientFinalityUpdate
                | RpcMethod::LightClientOptimisticUpdate
                    if !matches!(chunk_fork, Some(Fork::Altair) | Some(Fork::Capella)) =>
                {
                    return Err(io::Error::other(
                        "light-client chunk has non-altair/capella context bytes",
                    ));
                }
                _ => {}
            }

            // Success chunk: decode per method.
            match method {
                RpcMethod::Status => {
                    let s = read_ssz_snappy_payload::<_, Status>(io, 84).await?;
                    first_response = Some(RpcResponse::Status(s));
                    break; // single-response method
                }
                RpcMethod::Goodbye => {
                    let v = read_ssz_snappy_payload::<_, u64>(io, 8).await?;
                    first_response = Some(RpcResponse::Goodbye(v));
                    break;
                }
                RpcMethod::Ping => {
                    let v = read_ssz_snappy_payload::<_, u64>(io, 8).await?;
                    first_response = Some(RpcResponse::Ping(v));
                    break;
                }
                // MetaData v2 (altair): decode altair MetaData (seq + attnets + syncnets).
                // Altair MetaData SSZ: 8 (seq_number) + 8 (attnets Bitvector[64]) + 1 (syncnets Bitvector[4], SSZ-encodes to 1 byte) = 17 bytes.
                // Use a generous 64-byte max to accommodate future additions.
                RpcMethod::MetaData => {
                    let m = read_ssz_snappy_payload::<_, AltairMetaData>(io, 64).await?;
                    first_response = Some(RpcResponse::MetaData(MetaDataResponse::V2(m)));
                    break;
                }
                // MetaData v1 (phase-0): decode phase-0 MetaData (seq_number + attnets only).
                // Phase-0 MetaData SSZ: 8 (seq_number) + 8 (attnets/64 bits) = 16 bytes.
                RpcMethod::MetaDataV1 => {
                    let m = read_ssz_snappy_payload::<_, MetaData>(io, 16).await?;
                    first_response = Some(RpcResponse::MetaData(MetaDataResponse::V1(m)));
                    break;
                }
                RpcMethod::BlocksByRange | RpcMethod::BlocksByRoot => {
                    if blocks.len() >= MAX_REQUEST_BLOCKS as usize {
                        return Err(io::Error::other("response exceeds MAX_REQUEST_BLOCKS"));
                    }
                    // Dispatch SSZ decode based on the chunk's fork (context bytes).
                    let block = match chunk_fork {
                        Some(Fork::Capella) => {
                            let inner = read_ssz_snappy_payload::<_, E::CapellaSignedBeaconBlock>(
                                io,
                                MAX_SIGNED_BEACON_BLOCK_SSZ_BYTES,
                            )
                            .await?;
                            E::capella_into_signed_block(inner)
                        }
                        Some(Fork::Bellatrix) => {
                            let inner =
                                read_ssz_snappy_payload::<_, E::BellatrixSignedBeaconBlock>(
                                    io,
                                    MAX_SIGNED_BEACON_BLOCK_SSZ_BYTES,
                                )
                                .await?;
                            E::bellatrix_into_signed_block(inner)
                        }
                        Some(Fork::Altair) => {
                            let inner = read_ssz_snappy_payload::<_, E::AltairSignedBeaconBlock>(
                                io,
                                MAX_SIGNED_BEACON_BLOCK_SSZ_BYTES,
                            )
                            .await?;
                            E::altair_into_signed_block(inner)
                        }
                        // Phase0 or no context (legacy / test path).
                        Some(Fork::Phase0) | None => {
                            let inner = read_ssz_snappy_payload::<_, E::Phase0SignedBeaconBlock>(
                                io,
                                MAX_SIGNED_BEACON_BLOCK_SSZ_BYTES,
                            )
                            .await?;
                            E::phase0_into_signed_block(inner)
                        }
                    };
                    blocks.push(block);
                    // Continue reading chunks.
                }
                // Light-client response decoders per `specs/altair/light-client/p2p-interface.md`.
                // All four carry context bytes (already read above); context is always Altair for now.
                RpcMethod::LightClientBootstrap => {
                    let bootstrap = read_ssz_snappy_payload::<_, E::AltairLightClientBootstrap>(
                        io,
                        crate::rpc::size_bounds::MAX_LIGHT_CLIENT_OBJECT_SSZ_BYTES,
                    )
                    .await?;
                    first_response = Some(RpcResponse::LightClientBootstrap(bootstrap));
                    break;
                }
                RpcMethod::LightClientUpdatesByRange => {
                    // Streaming: each success chunk is one LightClientUpdate.
                    // Clamp to MAX_REQUEST_LIGHT_CLIENT_UPDATES per spec.
                    if lc_updates.len()
                        >= crate::rpc::types::MAX_REQUEST_LIGHT_CLIENT_UPDATES as usize
                    {
                        return Err(io::Error::other(
                            "response exceeds MAX_REQUEST_LIGHT_CLIENT_UPDATES",
                        ));
                    }
                    let update = read_ssz_snappy_payload::<_, E::AltairLightClientUpdate>(
                        io,
                        crate::rpc::size_bounds::MAX_LIGHT_CLIENT_OBJECT_SSZ_BYTES,
                    )
                    .await?;
                    lc_updates.push(update);
                    // Continue reading chunks.
                }
                RpcMethod::LightClientFinalityUpdate => {
                    let update = read_ssz_snappy_payload::<_, E::AltairLightClientFinalityUpdate>(
                        io,
                        crate::rpc::size_bounds::MAX_LIGHT_CLIENT_OBJECT_SSZ_BYTES,
                    )
                    .await?;
                    first_response = Some(RpcResponse::LightClientFinalityUpdate(update));
                    break;
                }
                RpcMethod::LightClientOptimisticUpdate => {
                    let update =
                        read_ssz_snappy_payload::<_, E::AltairLightClientOptimisticUpdate>(
                            io,
                            crate::rpc::size_bounds::MAX_LIGHT_CLIENT_OBJECT_SSZ_BYTES,
                        )
                        .await?;
                    first_response = Some(RpcResponse::LightClientOptimisticUpdate(update));
                    break;
                }
            }
        }

        if let Some(resp) = first_response {
            return Ok(resp);
        }

        // List responses (or empty stream for list methods).
        match method {
            RpcMethod::BlocksByRange => Ok(RpcResponse::BlocksByRange(blocks)),
            RpcMethod::BlocksByRoot => Ok(RpcResponse::BlocksByRoot(blocks)),
            RpcMethod::LightClientUpdatesByRange => {
                Ok(RpcResponse::LightClientUpdatesByRange(lc_updates))
            }
            _ => {
                // Single-response method with zero chunks.
                Err(io::Error::other(
                    "expected response chunk; stream closed early",
                ))
            }
        }
    }

    async fn write_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let method = &protocol.0;

        // Methods with no request body.
        if matches!(
            method,
            RpcMethod::MetaData
                | RpcMethod::MetaDataV1
                | RpcMethod::LightClientFinalityUpdate
                | RpcMethod::LightClientOptimisticUpdate
        ) {
            return Ok(());
        }

        let ssz = encode_request_ssz(req)?;
        write_ssz_snappy(io, &ssz).await
    }

    async fn write_response<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let _method = &protocol.0;
        match res {
            RpcResponse::Error { code, message } => {
                io.write_all(&[code]).await?;
                write_ssz_snappy(io, &message.as_ssz_bytes()).await?;
            }
            RpcResponse::Status(s) => {
                io.write_all(&[0]).await?;
                write_ssz_snappy(io, &s.as_ssz_bytes()).await?;
            }
            RpcResponse::Goodbye(v) => {
                io.write_all(&[0]).await?;
                write_ssz_snappy(io, &v.as_ssz_bytes()).await?;
            }
            RpcResponse::Ping(v) => {
                io.write_all(&[0]).await?;
                write_ssz_snappy(io, &v.as_ssz_bytes()).await?;
            }
            RpcResponse::MetaData(m) => {
                io.write_all(&[0]).await?;
                // Dispatch SSZ encoding based on the MetaData variant.
                match m {
                    MetaDataResponse::V1(v1) => {
                        write_ssz_snappy(io, &v1.as_ssz_bytes()).await?;
                    }
                    MetaDataResponse::V2(v2) => {
                        write_ssz_snappy(io, &v2.as_ssz_bytes()).await?;
                    }
                }
            }
            RpcResponse::LightClientBootstrap(bootstrap) => {
                let fc = self.fork_context.as_deref().ok_or_else(|| {
                    io::Error::other("missing fork context: cannot encode context bytes")
                })?;
                io.write_all(&[0]).await?;
                io.write_all(&fc.fork_digest_for(Fork::Altair).into_inner())
                    .await?;
                write_ssz_snappy(io, &bootstrap.as_ssz_bytes()).await?;
            }
            RpcResponse::LightClientUpdatesByRange(updates) => {
                let fc = self.fork_context.as_deref().ok_or_else(|| {
                    io::Error::other("missing fork context: cannot encode context bytes")
                })?;
                for update in &updates {
                    io.write_all(&[0]).await?;
                    io.write_all(&fc.fork_digest_for(Fork::Altair).into_inner())
                        .await?;
                    write_ssz_snappy(io, &update.as_ssz_bytes()).await?;
                }
            }
            RpcResponse::LightClientFinalityUpdate(update) => {
                let fc = self.fork_context.as_deref().ok_or_else(|| {
                    io::Error::other("missing fork context: cannot encode context bytes")
                })?;
                io.write_all(&[0]).await?;
                io.write_all(&fc.fork_digest_for(Fork::Altair).into_inner())
                    .await?;
                write_ssz_snappy(io, &update.as_ssz_bytes()).await?;
            }
            RpcResponse::LightClientOptimisticUpdate(update) => {
                let fc = self.fork_context.as_deref().ok_or_else(|| {
                    io::Error::other("missing fork context: cannot encode context bytes")
                })?;
                io.write_all(&[0]).await?;
                io.write_all(&fc.fork_digest_for(Fork::Altair).into_inner())
                    .await?;
                write_ssz_snappy(io, &update.as_ssz_bytes()).await?;
            }
            RpcResponse::BlocksByRange(blocks) | RpcResponse::BlocksByRoot(blocks) => {
                let fc = self.fork_context.as_deref().ok_or_else(|| {
                    io::Error::other("missing fork context: cannot encode context bytes")
                })?;
                for block in &blocks {
                    // Write 4 context bytes (fork digest) before the SSZ payload
                    // per `specs/altair/p2p-interface.md:445-461` and
                    // `specs/capella/p2p-interface.md`.
                    // Dispatch to the inner SSZ bytes (no fork discriminant byte).
                    let (fork, ssz) = if let Some(inner) = E::unwrap_capella_signed_block(block) {
                        (Fork::Capella, inner.as_ssz_bytes())
                    } else if let Some(inner) = E::unwrap_bellatrix_signed_block(block) {
                        (Fork::Bellatrix, inner.as_ssz_bytes())
                    } else if let Some(inner) = E::unwrap_altair_signed_block(block) {
                        (Fork::Altair, inner.as_ssz_bytes())
                    } else if let Some(inner) = E::unwrap_phase0_signed_block(block) {
                        (Fork::Phase0, inner.as_ssz_bytes())
                    } else {
                        return Err(io::Error::other(
                            "cannot encode context bytes: block variant has no known fork",
                        ));
                    };
                    io.write_all(&[0]).await?;
                    io.write_all(&fc.fork_digest_for(fork).into_inner()).await?;
                    write_ssz_snappy(io, &ssz).await?;
                }
            }
        }
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Read exactly `expected` decompressed bytes from a snappy-framed stream,
/// pulling only as many compressed frames from the source as needed. Does not
/// over-read past the current chunk's snappy stream — safe to call repeatedly
/// for multi-chunk responses.
///
/// Per Google's snappy framing format
/// (<https://github.com/google/snappy/blob/main/framing_format.txt>):
/// - Stream identifier: type `0xff`, payload `"sNaPpY"` (6 bytes).
/// - Compressed data: type `0x00`, payload `[crc:4][snappy_block]`.
/// - Uncompressed data: type `0x01`, payload `[crc:4][raw_bytes]`.
/// - Padding: type `0xfe`, skipped.
/// - Reserved skippable: types `0x80..=0xfd`, skipped.
/// - Reserved unskippable: types `0x02..=0x7f`, error.
async fn read_bounded_snappy<T: AsyncRead + Unpin>(
    io: &mut T,
    expected: usize,
) -> io::Result<Vec<u8>> {
    let mut decoded: Vec<u8> = Vec::with_capacity(expected);
    let mut raw_decoder = snap::raw::Decoder::new();
    let mut saw_stream_id = false;

    while decoded.len() < expected {
        let mut header = [0u8; 4];
        io.read_exact(&mut header).await?;
        let chunk_type = header[0];
        let chunk_len = u32::from_le_bytes([header[1], header[2], header[3], 0]) as usize;

        match chunk_type {
            0xff => {
                if chunk_len != 6 {
                    return Err(io::Error::other("bad snappy stream-id length"));
                }
                let mut payload = [0u8; 6];
                io.read_exact(&mut payload).await?;
                if &payload != b"sNaPpY" {
                    return Err(io::Error::other("bad snappy stream-id payload"));
                }
                saw_stream_id = true;
            }
            0x00 => {
                if !saw_stream_id {
                    return Err(io::Error::other("compressed frame before stream-id"));
                }
                if chunk_len < 4 {
                    return Err(io::Error::other("compressed frame too short"));
                }
                let mut payload = vec![0u8; chunk_len];
                io.read_exact(&mut payload).await?;
                let compressed = &payload[4..];
                let frame_decoded_len = snap::raw::decompress_len(compressed)
                    .map_err(|e| io::Error::other(format!("snappy decompress_len: {e}")))?;
                if decoded.len() + frame_decoded_len > expected {
                    return Err(io::Error::other(
                        "snappy frame would exceed expected uncompressed length",
                    ));
                }
                let start = decoded.len();
                decoded.resize(start + frame_decoded_len, 0);
                raw_decoder
                    .decompress(compressed, &mut decoded[start..])
                    .map_err(|e| io::Error::other(format!("snappy decompress: {e}")))?;
            }
            0x01 => {
                if !saw_stream_id {
                    return Err(io::Error::other("uncompressed frame before stream-id"));
                }
                if chunk_len < 4 {
                    return Err(io::Error::other("uncompressed frame too short"));
                }
                let mut payload = vec![0u8; chunk_len];
                io.read_exact(&mut payload).await?;
                let raw = &payload[4..];
                if decoded.len() + raw.len() > expected {
                    return Err(io::Error::other(
                        "snappy frame would exceed expected uncompressed length",
                    ));
                }
                decoded.extend_from_slice(raw);
            }
            0xfe => {
                let mut payload = vec![0u8; chunk_len];
                io.read_exact(&mut payload).await?;
            }
            t if t >= 0x80 => {
                let mut payload = vec![0u8; chunk_len];
                io.read_exact(&mut payload).await?;
            }
            _ => {
                return Err(io::Error::other(format!(
                    "unknown snappy chunk type {chunk_type:#x}"
                )));
            }
        }
    }

    Ok(decoded)
}

/// Read a varint-length-prefixed SSZ-snappy payload and SSZ-decode it.
///
/// Reads exactly `ssz_len` decompressed bytes; safe across multi-chunk
/// response boundaries.
async fn read_ssz_snappy_payload<T, D>(io: &mut T, max_ssz: usize) -> io::Result<D>
where
    T: AsyncRead + Unpin,
    D: Decode,
{
    let ssz_len = read_varint(io).await.map_err(io_err)? as usize;
    if ssz_len > max_ssz {
        return Err(io::Error::other("ssz length out of bounds"));
    }
    let bytes = read_bounded_snappy(io, ssz_len).await?;
    D::from_ssz_bytes(&bytes).map_err(|e| io::Error::other(format!("ssz decode: {e}")))
}

/// SSZ-encode and write a varint-prefixed snappy-framed payload.
async fn write_ssz_snappy<W: AsyncWrite + Unpin>(w: &mut W, ssz: &[u8]) -> io::Result<()> {
    write_varint(w, ssz.len() as u64).await.map_err(io_err)?;
    let compressed =
        encode_snappy_frame(ssz).map_err(|e| io::Error::other(format!("snappy encode: {e}")))?;
    w.write_all(&compressed).await
}

/// SSZ-encode an `RpcRequest` variant into raw bytes.
fn encode_request_ssz(req: RpcRequest) -> io::Result<Vec<u8>> {
    Ok(match req {
        RpcRequest::Status(s) => s.as_ssz_bytes(),
        RpcRequest::Goodbye(v) => v.as_ssz_bytes(),
        RpcRequest::Ping(v) => v.as_ssz_bytes(),
        RpcRequest::MetaData | RpcRequest::MetaDataV1 => Vec::new(),
        RpcRequest::BlocksByRange(r) => r.as_ssz_bytes(),
        RpcRequest::BlocksByRoot(r) => r.as_ssz_bytes(),
        // LightClientBootstrap carries a Root (32 bytes) as the request body.
        RpcRequest::LightClientBootstrap(req) => req.0.as_ssz_bytes(),
        // LightClientUpdatesByRange carries start_period and count (both u64 = 16 bytes).
        RpcRequest::LightClientUpdatesByRange(req) => {
            let mut bytes = Vec::with_capacity(16);
            bytes.extend_from_slice(&req.start_period.as_ssz_bytes());
            bytes.extend_from_slice(&req.count.as_ssz_bytes());
            bytes
        }
        // These two have no body; the write_request fast-path handles them before
        // calling encode_request_ssz, so this arm is unreachable.
        RpcRequest::LightClientFinalityUpdate | RpcRequest::LightClientOptimisticUpdate => {
            Vec::new()
        }
    })
}

/// SSZ-decode an `RpcRequest` from raw bytes for the given method.
fn decode_request(method: &RpcMethod, bytes: &[u8]) -> io::Result<RpcRequest> {
    match method {
        RpcMethod::Status => {
            let s = Status::from_ssz_bytes(bytes)
                .map_err(|e| io::Error::other(format!("ssz decode Status: {e}")))?;
            Ok(RpcRequest::Status(s))
        }
        RpcMethod::Goodbye => {
            let v = u64::from_ssz_bytes(bytes)
                .map_err(|e| io::Error::other(format!("ssz decode u64: {e}")))?;
            Ok(RpcRequest::Goodbye(v))
        }
        RpcMethod::Ping => {
            let v = u64::from_ssz_bytes(bytes)
                .map_err(|e| io::Error::other(format!("ssz decode u64: {e}")))?;
            Ok(RpcRequest::Ping(v))
        }
        RpcMethod::MetaData => Ok(RpcRequest::MetaData),
        RpcMethod::MetaDataV1 => Ok(RpcRequest::MetaDataV1),
        RpcMethod::BlocksByRange => {
            let r = BeaconBlocksByRangeRequest::from_ssz_bytes(bytes)
                .map_err(|e| io::Error::other(format!("ssz decode BlocksByRange: {e}")))?;
            Ok(RpcRequest::BlocksByRange(r))
        }
        RpcMethod::BlocksByRoot => {
            let r = BeaconBlocksByRootRequest::<MAX_REQUEST_BLOCKS>::from_ssz_bytes(bytes)
                .map_err(|e| io::Error::other(format!("ssz decode BlocksByRoot: {e}")))?;
            Ok(RpcRequest::BlocksByRoot(r))
        }
        // Light-client request decoders per `specs/altair/light-client/p2p-interface.md`.
        RpcMethod::LightClientBootstrap => {
            use pharos_types::phase0::primitives::Root;
            let root = Root::from_ssz_bytes(bytes)
                .map_err(|e| io::Error::other(format!("ssz decode Root: {e}")))?;
            Ok(RpcRequest::LightClientBootstrap(
                LightClientBootstrapRequest(root),
            ))
        }
        RpcMethod::LightClientUpdatesByRange => {
            if bytes.len() != 16 {
                return Err(io::Error::other(
                    "LightClientUpdatesByRange request must be 16 bytes (start_period + count)",
                ));
            }
            let start_period = u64::from_ssz_bytes(&bytes[..8])
                .map_err(|e| io::Error::other(format!("ssz decode start_period: {e}")))?;
            let count = u64::from_ssz_bytes(&bytes[8..])
                .map_err(|e| io::Error::other(format!("ssz decode count: {e}")))?;
            Ok(RpcRequest::LightClientUpdatesByRange(
                LightClientUpdatesByRangeRequest {
                    start_period,
                    count,
                },
            ))
        }
        // These two have no body; the read_request fast-path handles them before
        // calling decode_request, so this arm is unreachable.
        RpcMethod::LightClientFinalityUpdate => Ok(RpcRequest::LightClientFinalityUpdate),
        RpcMethod::LightClientOptimisticUpdate => Ok(RpcRequest::LightClientOptimisticUpdate),
    }
}

/// Convert a `NetworkError` into an `io::Error`.
fn io_err(e: crate::error::NetworkError) -> io::Error {
    match e {
        crate::error::NetworkError::Io(e) => e,
        other => io::Error::other(other.to_string()),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::request_response::Codec as _;
    use pharos_types::MainnetEthSpec;
    use pharos_types::phase0::Status;
    use pharos_utils::{Bytes4, Epoch, Hash256, Slot};

    /// Roundtrip a `Status` request through write_request → read_request.
    ///
    /// Uses a `Vec<u8>` as the write buffer; we then wrap it in a
    /// `futures::io::Cursor` to read back.
    #[tokio::test]
    async fn status_request_roundtrip() {
        let original = Status {
            fork_digest: Bytes4::from_array([0xde, 0xad, 0xbe, 0xef]),
            finalized_root: Hash256::from_array([0x11u8; 32]),
            finalized_epoch: Epoch(99),
            head_root: Hash256::from_array([0x22u8; 32]),
            head_slot: Slot(800),
        };

        let protocol = RpcProtocol(RpcMethod::Status);
        let mut codec = RpcCodec::<MainnetEthSpec>::default();

        // Write the request into a Vec<u8>.
        let mut buf: Vec<u8> = Vec::new();
        codec
            .write_request(&protocol, &mut buf, RpcRequest::Status(original.clone()))
            .await
            .expect("write_request failed");

        // Show the encoded bytes so the report can include them.
        let ssz = original.as_ssz_bytes();
        println!("Status SSZ bytes ({} bytes): {:02x?}", ssz.len(), ssz);
        println!("Status encoded on wire ({} bytes): {:02x?}", buf.len(), buf);

        // Read it back via a Cursor.
        let mut reader = futures::io::Cursor::new(buf);
        let req = codec
            .read_request(&protocol, &mut reader)
            .await
            .expect("read_request failed");

        match req {
            RpcRequest::Status(decoded) => {
                assert_eq!(decoded, original, "decoded Status must equal original");
            }
            other => panic!("expected RpcRequest::Status, got: {other:?}"),
        }
    }

    /// Roundtrip a `MetaData` request (no body).
    #[tokio::test]
    async fn metadata_request_roundtrip() {
        let protocol = RpcProtocol(RpcMethod::MetaData);
        let mut codec = RpcCodec::<MainnetEthSpec>::default();

        let mut buf: Vec<u8> = Vec::new();
        codec
            .write_request(&protocol, &mut buf, RpcRequest::MetaData)
            .await
            .expect("write_request failed");
        assert!(buf.is_empty(), "MetaData request must produce no bytes");

        let mut reader = futures::io::Cursor::new(buf);
        let req = codec
            .read_request(&protocol, &mut reader)
            .await
            .expect("read_request failed");

        assert!(matches!(req, RpcRequest::MetaData));
    }

    /// Verify the bounded snappy reader does not over-read past one chunk.
    ///
    /// Writes two `Ping` response chunks back-to-back, reads the first, then
    /// reads the second from the same cursor and asserts both decode cleanly.
    /// Regression guard for the multi-chunk over-read fix.
    #[tokio::test]
    async fn multi_chunk_no_overread() {
        let protocol = RpcProtocol(RpcMethod::Ping);
        let mut codec = RpcCodec::<MainnetEthSpec>::default();

        let mut buf: Vec<u8> = Vec::new();
        codec
            .write_response(&protocol, &mut buf, RpcResponse::Ping(42))
            .await
            .expect("write 1");
        codec
            .write_response(&protocol, &mut buf, RpcResponse::Ping(99))
            .await
            .expect("write 2");

        let mut reader = futures::io::Cursor::new(buf);
        let first = codec
            .read_response(&protocol, &mut reader)
            .await
            .expect("read 1");
        assert!(matches!(first, RpcResponse::Ping(42)));
        let second = codec
            .read_response(&protocol, &mut reader)
            .await
            .expect("read 2");
        assert!(matches!(second, RpcResponse::Ping(99)));
    }

    /// Roundtrip a `Status` response through write_response → read_response.
    #[tokio::test]
    async fn status_response_roundtrip() {
        let original = Status {
            fork_digest: Bytes4::from_array([0xca, 0xfe, 0xba, 0xbe]),
            finalized_root: Hash256::from_array([0xabu8; 32]),
            finalized_epoch: Epoch(42),
            head_root: Hash256::from_array([0xcdu8; 32]),
            head_slot: Slot(1024),
        };

        let protocol = RpcProtocol(RpcMethod::Status);
        let mut codec = RpcCodec::<MainnetEthSpec>::default();

        let mut buf: Vec<u8> = Vec::new();
        codec
            .write_response(&protocol, &mut buf, RpcResponse::Status(original.clone()))
            .await
            .expect("write_response failed");

        let mut reader = futures::io::Cursor::new(buf);
        let resp = codec
            .read_response(&protocol, &mut reader)
            .await
            .expect("read_response failed");

        match resp {
            RpcResponse::Status(decoded) => {
                assert_eq!(
                    decoded, original,
                    "decoded Status response must equal original"
                );
            }
            other => panic!("expected RpcResponse::Status, got: {other:?}"),
        }
    }
}
