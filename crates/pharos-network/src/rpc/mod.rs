//! Req-resp protocol: protocol IDs, request/response types, SSZ-snappy codec.
//!
//! Protocol family per `specs/phase0/p2p-interface.md:1077-1092`.

pub mod codec;
pub mod handler;
pub mod min_epochs;
pub mod protocol;
pub mod size_bounds;
pub mod types;
pub mod varint;

pub use protocol::RpcProtocol;
pub use types::{MAX_REQUEST_BLOCKS, RpcRequest, RpcResponse};
