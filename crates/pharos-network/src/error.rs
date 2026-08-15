//! Network error types.

use thiserror::Error;

/// Errors that can occur in the pharos-network layer.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// Underlying I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// libp2p transport or behaviour error.
    #[error("libp2p error: {0}")]
    Libp2p(String),

    /// discv5 discovery error.
    #[error("discv5 error: {0}")]
    Discv5(String),

    /// SSZ decoding error.
    #[error("SSZ decode error: {0}")]
    Ssz(#[from] pharos_ssz::SszError),

    /// Snappy compression/decompression error.
    #[error("snappy error: {0}")]
    Snappy(String),

    /// Gossip topic string is not a valid eth2 topic.
    #[error("invalid topic: {0}")]
    InvalidTopic(String),

    /// Protocol ID is malformed or unsupported.
    #[error("invalid protocol ID: {0}")]
    InvalidProtocolId(String),

    /// Received payload exceeds the allowed size.
    #[error("payload too large: got {got} bytes, max {max}")]
    PayloadTooLarge { got: usize, max: usize },

    /// The remote peer closed the connection unexpectedly.
    #[error("remote disconnected")]
    RemoteDisconnect,

    /// A request or handshake timed out.
    #[error("operation timed out")]
    Timeout,

    /// An internal command or event channel was closed.
    #[error("internal channel closed")]
    ChannelClosed,
}
