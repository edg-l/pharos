//! SSZ-snappy framing codec for gossipsub and req-resp messages.

pub mod snappy_frame;

pub use snappy_frame::MAX_PAYLOAD_SIZE;
