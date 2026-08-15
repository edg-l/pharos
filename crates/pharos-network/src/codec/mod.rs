//! SSZ-snappy codecs for gossipsub and req-resp messages.
//!
//! Two distinct snappy formats are used:
//! - Gossip (`snappy_block`): raw snappy block compression per
//!   `p2p-interface.md:1038-1048`.
//! - Req/resp (`snappy_frame`): snappy frame (streaming) compression per
//!   `p2p-interface.md:1255-1256`.

pub mod snappy_block;
pub mod snappy_frame;

pub use snappy_frame::MAX_PAYLOAD_SIZE;
