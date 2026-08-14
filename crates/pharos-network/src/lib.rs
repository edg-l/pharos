//! Networking layer.
//!
//! Built on raw `libp2p` + `discv5`. Owns the CL-specific surface: gossipsub
//! topic schemes, message validation, req-resp protocol IDs, peer scoring,
//! ENR / fork-digest handling.
