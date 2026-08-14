//! Engine API client.
//!
//! Talks to an execution-layer node (ethrex, reth, geth, ...) over JSON-RPC.
//! In-house implementation: `reqwest` + `serde_json` + JWT auth, our own
//! request/response types. HTTP first; IPC later.
//!
//! Spec: `execution-apis/src/engine/`.
