//! Handler for `GET /eth/v1/events` — Beacon API Server-Sent Events stream.
//!
//! Subscribes to the `EventBus` broadcast channel, filters events by the
//! caller-requested topics, and streams each accepted event as an SSE frame:
//!
//! ```text
//! event: head
//! data: {...}
//!
//! ```
//!
//! Topic filtering:
//! - All spec-listed topic names are accepted without error.
//! - Unrecognised topic strings return HTTP 400.
//! - Topics that pharos never emits (e.g. `payload_attributes`) are valid
//!   subscription targets but will simply never produce a frame.
//!
//! Lagged receivers (buffer-overrun on a slow client) skip dropped events and
//! continue; the connection is not closed.

use std::convert::Infallible;
use std::sync::Arc;

use axum::extract::{RawQuery, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures::stream;
use pharos_types::EthSpec;
use tokio::sync::broadcast::error::RecvError;
use tracing::debug;

use crate::error::ApiError;
use crate::events::KnownTopic;
use crate::state::ApiState;

// ── Handler ───────────────────────────────────────────────────────────────────

/// `GET /eth/v1/events`
///
/// Accepts `?topics=head&topics=finalized_checkpoint` (repeated key) or
/// `?topics=head,finalized_checkpoint` (comma-separated, single key).
///
/// Returns a `text/event-stream` response.  Each accepted event is serialised
/// as an SSE frame with `event: <topic>` and `data: <json>`.
///
/// Returns 400 when any topic string is not recognised by the spec.
pub async fn get_events<E: EthSpec>(
    State(state): State<Arc<ApiState<E>>>,
    RawQuery(raw_query): RawQuery,
) -> Response {
    // Resolve the event bus.
    let bus = match &state.event_bus {
        Some(b) => Arc::clone(b),
        None => {
            return ApiError::BadRequest("event bus not available (--http required)".to_string())
                .into_response();
        }
    };

    // Parse topics from the raw query string.
    // Supports repeated keys: `?topics=head&topics=block`
    // and comma-separated: `?topics=head,block`.
    let mut selected: Vec<KnownTopic> = Vec::new();
    if let Some(qs) = raw_query.as_deref().filter(|s| !s.is_empty()) {
        for pair in qs.split('&') {
            let (key, val) = pair.split_once('=').unwrap_or((pair, ""));
            if key.trim() != "topics" {
                continue;
            }
            // URL-decode percent-encoded characters in the value.
            let decoded = percent_decode(val);
            for part in decoded.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                match KnownTopic::parse(part) {
                    Some(t) => selected.push(t),
                    None => {
                        return ApiError::BadRequest(format!("Invalid topic: {part}"))
                            .into_response();
                    }
                }
            }
        }
    }

    // `topics` is required; reject absent or empty topic lists with 400.
    if selected.is_empty() {
        return ApiError::BadRequest(
            "required query parameter `topics` is missing or empty".to_string(),
        )
        .into_response();
    }

    // Subscribe to the broadcast bus BEFORE returning so no events emitted
    // during handler setup are missed.
    let rx = bus.subscribe();

    let event_stream = stream::unfold((rx, selected), |(mut rx, selected)| async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    // Filter: only emit if any requested topic matches.
                    if !selected.iter().any(|t| t.matches_event(&event)) {
                        continue;
                    }
                    let topic = event.topic();
                    let data = match event.data_json() {
                        Ok(d) => d,
                        Err(e) => {
                            debug!(error = %e, "failed to serialize SSE event; skipping");
                            continue;
                        }
                    };
                    let sse_event = Event::default().event(topic).data(data);
                    return Some((Ok::<Event, Infallible>(sse_event), (rx, selected)));
                }
                Err(RecvError::Lagged(n)) => {
                    // Slow client: events were dropped from the ring buffer.
                    // Continue without closing the connection.
                    debug!(dropped = n, "SSE receiver lagged; skipping dropped events");
                    continue;
                }
                Err(RecvError::Closed) => {
                    // Sender dropped (node shutting down).  End the stream.
                    return None;
                }
            }
        }
    });

    Sse::new(event_stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Minimal percent-decoder for query-string values.
///
/// Replaces `%XX` sequences with the corresponding byte and `+` with space.
/// Non-ASCII output is preserved as-is (topic names are ASCII).
fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hi = chars.next();
            let lo = chars.next();
            match (hi, lo) {
                (Some(h), Some(l)) => {
                    let hex = format!("{h}{l}");
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        out.push(byte as char);
                    } else {
                        out.push('%');
                        out.push(h);
                        out.push(l);
                    }
                }
                (Some(h), None) => {
                    out.push('%');
                    out.push(h);
                }
                _ => out.push('%'),
            }
        } else if c == '+' {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    out
}
