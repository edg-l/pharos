//! Structured tracing initialisation helper.
//!
//! Call [`init_tracing`] once at startup from each binary (`pharos`,
//! `pharos-vc`) to configure the global tracing subscriber.
//!
//! Two formats are supported:
//! - [`LogFormat::Pretty`] — human-readable, coloured output (default).
//! - [`LogFormat::Json`] — machine-readable JSON, suitable for log aggregators.
//!   Configured with [`tracing_subscriber::fmt::format::FmtSpan::ENTER`] |
//!   [`tracing_subscriber::fmt::format::FmtSpan::EXIT`] so span enter/exit
//!   events are emitted as separate JSON objects, enabling per-span latency
//!   measurement and parent-span linkage in log pipelines.
//!
//! Filtering follows the standard `RUST_LOG` directive syntax (e.g.
//! `info,pharos_stf=debug`) via [`tracing_subscriber::EnvFilter`].  The
//! `filter` parameter is the fallback directive used when `RUST_LOG` is not set
//! or is invalid; it can carry a `--log-level` override supplied by the
//! operator.

use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::{EnvFilter, fmt};

/// Log output format selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// Human-readable, coloured output (the default).
    #[default]
    Pretty,
    /// Machine-readable JSON; each log event and span event is a JSON object.
    Json,
}

impl std::str::FromStr for LogFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(LogFormat::Json),
            "pretty" => Ok(LogFormat::Pretty),
            other => Err(format!(
                "unknown log format {other:?}; expected \"json\" or \"pretty\""
            )),
        }
    }
}

/// Initialise the global tracing subscriber.
///
/// # Parameters
///
/// - `format` — output format; see [`LogFormat`].
/// - `filter` — `RUST_LOG`-style directive string used as the fallback when
///   `RUST_LOG` is not set (e.g. `"info"`, `"info,pharos_stf=debug"`).
///
/// # Panics
///
/// Panics if a global subscriber has already been installed (only one call per
/// process is valid).
pub fn init_tracing(format: LogFormat, filter: &str) {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter));

    match format {
        LogFormat::Json => {
            use tracing_subscriber::prelude::*;
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .json()
                        .with_span_events(FmtSpan::ENTER | FmtSpan::EXIT),
                )
                .init();
        }
        LogFormat::Pretty => {
            use tracing_subscriber::prelude::*;
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer())
                .init();
        }
    }
}

/// Build a JSON-format tracing layer that writes to `writer`, with
/// `FmtSpan::ENTER | FmtSpan::EXIT` span events enabled.
///
/// Intended for tests that need to capture tracing output to an in-memory
/// buffer.  Callers must wire this into a `tracing_subscriber::registry()`
/// themselves; this function does NOT install a global subscriber.
pub fn make_json_layer_for_test<W>(
    writer: W,
) -> impl tracing_subscriber::Layer<tracing_subscriber::Registry>
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    fmt::layer()
        .json()
        .with_span_events(FmtSpan::ENTER | FmtSpan::EXIT)
        .with_writer(writer)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::prelude::*;

    use super::*;

    // ── Shared capture writer ─────────────────────────────────────────────────

    /// An in-memory writer that accumulates bytes and can be drained as a
    /// `String`.  The `Clone` impl is required by `MakeWriter`.
    #[derive(Clone, Default)]
    struct CaptureWriter {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl CaptureWriter {
        fn new() -> Self {
            Self {
                buf: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn captured(&self) -> String {
            let guard = self.buf.lock().unwrap();
            String::from_utf8_lossy(&guard).into_owned()
        }
    }

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.buf.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    // ── Test: JSON layer emits valid JSON ─────────────────────────────────────

    /// Asserts that the JSON layer emits events that parse as valid JSON and
    /// contain the expected top-level fields (`timestamp`, `level`, `target`,
    /// `fields`).
    #[test]
    fn log_format_json_emits_valid_json() {
        let writer = CaptureWriter::new();
        let layer = make_json_layer_for_test(writer.clone());

        // Build a local subscriber (not a global) so parallel tests don't clash.
        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        tracing::info!(answer = 42, "test event");

        let output = writer.captured();
        assert!(!output.is_empty(), "no JSON output captured");

        // Each line should be a self-contained JSON object.
        for line in output.lines() {
            let v: serde_json::Value = serde_json::from_str(line).expect("JSON output must parse");
            assert!(
                v.get("timestamp").is_some(),
                "missing 'timestamp' field in: {line}"
            );
            assert!(v.get("level").is_some(), "missing 'level' field in: {line}");
            assert!(
                v.get("target").is_some(),
                "missing 'target' field in: {line}"
            );
            assert!(
                v.get("fields").is_some(),
                "missing 'fields' field in: {line}"
            );
        }
    }

    // ── Test: span enter events appear in sequence ────────────────────────────

    /// Asserts that with `FmtSpan::ENTER | FmtSpan::EXIT` configured:
    /// 1. The per-slot span ENTER event appears before the per-block span ENTER
    ///    event.
    /// 2. The per-block span ENTER event is followed by its EXIT event.
    /// 3. The per-slot span EXIT event appears last.
    ///
    /// This mirrors the real per-slot root → per-block child span hierarchy used
    /// in the block-ingestion loop.
    #[test]
    fn span_enter_events_sequence() {
        let writer = CaptureWriter::new();
        let layer = make_json_layer_for_test(writer.clone());

        let subscriber = tracing_subscriber::registry().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        // Simulate the per-slot root span → per-block child span hierarchy.
        let slot_span = tracing::info_span!("process_slot", slot = 42u64);
        let _slot_guard = slot_span.enter();

        let block_span = tracing::info_span!("import_block", block_root = "0xabcd");
        {
            let _block_guard = block_span.enter();
            // Some work inside the block span.
            tracing::info!("block imported");
        }
        // slot_span still active; block_span has exited here.
        drop(_slot_guard);

        let output = writer.captured();
        assert!(!output.is_empty(), "no JSON output captured");

        // Collect span events only (lines that have a "span" field in the JSON).
        let span_events: Vec<serde_json::Value> = output
            .lines()
            .filter_map(|line| {
                let v: serde_json::Value = serde_json::from_str(line).ok()?;
                // Span enter/exit events carry a "span" object.
                if v.get("span").is_some() {
                    Some(v)
                } else {
                    None
                }
            })
            .collect();

        // We expect at least 4 span events: slot ENTER, block ENTER, block EXIT,
        // slot EXIT (in that order).
        assert!(
            span_events.len() >= 4,
            "expected >= 4 span events, got {}; output: {output}",
            span_events.len()
        );

        // Helper: extract the span name from a span-event JSON object.
        let span_name = |v: &serde_json::Value| -> String {
            v.get("span")
                .and_then(|s| s.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_owned()
        };

        // Helper: "enter" or "exit" message emitted by FmtSpan.
        let is_enter = |v: &serde_json::Value| -> bool {
            v.get("fields")
                .and_then(|f| f.get("message"))
                .and_then(|m| m.as_str())
                .map(|m| m == "enter")
                .unwrap_or(false)
        };
        let is_exit = |v: &serde_json::Value| -> bool {
            v.get("fields")
                .and_then(|f| f.get("message"))
                .and_then(|m| m.as_str())
                .map(|m| m == "exit")
                .unwrap_or(false)
        };

        // Locate positions of key events.
        let slot_enter_pos = span_events
            .iter()
            .position(|v| span_name(v) == "process_slot" && is_enter(v))
            .expect("process_slot ENTER event not found");
        let block_enter_pos = span_events
            .iter()
            .position(|v| span_name(v) == "import_block" && is_enter(v))
            .expect("import_block ENTER event not found");
        let block_exit_pos = span_events
            .iter()
            .position(|v| span_name(v) == "import_block" && is_exit(v))
            .expect("import_block EXIT event not found");
        let slot_exit_pos = span_events
            .iter()
            .position(|v| span_name(v) == "process_slot" && is_exit(v))
            .expect("process_slot EXIT event not found");

        // Ordering invariants.
        assert!(
            slot_enter_pos < block_enter_pos,
            "process_slot ENTER must precede import_block ENTER"
        );
        assert!(
            block_enter_pos < block_exit_pos,
            "import_block ENTER must precede import_block EXIT"
        );
        assert!(
            block_exit_pos < slot_exit_pos,
            "import_block EXIT must precede process_slot EXIT"
        );
    }

    // ── LogFormat parsing ─────────────────────────────────────────────────────

    #[test]
    fn log_format_parses_json() {
        assert_eq!("json".parse::<LogFormat>().unwrap(), LogFormat::Json);
        assert_eq!("JSON".parse::<LogFormat>().unwrap(), LogFormat::Json);
    }

    #[test]
    fn log_format_parses_pretty() {
        assert_eq!("pretty".parse::<LogFormat>().unwrap(), LogFormat::Pretty);
    }

    #[test]
    fn log_format_unknown_errors() {
        assert!("yaml".parse::<LogFormat>().is_err());
    }
}
