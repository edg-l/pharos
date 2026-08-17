//! Integration tests for Phase 6 back-pressure on the network event channel.
//!
//! Verifies two properties of `emit_event` (D-network-backpressure):
//!
//! 1. **No events dropped on a slow consumer**: with channel capacity 2 and a
//!    consumer reading at 10 events/second, all 100 generated events are
//!    delivered (the network task awaits on a full channel instead of dropping).
//!
//! 2. **Timeout path**: when the consumer is fully stalled, the 1-second timeout
//!    in `emit_event` fires, a `WARN` log is emitted, and the network task
//!    continues running (it does not hang).
//!
//! Both tests use `dial_failed` events as the event source: dialling an
//! unreachable loopback address reliably produces one `NetworkEvent::DialFailed`
//! per attempt with no inter-node coordination.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::common::{NetworkEvent, TestHost};
use libp2p::identity::Keypair;
use pharos_network::{NetworkBuilder, NetworkCommand};
use pharos_types::MainnetBeaconSpec;
use pharos_types::phase0::primitives::ForkDigest;
use serial_test::serial;
use tokio::time::{sleep, timeout};
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt as _;

// ── helpers ───────────────────────────────────────────────────────────────────

const FORK_DIGEST: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

fn fd() -> ForkDigest {
    ForkDigest::from_array(FORK_DIGEST)
}

/// An unreachable address that triggers an immediate TCP RST.
///
/// Port 1 on loopback: nothing listens there; the OS sends RST immediately,
/// so `DialFailed` arrives within milliseconds.
fn unreachable_addr() -> libp2p::Multiaddr {
    "/ip4/127.0.0.1/tcp/1".parse().unwrap()
}

// ── global warn counter ───────────────────────────────────────────────────────

/// Counts WARN log events whose message contains "consumer stalled".
///
/// Initialised once per process via `install_global_warn_counter`.
/// The counter is shared across all threads (including tokio worker threads)
/// because it is set as the **global** tracing dispatcher.
static STALL_WARN_COUNT: OnceLock<Arc<AtomicUsize>> = OnceLock::new();

/// A tracing layer that increments `STALL_WARN_COUNT` whenever a WARN event
/// whose fields contain the string "consumer stalled" is observed.
struct StallWarnLayer;

impl<S> tracing_subscriber::Layer<S> for StallWarnLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if *event.metadata().level() != Level::WARN {
            return;
        }
        let mut visitor = ContainsVisitor {
            needle: "consumer stalled",
            found: false,
        };
        event.record(&mut visitor);
        if visitor.found
            && let Some(counter) = STALL_WARN_COUNT.get()
        {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// `tracing::Visit` impl that sets `found = true` when any string field
/// contains `needle`.
struct ContainsVisitor {
    needle: &'static str,
    found: bool,
}

impl tracing::field::Visit for ContainsVisitor {
    fn record_str(&mut self, _field: &tracing::field::Field, value: &str) {
        if value.contains(self.needle) {
            self.found = true;
        }
    }

    fn record_debug(&mut self, _field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if format!("{value:?}").contains(self.needle) {
            self.found = true;
        }
    }
}

/// Install the global tracing dispatcher (once per process).
///
/// Subsequent calls are no-ops because `OnceLock` prevents re-initialisation.
/// This must be called before spawning the network task so that worker threads
/// pick up the global dispatcher.
///
/// Counting stall warnings requires `StallWarnLayer` to be the global
/// dispatcher, so a lost race for that slot has to fail loudly: a dispatcher
/// installed elsewhere would leave the counter at zero and make the assertions
/// below vacuous rather than false.
fn install_global_warn_counter() -> Arc<AtomicUsize> {
    STALL_WARN_COUNT
        .get_or_init(|| {
            let counter = Arc::new(AtomicUsize::new(0));
            let subscriber = tracing_subscriber::registry().with(StallWarnLayer);
            tracing::dispatcher::set_global_default(tracing::Dispatch::new(subscriber))
                .expect("no other global tracing dispatcher in this test binary");
            counter
        })
        .clone()
}

// ── test: no events dropped ───────────────────────────────────────────────────

/// With a tiny event channel (capacity 2) and a consumer reading at
/// 10 events/second, all 100 `DialFailed` events must be delivered.
///
/// Asserts the back-pressure property: the network task awaits on a full
/// channel rather than silently dropping events (`D-network-backpressure`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn no_events_dropped_slow_consumer() {
    const EVENT_COUNT: usize = 100;
    const CHANNEL_CAPACITY: usize = 2;
    const READ_INTERVAL_MS: u64 = 100; // 10 events/second

    let (mut handle, _disc) =
        NetworkBuilder::<MainnetBeaconSpec, TestHost, _>::new(TestHost::new(fd()))
            .local_key(Keypair::generate_secp256k1())
            .listen_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .discv5_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .tcp_listen_port(0)
            .event_channel_capacity(CHANNEL_CAPACITY)
            .spawn()
            .await
            .expect("spawn failed");

    // Drain startup events (LocalEnr, NewListenAddr).
    timeout(Duration::from_secs(5), async {
        let mut saw_enr = false;
        let mut saw_addr = false;
        while !saw_enr || !saw_addr {
            match handle.next_event().await.expect("channel closed") {
                NetworkEvent::LocalEnr(_) => saw_enr = true,
                NetworkEvent::NewListenAddr(_) => saw_addr = true,
                _ => {}
            }
        }
    })
    .await
    .expect("startup events not received within 5 s");

    // Issue all dial commands concurrently from a separate task so they don't
    // block while we are also consuming events on this task.
    let cmd_sender = handle.command_sender();
    tokio::spawn(async move {
        for _ in 0..EVENT_COUNT {
            let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
            cmd_sender
                .send(NetworkCommand::Dial {
                    addr: unreachable_addr(),
                    reply: reply_tx,
                })
                .await
                .ok();
        }
    });

    // Consume events at 10 events/second (100 ms between reads).
    let mut dial_failed_count = 0usize;
    // Generous deadline: 100 events × 100 ms consumer delay + 10 s margin.
    let deadline = Duration::from_secs(25);

    timeout(deadline, async {
        while dial_failed_count < EVENT_COUNT {
            if let NetworkEvent::DialFailed { .. } = handle
                .next_event()
                .await
                .expect("channel closed unexpectedly")
            {
                dial_failed_count += 1;
                // Simulate a slow consumer: 100 ms between reads (10 events/s).
                sleep(Duration::from_millis(READ_INTERVAL_MS)).await;
            }
        }
    })
    .await
    .expect("did not receive all 100 DialFailed events within 25 s");

    assert_eq!(
        dial_failed_count, EVENT_COUNT,
        "expected {EVENT_COUNT} DialFailed events, got {dial_failed_count}"
    );
}

// ── test: warn log on stalled consumer ───────────────────────────────────────

/// When the consumer is fully stalled, the 1-second timeout in `emit_event`
/// fires, a WARN log containing "consumer stalled" is emitted, and the network
/// task continues running (it does not hang).
///
/// Asserts the graceful-degradation leg of `D-network-backpressure`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn timeout_warn_fires_on_stalled_consumer() {
    const CHANNEL_CAPACITY: usize = 2;

    // Install the global warn counter (no-op if already installed).
    let counter = install_global_warn_counter();
    let baseline = counter.load(Ordering::Relaxed);

    let (mut handle, _disc) =
        NetworkBuilder::<MainnetBeaconSpec, TestHost, _>::new(TestHost::new(fd()))
            .local_key(Keypair::generate_secp256k1())
            .listen_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .discv5_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .tcp_listen_port(0)
            .event_channel_capacity(CHANNEL_CAPACITY)
            .spawn()
            .await
            .expect("spawn failed");

    // Drain startup events.
    timeout(Duration::from_secs(5), async {
        let mut saw_enr = false;
        let mut saw_addr = false;
        while !saw_enr || !saw_addr {
            match handle.next_event().await.expect("channel closed") {
                NetworkEvent::LocalEnr(_) => saw_enr = true,
                NetworkEvent::NewListenAddr(_) => saw_addr = true,
                _ => {}
            }
        }
    })
    .await
    .expect("startup events not received within 5 s");

    // Stop consuming events — the channel will fill up.
    // Issue enough dials to fill the channel (capacity 2) plus extras that will
    // block in `emit_event` until the 1-second timeout fires.
    let cmd_sender = handle.command_sender();
    tokio::spawn(async move {
        // Capacity + 3 ensures at least one dial-failed event hits the timeout path.
        for _ in 0..(CHANNEL_CAPACITY + 3) {
            let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
            cmd_sender
                .send(NetworkCommand::Dial {
                    addr: unreachable_addr(),
                    reply: reply_tx,
                })
                .await
                .ok();
        }
    });

    // Wait long enough for the 1-second timeout to fire at least once.
    // Budget: 1 s timeout + 0.5 s margin = 1.5 s, plus time for the TCP RST
    // (near-instant on loopback). We use 2.5 s to be safe.
    sleep(Duration::from_millis(2500)).await;

    // Assert the warn log was emitted (counter incremented above baseline).
    let after = counter.load(Ordering::Relaxed);
    assert!(
        after > baseline,
        "expected at least one WARN log containing 'consumer stalled' after \
         the 1-second emit_event timeout; warn counter: baseline={baseline}, after={after}"
    );

    // Drain the channel to unblock the network task, then verify the task is
    // still alive by shutting it down cleanly.
    timeout(Duration::from_secs(5), async {
        loop {
            match handle.next_event().await {
                Some(NetworkEvent::DialFailed { .. }) => {}
                Some(_) => {}
                None => break,
            }
        }
    })
    .await
    .ok();

    // Shutdown cleanly to verify the task is still responsive.
    handle.shutdown().await;
}
