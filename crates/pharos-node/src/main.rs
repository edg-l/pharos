//! Pharos beacon-node entry point.

mod host_impl;
pub mod startup;

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use anyhow::{Context as _, bail};
use clap::Parser;
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use pharos_network::NetworkBuilder;
use pharos_types::MainnetEthSpec;
use tracing::info;

use host_impl::HostImpl;

// ── CLI ───────────────────────────────────────────────────────────────────────

/// Pharos Ethereum consensus-layer beacon node.
#[derive(Parser, Debug)]
#[command(name = "pharos", version)]
struct Args {
    /// TCP listen multiaddr for libp2p (e.g. /ip4/127.0.0.1/tcp/9000).
    #[arg(long, default_value = "/ip4/127.0.0.1/tcp/9000")]
    listen_addr: Multiaddr,

    /// UDP port for discv5 peer discovery.
    #[arg(long, default_value_t = 9000)]
    discv5_port: u16,

    /// Bootstrap ENR(s) for discv5 routing table initialisation (repeatable).
    #[arg(long, value_name = "ENR")]
    bootnode: Vec<String>,

    /// Data directory for persistent state (chain DB, slashing DB, etc.).
    #[arg(long, default_value = "./data")]
    data_dir: PathBuf,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract `(IpAddr, tcp_port)` from a `/ip4/<addr>/tcp/<port>` multiaddr.
fn parse_listen_addr(addr: &Multiaddr) -> anyhow::Result<(IpAddr, u16)> {
    let mut iter = addr.iter();
    let ip = match iter.next() {
        Some(Protocol::Ip4(a)) => IpAddr::V4(a),
        Some(Protocol::Ip6(a)) => IpAddr::V6(a),
        other => bail!("--listen-addr: expected /ip4 or /ip6 prefix, got {other:?}"),
    };
    let port = match iter.next() {
        Some(Protocol::Tcp(p)) => p,
        other => bail!("--listen-addr: expected /tcp/<port>, got {other:?}"),
    };
    Ok((ip, port))
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    info!(version = env!("CARGO_PKG_VERSION"), "pharos starting");
    info!(listen_addr = %args.listen_addr, discv5_port = args.discv5_port, "configuration");
    tracing::info!(data_dir = %args.data_dir.display(), "data directory (unused until M3)");

    // Parse --listen-addr into IP + TCP port.
    let (listen_ip, tcp_port) = parse_listen_addr(&args.listen_addr)
        .context("--listen-addr is not a valid /ip4/<addr>/tcp/<port> multiaddr")?;

    // Parse --bootnode ENR strings.
    let bootnodes: Vec<pharos_network::discovery::enr::Enr> = args
        .bootnode
        .iter()
        .map(|s| {
            s.parse::<pharos_network::discovery::enr::Enr>()
                .map_err(|e| anyhow::anyhow!("invalid bootnode ENR {s:?}: {e}"))
        })
        .collect::<anyhow::Result<_>>()?;

    // Build and spawn the network stack.
    let host = HostImpl::new();
    let discv5_addr = SocketAddr::new(listen_ip, args.discv5_port);

    let handle = NetworkBuilder::<MainnetEthSpec, _, _>::new(host)
        .listen_ip(listen_ip)
        .tcp_listen_port(tcp_port)
        .discv5_addr(discv5_addr)
        .bootnodes(bootnodes)
        .spawn()
        .await
        .context("failed to start network")?;

    info!(peer_id = %handle.local_peer_id(), "network started");

    // Block until Ctrl-C.
    tokio::signal::ctrl_c()
        .await
        .context("ctrl_c signal handler failed")?;

    info!("received shutdown signal");
    handle.shutdown().await;
    info!("network shutdown complete");

    Ok(())
}
