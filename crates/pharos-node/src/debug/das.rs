//! `pharos debug das` — PeerDAS custody calculator.
//!
//! Given a node id and a custody group count, reports the custody groups, the
//! data columns each group covers, the flattened sorted custody column set, and
//! the gossip subnet each custody column maps to. Pure reuse of
//! [`pharos_stf::fulu::data_columns`] +
//! [`pharos_network::compute_subnet_for_data_column_sidecar`]; this is the
//! offline mirror of the live custody loop (`crate::custody`).
//!
//! Mainnet and minimal share the same custody constants
//! (`NUMBER_OF_CUSTODY_GROUPS = NUMBER_OF_COLUMNS =
//! DATA_COLUMN_SIDECAR_SUBNET_COUNT = 128`), so `--preset` only changes the
//! label; both are wired for symmetry with the rest of the tooling.

use anyhow::{Context as _, bail};
use pharos_network::compute_subnet_for_data_column_sidecar;
use pharos_stf::fulu::data_columns::{compute_columns_for_custody_group, get_custody_groups};
use pharos_types::{BeaconSpec, MainnetBeaconSpec, MinimalBeaconSpec};
use serde_json::json;

/// Preset selector for the custody calculator.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Preset {
    Mainnet,
    Minimal,
}

/// Parse a 32-byte node id from a hex string (with or without a `0x` prefix).
fn parse_node_id(hex: &str) -> anyhow::Result<[u8; 32]> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes =
        hex::decode(stripped).with_context(|| format!("--node-id: not valid hex: {hex}"))?;
    if bytes.len() != 32 {
        bail!("--node-id: expected 32 bytes, got {}", bytes.len());
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Ok(id)
}

/// Run the custody calculator and print the result (human table or JSON).
///
/// `cgc` defaults to `CUSTODY_REQUIREMENT` (4) at the call site when the user
/// omits it. `column` optionally restricts the subnet report to a single
/// column index (handy for "which subnet does column K live on").
pub fn run(
    node_id_hex: &str,
    cgc: Option<u64>,
    preset: Preset,
    column: Option<u64>,
    json_out: bool,
) -> anyhow::Result<()> {
    match preset {
        Preset::Mainnet => {
            run_for::<MainnetBeaconSpec>(node_id_hex, cgc, "mainnet", column, json_out)
        }
        Preset::Minimal => {
            run_for::<MinimalBeaconSpec>(node_id_hex, cgc, "minimal", column, json_out)
        }
    }
}

fn run_for<E: BeaconSpec>(
    node_id_hex: &str,
    cgc: Option<u64>,
    preset_label: &str,
    column: Option<u64>,
    json_out: bool,
) -> anyhow::Result<()> {
    let node_id = parse_node_id(node_id_hex)?;
    let cgc = cgc.unwrap_or(E::CUSTODY_REQUIREMENT);

    if cgc > E::NUMBER_OF_CUSTODY_GROUPS {
        bail!(
            "--cgc {cgc} exceeds NUMBER_OF_CUSTODY_GROUPS {}",
            E::NUMBER_OF_CUSTODY_GROUPS
        );
    }
    if let Some(k) = column
        && k >= E::NUMBER_OF_COLUMNS
    {
        bail!(
            "--column {k} exceeds NUMBER_OF_COLUMNS {}",
            E::NUMBER_OF_COLUMNS
        );
    }

    let groups = get_custody_groups::<E>(node_id, cgc);

    // Per-group columns, and the flattened sorted custody column set.
    let mut per_group: Vec<(u64, Vec<u64>)> = Vec::with_capacity(groups.len());
    let mut columns: Vec<u64> = Vec::new();
    for &g in &groups {
        let cols = compute_columns_for_custody_group::<E>(g);
        columns.extend_from_slice(&cols);
        per_group.push((g, cols));
    }
    columns.sort_unstable();

    // Subnet per column. `--column K` restricts to that single column.
    let subnet_of =
        |c: u64| compute_subnet_for_data_column_sidecar(c, E::DATA_COLUMN_SIDECAR_SUBNET_COUNT);
    let subnet_rows: Vec<(u64, u64)> = match column {
        Some(k) => vec![(k, subnet_of(k))],
        None => columns.iter().map(|&c| (c, subnet_of(c))).collect(),
    };

    if json_out {
        let obj = json!({
            "preset": preset_label,
            "node_id": format!("0x{}", hex::encode(node_id)),
            "custody_group_count": cgc,
            "number_of_custody_groups": E::NUMBER_OF_CUSTODY_GROUPS,
            "number_of_columns": E::NUMBER_OF_COLUMNS,
            "data_column_sidecar_subnet_count": E::DATA_COLUMN_SIDECAR_SUBNET_COUNT,
            "custody_groups": groups,
            "columns_per_group": per_group
                .iter()
                .map(|(g, cols)| json!({ "group": g, "columns": cols }))
                .collect::<Vec<_>>(),
            "custody_columns": columns,
            "subnets": subnet_rows
                .iter()
                .map(|(c, s)| json!({ "column": c, "subnet": s }))
                .collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
        return Ok(());
    }

    println!("preset:                 {preset_label}");
    println!("node_id:                0x{}", hex::encode(node_id));
    println!(
        "custody_group_count:    {cgc}  (NUMBER_OF_CUSTODY_GROUPS={}, NUMBER_OF_COLUMNS={}, DATA_COLUMN_SIDECAR_SUBNET_COUNT={})",
        E::NUMBER_OF_CUSTODY_GROUPS,
        E::NUMBER_OF_COLUMNS,
        E::DATA_COLUMN_SIDECAR_SUBNET_COUNT,
    );
    println!("custody_groups ({}):    {:?}", groups.len(), groups);
    println!();
    println!("columns per group:");
    for (g, cols) in &per_group {
        println!("  group {g:>3}: {cols:?}");
    }
    println!();
    println!("custody_columns ({}):   {:?}", columns.len(), columns);
    println!();
    println!("subnets:");
    for (c, s) in &subnet_rows {
        println!("  column {c:>3} -> subnet {s}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_node_id_accepts_prefixed_and_bare() {
        let bare = "00".repeat(32);
        let prefixed = format!("0x{bare}");
        assert_eq!(parse_node_id(&bare).unwrap(), [0u8; 32]);
        assert_eq!(parse_node_id(&prefixed).unwrap(), [0u8; 32]);
    }

    #[test]
    fn parse_node_id_rejects_wrong_length() {
        assert!(parse_node_id("0x00").is_err());
        assert!(parse_node_id("zz").is_err());
    }

    /// The calculator returns exactly `cgc` custody groups, each group's columns
    /// land on the expected subnet, and the flattened set is sorted + sized
    /// `cgc * (NUMBER_OF_COLUMNS / NUMBER_OF_CUSTODY_GROUPS)`. Mirrors the live
    /// custody loop so a divergence would surface here offline.
    #[test]
    fn das_calculator_matches_custody_helpers() {
        let node_id = [0x11u8; 32];
        let cgc = 4u64;
        let groups = get_custody_groups::<MainnetBeaconSpec>(node_id, cgc);
        assert_eq!(groups.len() as u64, cgc);
        assert!(
            groups.windows(2).all(|w| w[0] < w[1]),
            "groups sorted+unique"
        );

        let mut columns = Vec::new();
        for &g in &groups {
            columns.extend(compute_columns_for_custody_group::<MainnetBeaconSpec>(g));
        }
        let columns_per_group =
            MainnetBeaconSpec::NUMBER_OF_COLUMNS / MainnetBeaconSpec::NUMBER_OF_CUSTODY_GROUPS;
        assert_eq!(columns.len() as u64, cgc * columns_per_group);

        // Subnet mapping agrees with the network helper.
        for &c in &columns {
            let subnet = compute_subnet_for_data_column_sidecar(
                c,
                MainnetBeaconSpec::DATA_COLUMN_SIDECAR_SUBNET_COUNT,
            );
            assert_eq!(
                subnet,
                c % MainnetBeaconSpec::DATA_COLUMN_SIDECAR_SUBNET_COUNT
            );
        }
    }

    /// `run` end-to-end (both output modes) on a valid input must not error.
    #[test]
    fn run_smoke_both_output_modes() {
        let node_id = format!("0x{}", "ab".repeat(32));
        run(&node_id, Some(4), Preset::Mainnet, None, false).unwrap();
        run(&node_id, None, Preset::Minimal, Some(7), true).unwrap();
    }
}
