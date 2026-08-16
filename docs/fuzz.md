# Pharos Fuzz Harness

This document describes the `cargo fuzz` targets, how to run them, and the
overnight campaign convention.

## Overview

The fuzz targets live in `fuzz/fuzz_targets/` (a non-workspace crate at
`fuzz/Cargo.toml`). They require a Rust nightly toolchain and `cargo-fuzz`.

Install `cargo-fuzz`:

    TMPDIR=~/.cache/tmp cargo +nightly install cargo-fuzz

## Targets

### `ssz_decode`

Fuzz SSZ decode of key beacon-chain containers (fork-enum `SignedBeaconBlock`,
`BeaconState`, `Attestation<2048>`, `BlobSidecar`). Oracle: `from_ssz_bytes`
must never panic — only return `Err`.

### `process_block`

Fuzz `process_block` on a fixed minimal genesis state with arbitrary phase0
blocks. Oracle: the STF must never panic — only return `StateTransitionError`.

### `rpc_codec`

Fuzz the req-resp varint + SSZ-snappy codec helpers on arbitrary bytes:
`read_varint`, `decode_snappy_frame`, `decode_snappy_block`, and the
simulated full decode pipeline. Oracle: never panic, only `Err`.

## Running

### Smoke test (30 s per target — CI gate)

    make fuzz-smoke

### Build only (verify targets compile)

    make fuzz-build

### Single target

    cargo +nightly fuzz run ssz_decode -- -max_total_time=300

### Overnight campaign (on master after merging)

For a sustained nightly run against master, run each target for several hours:

    cargo +nightly fuzz run ssz_decode   -- -max_total_time=28800 &
    cargo +nightly fuzz run process_block -- -max_total_time=28800 &
    cargo +nightly fuzz run rpc_codec    -- -max_total_time=28800 &

Crashes land in `fuzz/artifacts/<target>/`, corpus in `fuzz/corpus/<target>/`.
Commit any crash-reproducing inputs as regression corpus entries.

## Corpus

Seed corpus directories are at `fuzz/corpus/<target>/`. They are intentionally
empty in the initial commit — libFuzzer generates its own corpus. To add
handcrafted seeds (e.g., valid SSZ bytes of known containers), place them in
the corresponding corpus directory.

## Adding new targets

1. Create `fuzz/fuzz_targets/<name>.rs` with `#![no_main]` and a `fuzz_target!` macro.
2. Add a `[[bin]]` entry to `fuzz/Cargo.toml`.
3. Add it to `make fuzz-smoke`.
