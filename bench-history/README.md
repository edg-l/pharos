# bench-history

Each file is named `<git-sha>.json` and produced by `scripts/bench-summary.sh`
after a `make bench` run.

## Schema

```json
{
  "sha":       "<short git sha>",
  "host":      "<hostname>",
  "toolchain": "<rustc --version output>",
  "date":      "<ISO8601 UTC timestamp>",
  "benches": [
    { "name": "<criterion bench/group id>", "ns": <mean ns>, "stderr_ns": <std error ns> }
  ]
}
```

Field meanings:

- `ns` — mean wall time in nanoseconds as reported by criterion's `estimates.json`.
- `stderr_ns` — standard error of the mean in nanoseconds.

## Overwriting an existing record

`scripts/bench-summary.sh` refuses to overwrite a file for the same SHA. To
force a re-record (e.g. after re-running benches on the same commit), set:

```
BENCH_FORCE=1 make bench
```

## PERF_HOST invariant (`D-bench-machine`)

Bench numbers are only comparable when recorded on the same machine. The
canonical machine is the developer's 12-core Ryzen workstation (`D-bench-machine`
/ `D-perf-bench-machine` in `docs/decisions.md`). All baseline records stored
here MUST come from that host (`PERF_HOST`). Records from other machines are
informational only and should not be used for regression tracking.
