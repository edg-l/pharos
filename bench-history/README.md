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

## Regression check

`scripts/bench-check.sh` (target: `make bench-check`) compares HEAD's record
against the most recent prior baseline and exits non-zero on regression. Run it
on `PERF_HOST` after `make bench`:

```
make bench        # writes bench-history/<sha>.json for the current commit
make bench-check  # compares that record vs the latest prior baseline
```

A bench is flagged `REGRESS` only when it is **both** slower by more than
`REGRESSION_PCT` (default 10) **and** the slowdown clears a `NOISE_SIGMA`
(default 2) band built from criterion's reported standard error — so run-to-run
jitter on small benches does not trip the gate. Tune per-run:

```
REGRESSION_PCT=5 NOISE_SIGMA=3 make bench-check
```

It can also be pointed at explicit files for ad-hoc comparisons:

```
./scripts/bench-check.sh bench-history/<new>.json bench-history/<old>.json
```

Per the PERF_HOST invariant below, if HEAD's record `host` differs from the
baseline's, the comparison is printed but **not** used to gate (informational
only). The check is deliberately **not** wired into `make ci`: the benches are
slow, CPU-bound, and only comparable on `PERF_HOST`.

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
