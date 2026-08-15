#!/usr/bin/env bash
#
# bench-check.sh — local perf-regression gate.
#
# Compares the current commit's criterion record (bench-history/<sha>.json,
# produced by `make bench` via scripts/bench-summary.sh) against the most
# recent prior committed baseline, and exits non-zero if any bench regressed
# beyond REGRESSION_PCT *and* the move clears a NOISE_SIGMA noise band derived
# from criterion's reported standard error.
#
# Per the PERF_HOST invariant (D-bench-machine / bench-history/README.md), bench
# numbers are only comparable on the canonical machine. If the current record's
# `host` differs from the baseline's, the comparison is printed but NOT used to
# gate (informational only).
#
# Usage:
#   ./scripts/bench-check.sh                       # current = HEAD's record, baseline = latest other
#   ./scripts/bench-check.sh CURRENT.json          # explicit current, baseline = latest other
#   ./scripts/bench-check.sh CURRENT.json BASE.json # explicit both (handy for testing)
#
# Env:
#   REGRESSION_PCT  percent-slower that counts as a regression (default 10)
#   NOISE_SIGMA     multiples of (cur.stderr + base.stderr) the delta must clear (default 2)
set -euo pipefail

REGRESSION_PCT="${REGRESSION_PCT:-10}"
NOISE_SIGMA="${NOISE_SIGMA:-2}"

HIST_DIR="bench-history"

# Resolve the current record.
if [[ $# -ge 1 ]]; then
    CURRENT="$1"
else
    SHA=$(git rev-parse --short HEAD)
    CURRENT="${HIST_DIR}/${SHA}.json"
fi

if [[ ! -f "$CURRENT" ]]; then
    echo "bench-check: no current record at '$CURRENT'; run 'make bench' on PERF_HOST first." >&2
    exit 1
fi

# Resolve the baseline: explicit arg, else the most recent OTHER record by date.
if [[ $# -ge 2 ]]; then
    BASELINE="$2"
    if [[ ! -f "$BASELINE" ]]; then
        echo "bench-check: baseline '$BASELINE' not found." >&2
        exit 1
    fi
else
    BASELINE=""
    BASELINE_DATE=""
    for f in "$HIST_DIR"/*.json; do
        [[ -e "$f" ]] || continue
        [[ "$f" -ef "$CURRENT" ]] && continue
        d=$(jq -r '.date // ""' "$f")
        if [[ -z "$BASELINE_DATE" || "$d" > "$BASELINE_DATE" ]]; then
            BASELINE_DATE="$d"
            BASELINE="$f"
        fi
    done
    if [[ -z "$BASELINE" ]]; then
        echo "bench-check: no prior baseline in $HIST_DIR to compare against; nothing to check."
        exit 0
    fi
fi

CUR_HOST=$(jq -r '.host // "?"' "$CURRENT")
BASE_HOST=$(jq -r '.host // "?"' "$BASELINE")

echo "bench-check: current  $CURRENT (host=$CUR_HOST)"
echo "bench-check: baseline $BASELINE (host=$BASE_HOST)"
echo "bench-check: threshold ${REGRESSION_PCT}% slower, noise band ${NOISE_SIGMA}σ"
echo

GATE=1
if [[ "$CUR_HOST" != "$BASE_HOST" ]]; then
    echo "bench-check: WARNING host mismatch ($CUR_HOST != $BASE_HOST)." >&2
    echo "bench-check: per D-bench-machine the comparison is informational only — NOT gating." >&2
    echo
    GATE=0
fi

# Per-bench comparison. Joins current onto baseline by name and classifies each:
#   REGRESS  slower by > REGRESSION_PCT and delta clears the noise band
#   FASTER   faster by > REGRESSION_PCT and delta clears the noise band
#   ok       within threshold or within noise
#   NEW      present in current, absent from baseline
REPORT=$(jq -n -r \
    --slurpfile cur "$CURRENT" \
    --slurpfile base "$BASELINE" \
    --argjson pct "$REGRESSION_PCT" \
    --argjson sigma "$NOISE_SIGMA" '
    ($base[0].benches | map({(.name): .}) | add) as $bmap
    | $cur[0].benches[]
    | . as $c
    | $bmap[$c.name] as $b
    | if $b == null then
        "NEW     \($c.name)  (\($c.ns|floor) ns, no baseline)"
      else
        (($c.ns - $b.ns) / $b.ns * 100) as $dpct
        | ($c.ns - $b.ns) as $dns
        | ($sigma * ($c.stderr_ns + $b.stderr_ns)) as $noise
        | (if   ($dpct > $pct       and $dns > $noise)        then "REGRESS"
           elif ($dpct < (0 - $pct) and (0 - $dns) > $noise)  then "FASTER "
           else "ok     " end) as $status
        | "\($status) \($c.name)  \(($dpct*100|round)/100)%  (\($b.ns|floor) -> \($c.ns|floor) ns, noise±\($noise|floor))"
      end
')

echo "$REPORT"
echo

REGRESSIONS=$(printf '%s\n' "$REPORT" | grep -c '^REGRESS' || true)

if [[ "$GATE" == "1" && "$REGRESSIONS" -gt 0 ]]; then
    echo "bench-check: FAIL — $REGRESSIONS bench(es) regressed > ${REGRESSION_PCT}% beyond ${NOISE_SIGMA}σ noise." >&2
    exit 1
fi

if [[ "$GATE" == "0" ]]; then
    echo "bench-check: informational only (host mismatch); $REGRESSIONS apparent regression(s) not gated."
else
    echo "bench-check: PASS — no regressions beyond ${REGRESSION_PCT}% / ${NOISE_SIGMA}σ."
fi
