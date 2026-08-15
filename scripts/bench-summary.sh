#!/usr/bin/env bash
set -euo pipefail

SHA=$(git rev-parse --short HEAD)
HOST=$(hostname)
TOOLCHAIN=$(rustc --version)
DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

OUTFILE="bench-history/${SHA}.json"

if [[ -f "$OUTFILE" && "${BENCH_FORCE:-0}" != "1" ]]; then
    echo "bench-summary: $OUTFILE already exists; set BENCH_FORCE=1 to overwrite." >&2
    exit 1
fi

# Build benches array from criterion output files.
# Each bench directory under target/criterion/ may have nested subdirs;
# estimates.json is at target/criterion/<bench>/<group>/new/estimates.json
# or target/criterion/<bench>/new/estimates.json depending on criterion version.
BENCHES_JSON="["
FIRST=1

while IFS= read -r -d '' estimates_file; do
    # Derive bench name from path: strip leading "target/criterion/" and trailing "/new/estimates.json"
    rel="${estimates_file#target/criterion/}"
    bench_name="${rel%/new/estimates.json}"

    ns=$(jq '.mean.point_estimate' "$estimates_file")
    stderr_ns=$(jq '.mean.standard_error' "$estimates_file")

    entry=$(jq -n \
        --arg name "$bench_name" \
        --argjson ns "$ns" \
        --argjson stderr_ns "$stderr_ns" \
        '{"name": $name, "ns": $ns, "stderr_ns": $stderr_ns}')

    if [[ "$FIRST" == "1" ]]; then
        BENCHES_JSON+="$entry"
        FIRST=0
    else
        BENCHES_JSON+=",$entry"
    fi
done < <(find target/criterion -name "estimates.json" -path "*/new/estimates.json" -print0 2>/dev/null | sort -z)

BENCHES_JSON+="]"

# Refuse to write an empty-record artifact: it would silently commit a
# bench history with zero entries (e.g. if benches were never run or all
# failed mid-run).
if [[ "$BENCHES_JSON" == "[]" ]]; then
    echo "bench-summary: no estimates.json found under target/criterion/; did make bench complete?" >&2
    exit 1
fi

JSON=$(jq -n \
    --arg sha "$SHA" \
    --arg host "$HOST" \
    --arg toolchain "$TOOLCHAIN" \
    --arg date "$DATE" \
    --argjson benches "$BENCHES_JSON" \
    '{"sha": $sha, "host": $host, "toolchain": $toolchain, "date": $date, "benches": $benches}')

mkdir -p bench-history
printf '%s\n' "$JSON" > "$OUTFILE"
printf '%s\n' "$JSON"
