#!/usr/bin/env bash
# Download and extract consensus-spec-tests release tarballs.
#
# Usage:
#   ./scripts/fetch-spec-tests.sh
#
# Environment variables:
#   SPEC_TESTS_TAG   Release tag to download (default: v1.6.1)
#   PHAROS_SPEC_TESTS  Target directory (default: ~/.cache/pharos-spec-tests/)
#
# After this script completes, run:
#   cargo run -p pharos-conformance -- --write

set -euo pipefail

SPEC_TESTS_TAG="${SPEC_TESTS_TAG:-v1.6.1}"
DEST="${PHAROS_SPEC_TESTS:-${HOME}/.cache/pharos-spec-tests}"

BASE_URL="https://github.com/ethereum/consensus-specs/releases/download/${SPEC_TESTS_TAG}"

TARBALLS=(
    "general.tar.gz"
    "mainnet.tar.gz"
    "minimal.tar.gz"
)

echo "Fetching consensus-spec-tests ${SPEC_TESTS_TAG} -> ${DEST}"
mkdir -p "${DEST}"

for tarball in "${TARBALLS[@]}"; do
    url="${BASE_URL}/${tarball}"
    dest_file="${DEST}/${tarball}"
    echo "  Downloading ${url} ..."
    curl -L --progress-bar -o "${dest_file}" "${url}"
    echo "  Extracting ${tarball} ..."
    # Strip the leading `tests/` directory the tarballs include so the layout
    # is `<DEST>/{general,mainnet,minimal}/` rather than `<DEST>/tests/...`.
    tar -xzf "${dest_file}" -C "${DEST}" --strip-components=1
    rm "${dest_file}"
done

# Write the tag file so pharos-conformance can display the release in reports.
echo "${SPEC_TESTS_TAG}" > "${DEST}/tag"

echo ""
echo "Done. Fixtures extracted to ${DEST}"
echo "Run: cargo run -p pharos-conformance -- --write"
