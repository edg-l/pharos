#!/usr/bin/env bash
# Download and extract the EIP-3076 slashing-protection-interchange-tests.
#
# Usage:
#   ./scripts/fetch-interchange-tests.sh
#
# Environment variables:
#   INTERCHANGE_TESTS_TAG   Release tag to download (default: v5.3.0)
#   PHAROS_INTERCHANGE_TESTS  Target directory (default: ~/.cache/pharos-interchange-tests/)
#
# After this script completes, run:
#   cargo test -p pharos-validator --test interchange_conformance

set -euo pipefail

INTERCHANGE_TESTS_TAG="${INTERCHANGE_TESTS_TAG:-v5.3.0}"
DEST="${PHAROS_INTERCHANGE_TESTS:-${HOME}/.cache/pharos-interchange-tests}"

REPO="eth-clients/slashing-protection-interchange-tests"
URL="https://github.com/${REPO}/archive/refs/tags/${INTERCHANGE_TESTS_TAG}.tar.gz"

echo "Fetching ${REPO} ${INTERCHANGE_TESTS_TAG} -> ${DEST}"
mkdir -p "${DEST}"

tarball="${DEST}/interchange-tests.tar.gz"
echo "  Downloading ${URL} ..."
curl -L --progress-bar -o "${tarball}" "${URL}"
echo "  Extracting ..."
# Strip the leading `slashing-protection-interchange-tests-<tag>/` directory so
# the layout is `<DEST>/tests/generated/*.json`.
tar -xzf "${tarball}" -C "${DEST}" --strip-components=1
rm "${tarball}"

# Write the tag file so the harness can report the release.
echo "${INTERCHANGE_TESTS_TAG}" > "${DEST}/tag"

echo ""
echo "Done. Vectors extracted to ${DEST}"
echo "Run: cargo test -p pharos-validator --test interchange_conformance"
