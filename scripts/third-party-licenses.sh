#!/usr/bin/env bash
# Regenerates THIRD_PARTY_LICENSES.txt for the full build (--features gateway).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo metadata --format-version 1 --features gateway | python3 scripts/third_party_licenses.py
