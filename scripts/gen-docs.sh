#!/usr/bin/env bash
#
# Generate browsable API documentation for the mcp.d SDK from ddoc comments.
#
# Strategy:
#   1. Prefer `adrdox` (best-in-class D documentation output). If it is not on
#      PATH the script falls back automatically.
#   2. Fall back to dub's built-in ddox generator (`dub build -b ddox`).
#
# Output is written to the `docs/` directory by default (override with $OUTDIR).
#
# Usage:
#   scripts/gen-docs.sh                  # auto-detect generator, write to docs/
#   OUTDIR=site scripts/gen-docs.sh
#   GENERATOR=ddox scripts/gen-docs.sh   # force the ddox fallback
#   GENERATOR=adrdox scripts/gen-docs.sh # require adrdox
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

OUTDIR="${OUTDIR:-docs}"
GENERATOR="${GENERATOR:-auto}"
ADRDOX_BIN=""

find_adrdox() {
  if command -v adrdox >/dev/null 2>&1; then
    ADRDOX_BIN="$(command -v adrdox)"; return 0
  fi
  if command -v doc2 >/dev/null 2>&1; then
    ADRDOX_BIN="$(command -v doc2)"; return 0
  fi
  return 1
}

gen_with_adrdox() {
  echo ">> Generating docs with adrdox into '$OUTDIR' ..."
  rm -rf "$OUTDIR"
  mkdir -p "$OUTDIR"
  # -i : generate a per-package index ; -o : output directory
  "$ADRDOX_BIN" -i -o "$OUTDIR" source/mcp
  echo ">> adrdox docs written to '$OUTDIR/'."
}

gen_with_ddox() {
  echo ">> Generating docs with 'dub build -b ddox' into '$OUTDIR' ..."
  dub build -b ddox
  # dub's ddox places generated HTML under ./docs by default.
  if [ "$OUTDIR" != "docs" ] && [ -d docs ]; then
    rm -rf "$OUTDIR"; mv docs "$OUTDIR"
  fi
  echo ">> ddox docs written to '$OUTDIR/'."
}

case "$GENERATOR" in
  adrdox)
    if find_adrdox; then gen_with_adrdox; else
      echo "!! adrdox not found on PATH (install from https://github.com/adamdruppe/adrdox)" >&2
      exit 1
    fi ;;
  ddox)
    gen_with_ddox ;;
  auto)
    if find_adrdox; then gen_with_adrdox; else
      echo ">> adrdox not found; falling back to ddox." >&2
      gen_with_ddox
    fi ;;
  *)
    echo "Unknown GENERATOR='$GENERATOR' (expected: auto|adrdox|ddox)" >&2
    exit 1 ;;
esac

echo ">> Done. Open '$OUTDIR/index.html' in a browser."
