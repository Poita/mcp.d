#!/usr/bin/env bash
#
# Run D-Scanner static analysis over the SDK sources and fail on any finding.
#
# This is the script the CI "dscanner lint" gate invokes. It runs:
#     dub run dscanner -- --styleCheck source/
# using the project's dscanner.ini (which documents every disabled check), then
# fails if D-Scanner reports any warning or error.
#
# Documented exceptions (filtered out below):
#   * source/mcp/api/reflection.d named-argument UDA syntax.
#     The bundled libdparse parser (D-Scanner 0.16 / libdparse 0.23) cannot
#     parse D's named-argument syntax inside UDAs, e.g.
#         @toolAnnotations(destructiveHint: true.nullable, ...)
#     The real D compiler accepts this (these unittests compile and pass under
#     `dub test`), so D-Scanner's "Expected `)` instead of `:`" parse errors on
#     that file are false positives and are ignored here. Everything else --
#     including any other finding in that same file -- still fails the gate.
#
# Usage:
#   scripts/dscanner-lint.sh
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# Raise the file-descriptor limit; the D toolchain opens many files at once.
ulimit -n 65536 2>/dev/null || true

# Collect only the diagnostic lines (D-Scanner prints them to stdout).
raw="$(dub run --quiet dscanner -- --styleCheck source/ 2>/dev/null || true)"

# Keep only [warn]/[error] diagnostics, then drop the documented false positives.
findings="$(printf '%s\n' "${raw}" \
  | grep -E '\[(warn|error)\]' \
  | grep -vE '^source/mcp/api/reflection\.d\([0-9]+:[0-9]+\)\[error\]: (Expected `\)` instead of `:`|Declaration expected)' \
  || true)"

if [[ -n "${findings}" ]]; then
  echo "D-Scanner reported findings:" >&2
  printf '%s\n' "${findings}" >&2
  exit 1
fi

echo "D-Scanner lint: clean (no findings)."
