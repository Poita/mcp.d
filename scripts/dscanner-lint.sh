#!/usr/bin/env bash
#
# Run D-Scanner static analysis over the SDK sources and fail on any finding.
#
# This is the script the CI "dscanner lint" gate invokes. It runs:
#     dub run dscanner@<DSCANNER_VERSION> -- --styleCheck source/
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
#   * source/mcp/internal/unittest_runner.d "Catching Error or Throwable".
#     The macOS-only custom unittest runner must catch `Throwable` per module,
#     exactly as druntime's own default module-unit-tester does, so a failing
#     `assert` (an `Error`) in one module is recorded and the remaining modules
#     still run. Catching `Throwable` here is intentional and required; any
#     other finding in that file still fails the gate.
#
#   * source/mcp/client/runner.d "Catching Error or Throwable".
#     `runWithEventLoop` runs the caller's scenario inside a `nothrow` vibe
#     task, so it must catch `Throwable` there to capture a failure (including
#     a failing `assert`, an `Error`) and rethrow it to the caller after the
#     event loop exits. Capture-and-rethrow, never swallow; any other finding
#     in that file still fails the gate.
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

# Build D-Scanner with LDC when it is installed (CI builds it with LDC too).
compiler=()
if command -v ldc2 >/dev/null 2>&1; then
  compiler=(--compiler=ldc2)
fi

# D-Scanner is pinned: the filters below match its exact diagnostic text, and
# its parser decides which constructs it can read. Bump deliberately and
# re-check the filters.
DSCANNER_VERSION=0.16.0-beta.4
dscanner="dscanner@${DSCANNER_VERSION}"

# D-Scanner exits non-zero both when it reports findings and when it cannot be
# built, so build it first: a toolchain failure must fail the gate rather than
# leave an empty, "clean" result.
if ! dub build --quiet ${compiler[@]+"${compiler[@]}"} "${dscanner}" >/dev/null; then
  echo "D-Scanner could not be built; no lint was run." >&2
  exit 2
fi

# Diagnostics go to stdout; stderr is kept apart to tell a crash from findings.
errfile="$(mktemp)"
trap 'rm -f "${errfile}"' EXIT
raw="$(dub run --quiet ${compiler[@]+"${compiler[@]}"} "${dscanner}" -- --styleCheck source/ 2>"${errfile}")"
status=$?

# A non-zero exit with no diagnostics, or an uncaught D exception or error on
# stderr, means D-Scanner crashed rather than finished the analysis.
if grep -qE '^[A-Za-z_][A-Za-z0-9_.]*(Exception|Error)@' "${errfile}" \
    || { [[ ${status} -ne 0 ]] && ! printf '%s\n' "${raw}" | grep -qE '\[(warn|error)\]'; }; then
  echo "D-Scanner failed (exit ${status}); the analysis did not complete:" >&2
  cat "${errfile}" >&2
  exit 2
fi

# Keep only [warn]/[error] diagnostics, then drop the documented false positives.
findings="$(printf '%s\n' "${raw}" \
  | grep -E '\[(warn|error)\]' \
  | grep -vE '^source/mcp/api/reflection\.d\([0-9]+:[0-9]+\)\[error\]: (Expected `\)` instead of `:`|Declaration expected)' \
  | grep -vE '^source/mcp/internal/unittest_runner\.d\([0-9]+:[0-9]+\)\[warn\]: Catching Error or Throwable is almost always a bad idea\.' \
  | grep -vE '^source/mcp/client/runner\.d\([0-9]+:[0-9]+\)\[warn\]: Catching Error or Throwable is almost always a bad idea\.' \
  || true)"

if [[ -n "${findings}" ]]; then
  echo "D-Scanner reported findings:" >&2
  printf '%s\n' "${findings}" >&2
  exit 1
fi

echo "D-Scanner lint: clean (no findings)."
