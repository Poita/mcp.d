#!/usr/bin/env bash
#
# Guard against the README's toolchain requirement drifting from dub.json.
#
# dub.json's "toolchainRequirements" is the single source of truth for the
# minimum DMD/LDC the SDK supports. The README's Requirements section restates
# those numbers for human readers, so it can silently fall out of date when the
# floor is bumped. This script extracts the minimums from dub.json and fails if
# the README does not mention the matching "DMD <ver>+" / "LDC <ver>+" strings.
#
# CI runs this as a lint gate; run it locally the same way:
#     ./scripts/check-readme-versions.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# Pull ">=2.111.0" -> "2.111" and ">=1.41.0" -> "1.41" out of dub.json.
extract() {
  local key="$1"
  grep -oE "\"${key}\"[[:space:]]*:[[:space:]]*\">=[0-9]+\.[0-9]+" dub.json \
    | grep -oE "[0-9]+\.[0-9]+"
}

dmd_ver="$(extract dmd || true)"
ldc_ver="$(extract ldc || true)"

if [[ -z "$dmd_ver" || -z "$ldc_ver" ]]; then
  echo "error: could not read dmd/ldc minimums from dub.json toolchainRequirements" >&2
  exit 2
fi

fail=0
check() {
  local needle="$1"
  if ! grep -qF "$needle" README.md; then
    echo "error: README.md is missing \"$needle\" (from dub.json)" >&2
    fail=1
  fi
}

check "DMD ${dmd_ver}+"
check "LDC ${ldc_ver}+"

if [[ "$fail" -ne 0 ]]; then
  echo >&2
  echo "The README toolchain requirement is out of sync with dub.json." >&2
  echo "Update the Requirements section in README.md to match DMD ${dmd_ver}+ / LDC ${ldc_ver}+." >&2
  exit 1
fi

echo "README toolchain requirement matches dub.json (DMD ${dmd_ver}+ / LDC ${ldc_ver}+)."
