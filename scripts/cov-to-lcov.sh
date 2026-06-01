#!/usr/bin/env bash
# Convert D's `dub test --coverage` output (dmd-style per-module `.lst` files in
# the repo root) into a single lcov `lcov.info`. lcov is ingested reliably by
# Codecov / any coverage tool, whereas D's `.lst` format + dub's dash-mangled
# filenames (source-mcp-foo.lst) are flaky to parse.
#
# Each `.lst` line is `<count>|<source line>`:
#   - blank count  -> non-executable line (skipped)
#   - a number     -> executed that many times
#   - 0000000      -> executable but not covered (count 0)
# The final line of each file is `<path> is N% covered` (or `... has no code`),
# which gives the real source path.
#
# Usage: scripts/cov-to-lcov.sh [output] [glob]   (defaults: lcov.info, *.lst)
set -uo pipefail
out="${1:-lcov.info}"
: > "$out"
shopt -s nullglob
files=( *.lst )
[ "$#" -ge 2 ] && files=( "${@:2}" )

for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  last="$(tail -n 1 "$f")"
  case "$last" in
    *"has no code"*) continue ;;            # nothing executable
    *" is "*"% covered") src="${last%% is *}" ;;
    *) continue ;;                          # not a coverage summary line
  esac
  [ -f "$src" ] || continue                 # only map files that exist in the tree

  {
    echo "SF:$src"
    # Body lines (all but the last summary line); body line N == source line N.
    awk -F'|' -v n="$(( $(wc -l < "$f") - 1 ))" '
      NR <= n {
        cnt = $1; gsub(/ /, "", cnt);
        if (cnt ~ /^[0-9]+$/) printf "DA:%d,%d\n", NR, cnt + 0;
      }' "$f"
    echo "end_of_record"
  } >> "$out"
done

# Quick summary to stderr.
awk -F, '/^DA:/ { total++; if ($2+0 > 0) hit++ }
  END { if (total) printf "lcov: %d/%d lines hit (%.1f%%)\n", hit, total, 100*hit/total > "/dev/stderr" }' "$out"
