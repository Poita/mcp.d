#!/usr/bin/env bash
# Build and e2e-run every example under examples/ (each is its own dub package).
# Each example's client is a self-verifying e2e test (exits non-zero on failure).
# - stdio examples (client uses McpClient.spawn): just run the client.
# - http examples: start the server (default port), run the client, check exit, stop.
set -uo pipefail
fail=0
for d in examples/*/; do
  n=$(basename "$d")
  [ -f "${d}dub.json" ] || continue
  echo "::group::example ${n}"
  if ! ( cd "$d" && dub build -c server && dub build -c client ); then
    echo "BUILD FAILED: ${n}"; fail=1; echo "::endgroup::"; continue
  fi
  if grep -q 'spawn' "${d}client.d" 2>/dev/null; then
    echo "[stdio] running ${n} client (spawns server)"
    ( cd "$d" && dub run -c client --quiet ) || { echo "E2E FAILED (stdio): ${n}"; fail=1; }
  else
    echo "[http] starting ${n} server + running client"
    ( cd "$d" && dub run -c server --quiet >"/tmp/ex-${n}-srv.log" 2>&1 ) &
    srvpid=$!
    sleep 4
    if ! ( cd "$d" && dub run -c client --quiet ); then
      echo "E2E FAILED (http): ${n}"; echo "--- server log ---"; tail -20 "/tmp/ex-${n}-srv.log"; fail=1
    fi
    kill "$srvpid" 2>/dev/null || true
    pkill -f "${n}-server" 2>/dev/null || true
  fi
  echo "::endgroup::"
done
if [ "$fail" -eq 0 ]; then echo "ALL EXAMPLES PASSED"; else echo "SOME EXAMPLES FAILED"; fi
exit "$fail"
