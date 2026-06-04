#!/usr/bin/env bash
# Build and e2e-run every example under examples/ over EVERY transport it
# supports. Each example's client is a self-verifying e2e test (it asserts the
# server's behaviour and exits non-zero on any mismatch).
#
#   - HTTP (every example): start the server with `--http --port <P>` (auth is
#     HTTP by default, started with just `--port <P>`), then run the client
#     against http://127.0.0.1:<P>/mcp (auth client uses `--url`, the rest use
#     `--http`).
#   - stdio (every example EXCEPT auth): run the client with no transport flag;
#     it spawns the server binary and speaks MCP over the pipe. `auth` is
#     inherently HTTP (OAuth 2.1 resource-server protection), so it has no stdio
#     mode.
set -uo pipefail
fail=0

# Per-example HTTP port, kept distinct so the servers never collide.
port_for() {
  case "$1" in
    auth) echo 8742 ;;
    caching) echo 8531 ;;
    elicitation) echo 9355 ;;
    mrtr) echo 8765 ;;
    prompts) echo 8533 ;;
    resources) echo 8349 ;;
    sampling) echo 9354 ;;
    stateless-draft) echo 8431 ;;
    stickynotes) echo 8537 ;;
    streaming) echo 9357 ;;
    tools) echo 8530 ;;
    *) echo 8600 ;;
  esac
}

for d in examples/*/; do
  n=$(basename "$d")
  [ -f "${d}dub.json" ] || continue
  # Skip shared library packages (e.g. examples/common) — they are helper
  # libraries with no server/client configurations, not runnable examples.
  if grep -q '"targetType"[[:space:]]*:[[:space:]]*"library"' "${d}dub.json"; then
    echo "skipping library package ${n}"
    continue
  fi
  echo "::group::example ${n}"

  if ! ( cd "$d" && dub build -c server && dub build -c client ); then
    echo "BUILD FAILED: ${n}"; fail=1; echo "::endgroup::"; continue
  fi

  # --- stdio (every example except the inherently-HTTP auth) ---
  if [ "$n" != "auth" ]; then
    echo "[stdio] ${n}: client spawns the server"
    if ! ( cd "$d" && dub run -c client --quiet ); then
      echo "E2E FAILED (stdio): ${n}"; fail=1
    fi
  else
    echo "[stdio] ${n}: N/A (HTTP-only example)"
  fi

  # --- http (every example) ---
  p=$(port_for "$n")
  url="http://127.0.0.1:${p}/mcp"
  echo "[http] ${n}: server on ${url}"
  if [ "$n" = "auth" ]; then
    ( cd "$d" && dub run -c server --quiet -- --port "$p" >"/tmp/ex-${n}-srv.log" 2>&1 ) &
    clientflag="--url"
  else
    ( cd "$d" && dub run -c server --quiet -- --http --port "$p" >"/tmp/ex-${n}-srv.log" 2>&1 ) &
    clientflag="--http"
  fi
  srvpid=$!
  sleep 4
  if ! ( cd "$d" && dub run -c client --quiet -- "$clientflag" "$url" ); then
    echo "E2E FAILED (http): ${n}"; echo "--- server log ---"; tail -20 "/tmp/ex-${n}-srv.log"; fail=1
  fi
  kill "$srvpid" 2>/dev/null || true
  pkill -f "${n}-server" 2>/dev/null || true

  echo "::endgroup::"
done

if [ "$fail" -eq 0 ]; then
  echo "ALL EXAMPLES PASSED (stdio + http)"
else
  echo "SOME EXAMPLES FAILED"
fi
exit "$fail"
