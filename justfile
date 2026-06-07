# Common developer tasks for the D MCP SDK.
#
# Run `just <task>` to invoke a recipe (install just from https://just.systems).
# Run `just` (or `just --list`) to see all available tasks.
#
# Every recipe sets `ulimit -n 65536` before invoking `dub`. Some terminals
# (notably ghostty) default to `ulimit -n unlimited`, under which the D
# toolchain spuriously hits its open-file limit and fails; an explicit, finite
# limit fixes it. See CONTRIBUTING.md ("The `ulimit -n` gotcha").

# Pin the official conformance harness; matches CONFORMANCE_VERSION in
# .github/workflows/conformance.yml. Bump deliberately, never `@latest`.
conformance_version := "0.1.16"

# Show the list of available recipes (default when you run bare `just`).
default:
    @just --list

# Build the library.
build:
    ulimit -n 65536 && dub build

# Run all unit tests (every module must pass).
test:
    ulimit -n 65536 && dub test

# Format the source in place (source/ + conformance/, matching CI).
fmt:
    ulimit -n 65536 && dub run dfmt -- --inplace source/ conformance/

# Run the exact D-Scanner lint gate CI runs (with documented filters).
lint:
    ./scripts/dscanner-lint.sh

# Build + run the official MCP server conformance suite (server 39/39).
conformance-server:
    ulimit -n 65536 && dub build -c conformance-server
    ./conformance-server --port 3000 & \
      SERVER_PID=$!; \
      trap 'kill "$SERVER_PID" 2>/dev/null || true' EXIT; \
      for i in $(seq 1 30); do \
        if curl -sf -o /dev/null "http://127.0.0.1:3000/mcp" \
          -H 'Accept: application/json, text/event-stream' \
          -H 'Content-Type: application/json' \
          -X POST -d '{}'; then break; fi; \
        sleep 1; \
      done; \
      npx --yes "@modelcontextprotocol/conformance@{{conformance_version}}" \
        server --url http://127.0.0.1:3000/mcp

# Build + run the official MCP client conformance suite (client 287/287).
conformance-client:
    ulimit -n 65536 && dub build -c conformance-client
    npx --yes "@modelcontextprotocol/conformance@{{conformance_version}}" \
      client --command ./conformance-client --suite all

# Run both conformance suites (server then client).
conformance: conformance-server conformance-client
