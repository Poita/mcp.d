# stateless-draft — Stateless (draft) protocol, dual-transport (stdio + HTTP)

A focused, self-contained example of the MCP **draft (2026-07-28) stateless
protocol**, shown from both sides and runnable over **both** transports from a
single server binary and a single client e2e. It is its own dub package with a
path-dependency on the root `mcp` library, so it does not touch the root
`dub.json`.

## What it teaches

The draft redesign drops the stateful `initialize` handshake in favor of a
**per-request** model:

- **`server/discover`** — the client asks the server up front for its
  `supportedVersions`, capabilities, and identity (instead of negotiating
  inside `initialize`).
- **Per-request `_meta`** — every request carries the protocol version, client
  identity, and client capabilities in `params._meta`; there is no long-lived
  session to set up or tear down. Because this is purely message-level, the
  draft model rides **identically over stdio and Streamable HTTP** — the same
  client e2e verifies both.
- **`enableModern()` / `connect()`** — `enableModern()` switches the client into
  stateless draft mode; `connect()` runs `server/discover` and selects the
  newest mutually-supported version (the draft here).
- **`CacheableResult` freshness hints** — draft results may carry `ttlMs` /
  `cacheScope`. The server attaches a per-list hint to `tools/list` and a
  per-resource hint to `resources/read`; the client reads them back off
  `listTools().cache` and `readResource(...).cache`.

## Typed APIs

This example uses the SDK's **ergonomic UDA + typed** surface only — there is no
hand-built request/response Json on the server:

- The `@tool` `add` method returns a typed `SumResult` struct. The SDK infers
  the input schema from the typed parameters and infers `structuredContent`
  (plus a JSON text mirror) from the returned struct — no hand-built
  `CallToolResult`.
- The `@resource` `greeting` method's draft freshness hint is declared with the
  `@cache(ttl, scope)` UDA (a `core.time.Duration`), and `registerHandlers` wires
  everything up.

The client side likewise uses the SDK's typed surface where it cleanly applies:

- It calls `add` with a typed **`callTool("add", AddArgs(2, 40))`** instead of
  hand-building an `arguments` Json object.
- It reads the result's `structuredContent` back as a typed struct via
  **`res.structuredContentAs!SumResult`**, asserting on `sum.sum` rather than
  indexing raw `Json`.

(The *error-path* call still passes a dynamic `Json.emptyObject`, since it is a
deliberately malformed call to an unknown tool.)

## Shared scaffold

Transport selection, the event-loop wiring, and the assertion primitives come
from the shared **`examples_common`** package (`examples/common`), so this
example contains no transport boilerplate of its own:

- the server's `main` calls **`runServerFromArgs(server, args, 8431)`**, which
  parses `--http` / `--port` / `--host` and serves Streamable HTTP or stdio;
- the client's `main` calls **`runClient(...)`** (drives the vibe event loop
  uniformly for both transports) around
  **`connectFromArgs(args, "stateless-draft-server")`**, which connects over
  HTTP for `--http <url>` (alias `--url <url>`) or otherwise spawns the sibling
  `stateless-draft-server` binary over stdio via `McpClient.spawnSibling`;
- the e2e assertions use the shared **`check`** / **`checkEq`** helpers, which
  print a `FAIL:` line and throw on mismatch so `runClient` returns a non-zero
  exit code.

## Files

- `server.d` — one binary, either transport. Defaults to **stdio**
  (`runStdio`); pass `--http` (with `--port` / `--host`) to serve over
  **Streamable HTTP** (`runStreamableHttp`). Exposes the `add` tool and the
  `demo://greeting` resource, plus the two draft cache hints. The server object
  is protocol-agnostic; the draft model is engaged per-request by the client.
- `client.d` — connects over the selected transport, runs `server/discover`,
  exercises the tool and resource statelessly, and **asserts the expected
  values**. It is a self-verifying e2e test: it prints an `OK:` summary and
  exits 0 on success, or prints what differed and exits non-zero on any
  mismatch. With no `--http`, it spawns the built server binary and talks stdio;
  with `--http <url>`, it connects over HTTP. The assertions are
  transport-agnostic, so the same client verifies both.
- `dub.json` — `server` and `client` configurations.

## Run over stdio (one terminal)

The client spawns the server binary itself, so just build both and run the
client:

```sh
dub build -c server     # produces ./stateless-draft-server (also spawned by the client)
dub build -c client
dub run -c client
echo "exit code: $?"    # 0 = all assertions passed
```

## Run over Streamable HTTP (two terminals)

Terminal 1 — start the server with `--http` (listens on `http://127.0.0.1:8431/mcp`):

```sh
dub run -c server -- --http --port 8431
```

Terminal 2 — run the client e2e against it:

```sh
dub run -c client -- --http http://127.0.0.1:8431/mcp
echo "exit code: $?"    # 0 = all assertions passed
```

Either way the client prints a line like:

```
OK: stateless-draft e2e passed over <transport> — discover(2026-07-28), connect()=draft, listTools[add] cache(5000/public), add->{"sum":42} (+structuredContent), greeting resource cache(9000/private), unknown-tool=-32602.
```

CI runs both: the stdio path (run the client, which spawns the server) and the
HTTP path (start the server with `--http` in the background, run the client with
`--http`), checking the exit code each time — so any behavioral regression on
either transport fails the build.

## A note on auth

This example does **not** demonstrate auth. OAuth in MCP is an **HTTP-only**
concern: the bearer-token / authorization flow lives in HTTP headers and the
`401` + `WWW-Authenticate` challenge, which only the Streamable HTTP transport
carries. The stdio transport is a local trusted pipe with no such layer, so
there is no stdio equivalent to document. See the `auth` example for the
HTTP-only OAuth flow.
