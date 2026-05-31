# stateless-draft — Stateless (draft) protocol over Streamable HTTP

A focused, self-contained example of the MCP **draft (2026-07-28) stateless
protocol**, shown from both sides. It is its own dub package with a
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
  session to set up or tear down. Over Streamable HTTP each request is fully
  self-describing (the standard `Mcp-Method` / `Mcp-Name` /
  `MCP-Protocol-Version` headers are derived automatically).
- **`enableDraft()` / `connect()`** — `enableDraft()` switches the client into
  stateless draft mode; `connect()` runs `server/discover` and selects the
  newest mutually-supported version (the draft here).
- **`CacheableResult` freshness hints** — draft results may carry `ttlMs` /
  `cacheScope`. The server attaches a per-list hint to `tools/list` and a
  per-resource hint to `resources/read`; the client reads them back off
  `listTools().cache` and `readResource(...).cache`.

## Files

- `server.d` — a deployable Streamable HTTP server (`runStreamableHttp`) with an
  `add` tool and a `demo://greeting` resource, plus the two draft cache hints.
  The server object is protocol-agnostic; the draft model is engaged per-request
  by the client.
- `client.d` — connects, runs `server/discover`, exercises the tool and
  resource statelessly, and **asserts the expected values**. It is a
  self-verifying e2e test: it prints an `OK:` summary and exits 0 on success, or
  prints what differed and exits non-zero on any mismatch.
- `dub.json` — `server` and `client` configurations.

## Run (Streamable HTTP — two terminals)

Terminal 1 — start the server (listens on `http://127.0.0.1:8431/mcp`):

```sh
dub run -c server
```

Terminal 2 — run the client e2e against it:

```sh
dub run -c client -- http://127.0.0.1:8431/mcp
# (the URL is optional; it defaults to http://127.0.0.1:8431/mcp)
echo "exit code: $?"   # 0 = all assertions passed
```

The client prints a line like:

```
OK: stateless-draft e2e passed — discover(2026-07-28), connect()=draft, listTools[add] cache(5000/public), add->42 (+structuredContent), greeting resource cache(9000/private), unknown-tool=-32602.
```

CI runs the same two steps: start `server.d` in the background, run `client.d`,
and check the exit code — so any behavioral regression fails the build.
