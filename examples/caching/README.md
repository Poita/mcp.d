# Caching (`CacheableResult`) example — dual transport

A focused, self-contained example showing the draft MCP **`CacheableResult`**
freshness hints (`ttlMs` / `cacheScope`) from *both* sides — a server that
attaches them (in ergonomic **UDA style**) and a client that reads them — over
**both** the **stdio** and **Streamable HTTP** transports from a single binary
each.

It is its own dub package (depends on the root `mcp` via a path dependency) and
does **not** modify the root `dub.json`.

## What it teaches

Cache hints let a server tell clients and intermediaries how long a result may
be reused and by whom (`public` shared cache vs `private` per-client cache).
They are **draft-only** (protocol `2026-07-28`): the server only emits the
fields when the negotiated protocol is the stateless draft, and the client must
opt in with `client.enableModern()`.

- **Per-resource hint** — `server.d` declares it with the `@cache(ttl, scope)`
  UDA (a `core.time.Duration`) on a `@resource` method; `registerHandlers` plumbs
  it onto that resource's `resources/read` result (serialized on the wire as
  `ttlMs` milliseconds).
  ```d
  @resource("config://app", "Application configuration", "application/json")
  @cache(60.seconds, "private")
  string config() @safe { return `{"theme":"dark","retries":3}`; }
  ```
- **Per-list hint** — `server.d` calls
  `server.setListCacheHint("resources/list", CacheHint(5.seconds, CacheScope.public_))`.
  It rides on the `resources/list` result. (Valid list methods: `tools/list`,
  `resources/list`, `resources/templates/list`, `prompts/list`.)
- **Consumer's-eye view** — `client.d` enables draft mode
  (`client.enableModern()`), then reads `list.cache.ttl` / `cacheScope` and
  `readResource(uri).cache.ttl` / `cacheScope` (each `.ttl` a `Duration`).

A third resource (`status://live`) is registered with **no** hint, and the
client asserts that its read carries **no** cache hint — proving the absence is
reported faithfully.

## Typed APIs used

The server stays in the ergonomic UDA style (`@resource` + `@cache` +
`registerHandlers`) — no low-level raw-Json registration. Cache hints are passed
as typed `CacheHint` / `CacheScope` values, and the client consumes typed
`listResources()` / `readResource()` results whose `.cache` field is a typed
`Nullable!CacheHint`.

Over stdio the client spawns the server with `McpClient.spawn([serverBinaryPath()])`
and reaps it with `client.close()` (the SDK owns the subprocess and runs the MCP
stdio shutdown sequence: close stdin → `SIGTERM` → `SIGKILL`) — there is no
hand-rolled `ProcessPipes` plumbing. (This example has no tool/elicitation/sampling
surface, so the typed callTool / `structuredContentAs!T` / elicitation /
MRTR-builder APIs do not apply here.)

## Dual transport — one binary each

Both `server.d` and `client.d` pick their transport from flags:

| Side   | stdio (default)              | HTTP                                       |
| ------ | ---------------------------- | ------------------------------------------ |
| server | (no flags) → `runStdio`      | `--http [--port N] [--host H]` → `runStreamableHttp` |
| client | (no flags) → spawns server   | `--http http://127.0.0.1:N/mcp` → `McpClient.http` |

The client's assertions are transport-agnostic, so the SAME client verifies both
transports.

## Self-verifying e2e test

`client.d` is also an end-to-end regression test. It asserts the concrete values
that `server.d` set:

| Surface                       | `ttlMs` | `cacheScope` |
| ----------------------------- | ------- | ------------ |
| `resources/list`              | 5000    | `public`     |
| `resources/read config://app` | 60000   | `private`    |
| `resources/read status://live`| (none)  | (none)       |

On success it prints `OK: ...` and exits `0`; on any mismatch it prints what
differed and exits non-zero.

## Running it

### stdio (simplest — the client spawns the server)

```sh
dub build -c server && dub build -c client
dub run -c client
echo "exit code: $?"   # 0 = all assertions passed
```

The client locates the built `caching-server` binary next to itself, spawns it
over stdio (no `--http`), drives it, and reaps it on exit.

### HTTP (two steps)

```sh
dub build -c server && dub build -c client

# terminal 1 — start the HTTP server (serves http://127.0.0.1:8531/mcp)
dub run -c server -- --http --port 8531

# terminal 2 — run the self-verifying client against it
dub run -c client -- --http http://127.0.0.1:8531/mcp
echo "exit code: $?"   # 0 = all assertions passed
```

One-shot HTTP equivalent (what CI does):

```sh
dub build -c server && dub build -c client
./caching-server --http --port 8531 &
SERVER_PID=$!
sleep 3
./caching-client --http http://127.0.0.1:8531/mcp
RESULT=$?
kill $SERVER_PID
exit $RESULT
```

The HTTP port can be changed with `--port`; point the client at it with
`--http http://127.0.0.1:<port>/mcp`.

## Auth

Authentication (OAuth bearer tokens) is an **HTTP-only** concern in MCP: the
OAuth flows and the `Authorization: Bearer <token>` header live on the HTTP
transport. There is no stdio equivalent (stdio is a local, trusted pipe between
parent and child process), so `client.setBearerToken(...)` is a no-op over
stdio. This caching example does not require auth; if you fronted the HTTP server
with an OAuth-protected deployment, you would attach the token on the HTTP
client only.
