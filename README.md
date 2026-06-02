# mcp.d

[![CI](https://github.com/Poita/mcp.d/actions/workflows/ci.yml/badge.svg)](https://github.com/Poita/mcp.d/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Poita/mcp.d/branch/main/graph/badge.svg)](https://codecov.io/gh/Poita/mcp.d)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A feature-complete [Model Context Protocol](https://modelcontextprotocol.io) (MCP) SDK for
the D programming language — client and server, built on [vibe-d](https://vibed.org).

```d
import mcp;

@tool("add", "Add two integers")
long add(long a, long b) @safe { return a + b; }
void main()
{
    auto server = new McpServer("demo", "1.0.0");
    registerModule!(__traits(parent, add))(server);
    runStdio(server);
}
```

## Goals

- Full MCP support across every protocol version (`2024-11-05` → `draft`) with negotiation.
- Both transports: **stdio** and **Streamable HTTP**.
- FastMCP-style ergonomic server API via D attributes (`@tool`, `@resource`, `@prompt`).
- Batteries included: OAuth 2.1, SSE resumability, all protocol utilities.
- Validated against the official `@modelcontextprotocol/conformance` suite.

## Status

**All official conformance tests pass** (0 failures): **server 38/38**, **client 287/287**
(one advisory `SHOULD` warning on the optional Client-ID-Metadata-Document flow).

- ✅ **All 30 server scenarios**: lifecycle, tools with every content type, resources +
  templates + subscribe, prompts, completion, logging, progress/logging streaming, sampling,
  elicitation (incl. SEP-1034/1330), DNS-rebinding protection.
- ✅ **All client scenarios**, including the **complete OAuth 2.1** suite — token-endpoint
  auth (none/basic/post + **`private_key_jwt`** ES256), metadata discovery (all variants +
  2025-03-26 backcompat + endpoint fallback), scope selection/step-up/retry-limit,
  offline-access, DCR, pre-registration, resource-mismatch, **cross-app access**
  (token-exchange → JWT-bearer); **elicitation** with schema defaults; and **SSE
  resumption** (`retry:` + `Last-Event-ID`).
- ✅ **FastMCP-style UDA API** — `@tool` / `@resource` / `@prompt` with auto JSON-Schema.
- ✅ **DRAFT (2026-07-28)** — stateless per-request `_meta`, `server/discover`,
  `subscriptions/listen`, `CacheableResult` (`ttlMs`/`cacheScope`), MRTR types, the standard
  request headers (`Mcp-Method`/`Mcp-Name`/`MCP-Protocol-Version`) with `HeaderMismatch`
  validation, and `x-mcp-header` mirroring — on both client and server.

Optional follow-ups (not required for conformance): Client-ID-Metadata-Document client_id
(currently uses DCR, a passing SHOULD warning), MRTR end-to-end client retry helper, and a
built-in loopback redirect listener for the interactive auth-code flow.

## Requirements

- A D toolchain with frontend **2.100+** (DMD 2.100+, or LDC 1.30+).
- **OpenSSL 3.x** must be installed on the system. The `openssl` / vibe-d:tls
  dependency links against it for TLS (HTTPS transport, OAuth 2.1).
  - **Ubuntu/Debian:** ships with OpenSSL 3.x (`apt install libssl-dev` if headers
    are missing).
  - **macOS:** `brew install openssl@3`, then export
    `PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"` so dub can find it.

## Build & test

```bash
ulimit -n 65536        # required: dub misbehaves under ghostty's `ulimit -n unlimited`
dub build              # build the library
dub test               # run all unit tests (11 modules, ~120 tests)
```

Formatting and linting:

```bash
dub run dfmt -- --inplace source/
dub run dscanner -- --styleCheck source/
```

## API documentation

Browsable HTML API docs are generated from the ddoc comments in `source/mcp`:

```bash
scripts/gen-docs.sh        # auto: adrdox if available, else ddox -> docs/
```

The script prefers [adrdox](https://github.com/adamdruppe/adrdox) (the best D
documentation generator) and falls back to dub's built-in ddox build when adrdox
is not on `PATH`:

```bash
GENERATOR=adrdox scripts/gen-docs.sh   # require adrdox
GENERATOR=ddox   scripts/gen-docs.sh   # force the ddox fallback (dub build -b ddox)
OUTDIR=site      scripts/gen-docs.sh   # write to ./site instead of ./docs
```

Open `docs/index.html` in a browser when it finishes. The generated `docs/`
directory is a build artifact and is git-ignored.

CI builds the docs on every push/PR (`.github/workflows/docs.yml`) so doc
generation can never silently break, and publishes them to GitHub Pages on
pushes to `main` (best-effort: the publish step is skipped if Pages is not
enabled for the repository).

## Statefulness

A server chooses one of two statefulness models at construction. **Stateless is
the default.** The author picks the mode via factories; the existing
`new McpServer(name, version)` constructors keep working and default to
stateless.

```d
auto s1 = McpServer.stateless("my-server", "1.0.0"); // default; same as `new McpServer(...)`
auto s2 = McpServer.stateful("my-server", "1.0.0");   // opt-in session management
```

The core invariant: **a stateless server has NO shared state across HTTP calls.**
`McpServer` holds no mutable per-connection state; per-connection state lives in a
`ConnectionState` object (`mcp.server.connection`) — protocol version, client
capabilities, log level, resource subscriptions, and the in-flight cancellation
registry. In **stateful** mode the SDK keys everything on `Mcp-Session-Id`: there
is exactly one `ConnectionState` per session, owned by the transport's
`SessionManager`. In **stateless** mode the transport builds a transient
`ConnectionState` per request and discards it, so two concurrent peers sharing one
`McpServer` cannot leak version, capability, subscription, or cancellation state
into one another (issue #550).

Because a stateless server keeps nothing across HTTP calls, **anything that
correlates more than one HTTP call is forbidden over HTTP in stateless mode and
errors rather than silently dropping**: server-initiated `elicit`/`sample`/`roots`
(any server->client request), `resources/subscribe`/`resources/unsubscribe`, the
draft `subscriptions/listen` stream, and the standalone GET SSE stream. Each of
those would have to ride mount-global state (the `StreamCoordinator` / GET-push
channel / per-session subscription set), which is exactly the shared state a
stateless server must not keep. The gating depends only on `server.mode`
(`ServerMode.stateless`), **not** on the negotiated protocol version — modern-draft
and legacy stateless are gated identically.

> **Guidance:** if your tools initiate elicitation/sampling/roots, or use resource
> subscriptions / `subscriptions/listen` over HTTP, construct the server with
> `McpServer.stateful()`. Stateless is correct for plain request/response tools,
> resources, prompts, progress, and the draft MRTR (more-requests-then-respond)
> input flow, none of which correlate more than one HTTP call.

**stdio note:** stdio is a single implicit connection for the life of the process
(it assumes protocol `2025-11-25`), so server->client requests (`elicit`/`sample`/
`roots`) work over stdio **in any mode** — the gating above applies only to the
HTTP transport. A stateless server is therefore fully usable over stdio even for
elicitation/sampling.

### The three effective modes

| | Resolution of per-connection state | Notes |
|---|---|---|
| **Modern stateless** (stateless + request >= draft) | Per-request `_meta` (protocolVersion + clientCapabilities + logLevel) | No `initialize` (uses `server/discover`); input via MRTR; **no** subscriptions/listen, **no** blocking server->client elicitation/sampling over HTTP (see the feature-gating matrix) |
| **Legacy stateless** (stateless + request < draft) | `MCP-Protocol-Version` header (default `2025-03-26`; stdio assumes `2025-11-25`); client capabilities **unknown** (assumed none) | `initialize`/`notifications/initialized` are no-ops (no session id minted); a `tools/call` may be the first request with no prior `initialize`; correlation features are forbidden |
| **Stateful** (opt-in, pre-draft only) | `ConnectionState` resolved by `Mcp-Session-Id`, created at `initialize` | The draft is **excluded** from negotiation (clamped down to `<= 2025-11-25`); `server/discover` is not served; DELETE terminates the session |

### Feature-gating matrix

The gating is keyed on `server.mode`, not the protocol version, so the two
stateless eras (modern-draft and legacy) forbid the same correlation features over
HTTP — they differ only in how each request's `ConnectionState` is resolved.

| Feature (over HTTP) | Modern stateless | Legacy stateless | Stateful |
|---|---|---|---|
| `initialize` handshake | n/a (`server/discover`) | no-op (no session id) | mints `Mcp-Session-Id` |
| Per-request `_meta` version/caps | yes | n/a (header + empty caps) | n/a (session-negotiated) |
| Standalone GET SSE stream | forbidden (405) | forbidden (405) | yes |
| `resources/subscribe` / `unsubscribe` | forbidden (-32601) | forbidden (-32601) | yes |
| `subscriptions/listen` (draft) | forbidden (-32601) | n/a (draft-only) | yes |
| Server->client `elicit`/`sample`/`roots` | forbidden (error; MRTR instead) | forbidden (error) | yes |
| `logging/setLevel` | n/a (per-request `_meta`) | per-request / n/a | yes (session-scoped) |
| Session id minted | never | never | yes |

The `subscribe` capability advertisement follows the same rule: a stateless server
does **not** advertise the resources `subscribe` capability even after
`enableResourceSubscriptions()` (the opt-in is inert in stateless mode), so a
client never expects per-resource update push it could not receive. The
server->client (elicit/sample/roots) gating is bypassed on **stdio** (a single
implicit connection — see the stdio note above).

The Streamable HTTP transport derives session minting purely from
`server.mode` (`ServerMode.stateful` => mint and require `Mcp-Session-Id`;
`ServerMode.stateless` => never). There is no separate `enableSessions` option.

## Examples

The repository ships ten runnable, self-verifying server/client pairs in
[`examples/`](examples/). Each `client.d` is an end-to-end test that asserts the
matching server's behaviour, and CI runs every pair over **both** stdio and
Streamable HTTP.

| Example | What it shows | Server | Client |
| --- | --- | --- | --- |
| Tools | `@tool` handlers with typed args/results | [server](examples/tools/server.d) | [client](examples/tools/client.d) |
| Prompts | `@prompt` templates | [server](examples/prompts/server.d) | [client](examples/prompts/client.d) |
| Resources | resources + templates + `subscriptions/listen` push | [server](examples/resources/server.d) | [client](examples/resources/client.d) |
| Caching | draft `CacheableResult` hints (`ttlMs`/`cacheScope`) | [server](examples/caching/server.d) | [client](examples/caching/client.d) |
| Stateless draft | the stateless draft protocol (`server/discover`, per-request `_meta`) | [server](examples/stateless-draft/server.d) | [client](examples/stateless-draft/client.d) |
| Streaming | progress notifications from a long-running tool | [server](examples/streaming/server.d) | [client](examples/streaming/client.d) |
| MRTR | multi-round-trip tool input (carried in the result) | [server](examples/mrtr/server.d) | [client](examples/mrtr/client.d) |
| Sampling | server-initiated LLM sampling (`ctx.sample`) | [server](examples/sampling/server.d) | [client](examples/sampling/client.d) |
| Elicitation | server-initiated, typed user input (`ctx.elicit!T`) | [server](examples/elicitation/server.d) | [client](examples/elicitation/client.d) |
| Auth | OAuth 2.1 protected HTTP resource server (HTTP only) | [server](examples/auth/server.d) | [client](examples/auth/client.d) |

Annotate plain typed D functions with `@tool` / `@resource` / `@prompt` and register
a whole module with `registerModule!(my.module)(server)` — the input schema (from
the parameter types) and output schema (from the return type) are derived at
compile time, and arguments/results are marshalled for you. A handler may take a
trailing `RequestContext` parameter to report progress, log, or call back to the
client (sampling/elicitation). For tools whose schema is only known at runtime,
drop to `server.registerDynamicTool(Tool, delegate)` / `registerResource` /
`registerDynamicPrompt`, which receive the raw `Json`.

## Event-loop model

`McpClient` speaks vibe.d async I/O: call every `McpClient` method from inside the
vibe event loop — wrap your calls in a `runTask` under `runEventLoop()` (the
examples' shared scaffold does this for you). The same API (`initialize` /
`listTools` / `callTool` / `listResources` / `readResource` / `listPrompts` /
`getPrompt` / `subscribe` / `setLogLevel`, plus the auto-paginated list helpers and
`enableDraft()`) works over every transport. `McpClient.http(url)` builds a client
over Streamable HTTP; `McpClient.spawn(command)` / `McpClient.stdio(readLine,
writeLine)` build one over stdio. The server side is `runStreamableHttp(server,
port)` or `runStdio(server)`.


## Running the conformance suite

Server suite:

```bash
dub build -c conformance-server
./conformance-server --port 3000 &
npx @modelcontextprotocol/conformance@0.1.16 server --url http://127.0.0.1:3000/mcp
```

Client suite:

```bash
dub build -c conformance-client
npx @modelcontextprotocol/conformance@0.1.16 client --command ./conformance-client --suite all
```

Both suites run automatically in CI on every push and pull request via the
[`Conformance`](.github/workflows/conformance.yml) workflow, with the harness
version pinned for reproducibility. The job fails on any scenario failure,
keeping the **server 38/38** and **client 287/287** baseline honest.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup,
the build/test/lint commands, project conventions, and the PR flow.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). This aligns the SDK with the [Model Context Protocol project](https://github.com/modelcontextprotocol/modelcontextprotocol), which is licensed under Apache-2.0.
