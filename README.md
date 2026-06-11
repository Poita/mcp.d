# mcp.d

[![CI](https://github.com/Poita/mcp.d/actions/workflows/ci.yml/badge.svg)](https://github.com/Poita/mcp.d/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Poita/mcp.d/branch/main/graph/badge.svg)](https://codecov.io/gh/Poita/mcp.d)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![API docs](https://img.shields.io/badge/docs-API%20reference-blue.svg)](https://poita.github.io/mcp.d/)

A feature-complete [Model Context Protocol](https://modelcontextprotocol.io) (MCP) SDK for
the D programming language — client and server, built on [vibe-d](https://vibed.org).

## Quickstart

A server is a handful of annotated functions plus `runStdio`:

```d
// server.d
import mcp;
import mcp.transport : runStdio;

@tool("add", "Add two integers")
long add(long a, long b) @safe { return a + b; }

void main()
{
    auto server = new McpServer("demo", "1.0.0");
    registerModule!(__traits(parent, add))(server);
    runStdio(server);
}
```

A client spawns that server over stdio, negotiates the protocol (any era — legacy
or modern) with `connect()`, calls the tool, and checks the result:

```d
// client.d — build server.d as ./demo-server first
import mcp;
import vibe.data.json : parseJsonString;
import vibe.core.core : runTask, runEventLoop, exitEventLoop;

void main()
{
    // The client drives vibe's event loop.
    runTask(() nothrow {
        scope (exit) exitEventLoop();
        try
        {
            auto client = McpClient.spawn(["./demo-server"]);
            scope (exit) client.close();
            client.connect();

            auto r = client.callTool("add", parseJsonString(`{"a": 2, "b": 3}`));
            assert(r.structuredContent["result"].get!long == 5);
        }
        catch (Exception e) assert(false, e.msg);
    });
    runEventLoop();
}
```

## Installation

Add mcp.d to your project with dub:

```bash
dub add mcp-d
```

Or add it manually to your `dub.json`:

```json
"dependencies": {
    "mcp-d": "~>0.1"
}
```

Then `import mcp;` in your source files.

## Goals

- Full MCP support across every protocol version (`2024-11-05` → `draft`) with negotiation.
- Both transports: **stdio** and **Streamable HTTP**.
- FastMCP-style ergonomic server API via D attributes (`@tool`, `@resource`, `@prompt`).
- Batteries included: OAuth 2.1, SSE resumability, all protocol utilities.
- Validated against the official `@modelcontextprotocol/conformance` suite.

## Status

**All official conformance tests pass** (0 failures): **server 39/39**, **client 287/287**
(one advisory `SHOULD` warning on the optional Client-ID-Metadata-Document flow).

- ✅ **All 39 server scenarios**: lifecycle, tools with every content type, resources +
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
  `callTool` transparently drives the full MRTR (SEP-2322) round-trip loop via an internal
  `callToolLoop`, satisfying each `InputRequest` and resubmitting until a completed result is
  returned (capped at 16 rounds to guard against misbehaving servers).

- ✅ **Client ID Metadata Documents (SEP-991)** on both sides — the spec-recommended
  registration mechanism now that DCR is deprecated. The **client** advertises and uses an
  HTTPS-URL `client_id` when the AS supports it; the **server-side OAuth proxy** opts in via
  `OAuthProxyConfig.clientIdMetadataDocumentSupported`, advertising
  `client_id_metadata_document_supported`, then fetching (SSRF-guarded, size-capped) and
  validating the hosted document at `/authorize` — exact `client_id` match, required fields
  (`client_id`, `client_name`, `redirect_uris`), and a redirect-URI allowlist sourced from the
  document — with confused-deputy consent keyed on the stable `client_id` URL. The consent
  screen surfaces the verified `client_name` and the redirect-URI hostname. DCR remains as the
  deprecated fallback.

Optional follow-ups (not required for conformance): a built-in loopback redirect listener for
the interactive auth-code flow, and a localhost-redirect impersonation warning on the proxy's
CIMD consent screen (a spec `SHOULD`).

## Requirements

- A D toolchain with frontend **2.100+** (DMD 2.100+, or LDC 1.30+).
- **OpenSSL 3.x** must be installed on the system. The `openssl` / vibe-d:tls
  dependency links against it for TLS (HTTPS transport, OAuth 2.1).
  - **Ubuntu/Debian:** ships with OpenSSL 3.x (`apt install libssl-dev` if headers
    are missing).
  - **macOS:** `brew install openssl@3`, then export
    `PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"` so dub can find it.
  - **Windows:** install OpenSSL 3.x (e.g. `choco install openssl`) and ensure its
    `bin` directory is on `PATH` so the runtime DLLs are found.

### Platform support

Linux, macOS, and Windows are all supported and exercised in CI (Linux/macOS with
DMD and LDC, Windows with LDC). The stdio transport, the OS CSPRNG, and the OAuth
token store each have native Windows code paths; on Windows the token store
tightens file permissions via ACLs rather than POSIX modes.

## Build & test

```bash
ulimit -n 65536        # required: dub misbehaves under ghostty's `ulimit -n unlimited`
dub build              # build the library
dub test               # run all unit tests (42 modules, ~1900 tests)
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
generation can never silently break, and publishes them to GitHub Pages on a
published **release** (or a manual `workflow_dispatch`), not on every push to
`main` (best-effort: the publish step is skipped if Pages is not enabled for the
repository).

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
into one another.

Because a stateless server keeps nothing across HTTP calls, **anything that has to
correlate a request with a *separate* later HTTP call is forbidden over HTTP in
stateless mode and errors rather than silently dropping**: server-initiated
`elicit`/`sample`/`roots` (a server->client request whose reply arrives on a
different POST), `resources/subscribe`/`resources/unsubscribe` (whose updates would
be delivered on the separate standalone GET stream), and the standalone GET SSE
stream itself. Each would have to ride mount-global state (the `StreamCoordinator` /
GET-push channel / per-session subscription set), which is exactly the shared state
a stateless server must not keep. The gating depends only on `server.mode`
(`ServerMode.stateless`), **not** on the negotiated protocol version.

A *self-contained* long-lived stream is fine, because it never correlates a second
HTTP call: the draft `subscriptions/listen` works in stateless mode. Its POST opens
an SSE response and the server streams `notifications/resources/updated` /
`list_changed` down that same response, filtered by the stream's own subscription
set — exactly like a tool call emitting progress on its own SSE stream. (Whether a
mutation originating on another node reaches the stream is the deployment's
out-of-band concern, not the SDK's.)

> **Guidance:** if your tools initiate elicitation/sampling/roots, or use the
> 2025-era `resources/subscribe` push over HTTP, construct the server with
> `McpServer.stateful()`. Stateless is correct for plain request/response tools,
> resources, prompts, progress, the draft `subscriptions/listen` stream, and the
> draft MRTR (more-requests-then-respond) input flow.

**stdio note:** stdio is a single implicit connection for the life of the process
(it negotiates protocol `2025-11-25` by default). Statefulness (`server.mode`),
not the transport, governs server->client requests (`elicit`/`sample`/`roots`) and
`logging/setLevel`: the same mode-based gating applies over stdio and HTTP alike.
A stateless server has no `elicit`/`sample`/`roots` and no `logging/setLevel` on
any transport; use `McpServer.stateful()` for those features, or MRTR on the modern
protocol.

### The three effective modes

| | Resolution of per-connection state | Notes |
|---|---|---|
| **Modern stateless** (stateless + request >= draft) | Per-request `_meta` (protocolVersion + clientCapabilities + logLevel) | No `initialize` (uses `server/discover`); input via MRTR; `subscriptions/listen` is supported (a self-contained stream); **no** blocking server->client elicitation/sampling on any transport (see the feature-gating matrix) |
| **Legacy stateless** (stateless + request < draft) | `MCP-Protocol-Version` header (default `2025-03-26`; stdio assumes `2025-11-25`); client capabilities **unknown** (assumed none) | `initialize`/`notifications/initialized` are no-ops (no session id minted); a `tools/call` may be the first request with no prior `initialize`; correlation features are forbidden |
| **Stateful** (opt-in, pre-draft only) | `ConnectionState` resolved by `Mcp-Session-Id`, created at `initialize` | The draft is **excluded** from negotiation (clamped down to `<= 2025-11-25`); `server/discover` is not served; DELETE terminates the session |

### Feature-gating matrix

The gating is keyed on `server.mode`, not the protocol version, so the two
stateless eras (modern-draft and legacy) forbid the same correlation features
regardless of transport — they differ only in how each request's `ConnectionState`
is resolved.

| Feature | Modern stateless | Legacy stateless | Stateful |
|---|---|---|---|
| `initialize` handshake | n/a (`server/discover`) | no-op (no session id) | mints `Mcp-Session-Id` |
| Per-request `_meta` version/caps | yes | n/a (header + empty caps) | n/a (session-negotiated) |
| Standalone GET SSE stream | forbidden (405) | forbidden (405) | yes |
| `resources/subscribe` / `unsubscribe` | forbidden (-32601) | forbidden (-32601) | yes |
| `subscriptions/listen` (draft) | yes (self-contained stream) | n/a (draft-only) | yes |
| Server->client `elicit`/`sample`/`roots` | forbidden (error; MRTR instead) | forbidden (error) | yes |
| `logging/setLevel` | n/a (per-request `_meta`) | forbidden (-32601) | yes (session-scoped) |
| Session id minted | never | never | yes |

The `subscribe` capability advertisement follows the same rule: a stateless server
does **not** advertise the resources `subscribe` capability even after
`enableResourceSubscriptions()` (the opt-in is inert in stateless mode), so a
client never expects per-resource update push it could not receive. The
server->client (elicit/sample/roots) gating is transport-agnostic — stdio follows
the same `server.mode` rules as HTTP.

The Streamable HTTP transport derives session minting purely from
`server.mode` (`ServerMode.stateful` => mint and require `Mcp-Session-Id`;
`ServerMode.stateless` => never). There is no separate `enableSessions` option.

## Client response cache

`McpClient` caches the six read-only operations the draft marks `CacheableResult`
— `listTools`, `listResources`, `listResourceTemplates`, `listPrompts`,
`readResource`, and `discover` — so a repeat call within the server's freshness
window is served locally with **no round-trip**. `callTool` and `getPrompt` are
never cached (the spec excludes them).

**On by default, byte-identical when idle.** A client built via
`McpClient.http`/`stdio`/`spawn` ships an in-memory store. Caching engages only
when a result carries a positive `ttlMs` hint, so against pre-draft servers (or a
draft server sending `ttlMs:0`) behaviour matches the uncached client exactly.
The stored entry's lifetime is the server's `ttlMs`; its `cacheScope`
(`public`/`private`) is recorded for shared backends.

```d
auto c = McpClient.http("https://server.example/mcp");
c.connect();
c.listTools();   // round-trips, then caches per the server's ttlMs
c.listTools();   // served from cache — no request
```

**Configure via `ClientSettings`** (the per-client knobs you'd otherwise pass
loose):

```d
ClientSettings s;
s.cache = noCache;            // disable caching entirely
s.cache = new MyRedisStore;   // or bring your own CacheStore (shared/persistent)
s.defaultCacheTtl = 30.seconds; // cache even responses the server left unhinted
auto c = McpClient.http(url, s);
```

A `CacheStore` is a small `get`/`put`/`invalidate`/`invalidateMethod`/
`invalidatePartition`/`clear` interface; supply your own to pre-seed entries and
skip round-trips, or share one across clients. The default `InMemoryCacheStore`
is per-client and bounded by an LRU-style size cap. `client.setCache`,
`setDefaultCacheTtl`, and `clearCache` adjust this at runtime; `cache()` exposes
the live store for pre-seeding.

**`public` vs `private` scope (shared caches).** The server's `cacheScope`
controls *where* an entry is stored, which only matters when several clients
share one backend. A `public` result lives under a shared key, so **every client
hits the same entry** — the point of a shared cache. A `private` result is
namespaced under the requesting client's `cachePartition` (a stable principal /
tenant id you set in `ClientSettings`), so it is never served to another
identity. The default per-client store leaves `cachePartition` empty and the
distinction is moot.

```d
auto shared = new MyRedisStore;
ClientSettings sa; sa.cache = shared; sa.cachePartition = "tenant-a";
ClientSettings sb; sb.cache = shared; sb.cachePartition = "tenant-b";
// a public listTools fetched by tenant-a is served to tenant-b with no round-trip;
// a private readResource stays isolated to its tenant.
```

On `setBearerToken`, the client evicts only its **own** partition (the previous
identity's `private` entries), sparing shared `public` entries and other
principals' partitions; for the default per-client store that empty partition
holds everything, so it behaves as a full clear.

**Per-call modes** via `RequestOptions.cacheMode`:

| Mode | Behaviour |
| --- | --- |
| `use` (default) | serve a fresh entry, else fetch and store |
| `bypass` | ignore the cache for read and write — force the network, store nothing |
| `refresh` | skip the read, force the network, then store the fresh result |

```d
RequestOptions o; o.cacheMode = CacheMode.refresh;
c.listResources(o); // re-fetch and update the cached entry
```

**Automatic invalidation.** The server's change notifications evict the affected
entries so the next call lazily refetches: `notifications/tools/list_changed`,
`prompts/list_changed`, and `resources/list_changed` drop the matching list
cache(s), and `resources/updated` drops just that URI's `readResource` entry. Each
also fires a typed callback (`onToolsListChanged`, `onPromptsListChanged`,
`onResourcesListChanged`, `onResourceUpdated(uri)`) in addition to the generic
`onNotification`. `setBearerToken` evicts the client's own partition so a
re-authenticated session never reads the previous identity's `private` results.

## Examples

The repository ships thirteen runnable, self-verifying server/client pairs in
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
| Tasks | async `@task` tools (progress, cancellation, mid-task input) | [server](examples/tasks/server.d) | [client](examples/tasks/client.d) |
| Sampling | server-initiated LLM sampling (`ctx.sample`) | [server](examples/sampling/server.d) | [client](examples/sampling/client.d) |
| Elicitation | server-initiated, typed user input (`ctx.elicit!T`) | [server](examples/elicitation/server.d) | [client](examples/elicitation/client.d) |
| Sticky notes | stateful tools + a resource per note + elicitation-confirmed clear | [server](examples/stickynotes/server.d) | [client](examples/stickynotes/client.d) |
| Auth | OAuth 2.1 protected HTTP resource server (HTTP only) | [server](examples/auth/server.d) | [client](examples/auth/client.d) |
| Apps | MCP Apps extension: `@ui` tool link + a `ui://` HTML resource | [server](examples/apps/server.d) | [client](examples/apps/client.d) |
| Tasks | MCP Tasks extension (SEP-2663): `@task` async tasks with progress, cancellation, and `input_required` | [server](examples/tasks/server.d) | [client](examples/tasks/client.d) |

Annotate plain typed D functions with `@tool` / `@resource` / `@prompt` and register
a whole module with `registerModule!(my.module)(server)` — the input schema (from
the parameter types) and output schema (from the return type) are derived at
compile time, and arguments/results are marshalled for you. A handler may take a
trailing `RequestContext` parameter to report progress, log, or call back to the
client (sampling/elicitation). For tools whose schema is only known at runtime,
drop to `server.registerTool(Tool, delegate)` / `registerResource` /
`registerPrompt`, which receive the raw `Json`.

## MCP Apps (interactive UI)

The [MCP Apps extension](https://modelcontextprotocol.io/extensions/apps/overview)
(`io.modelcontextprotocol/ui`) lets a server ship an interactive HTML UI that a
host renders inline in the conversation. On the server side it is metadata plus a
resource convention, and `import mcp;` brings in the helpers (`mcp.api.apps`):

```d
auto server = new McpServer("weather", "1.0.0");
registerModule!(my.module)(server);     // a @tool tagged @ui("ui://weather/dashboard", "model", "app")
enableApps(server);               // declare the extension capability

UiResourceMeta ui;
ui.csp.connectDomains = ["https://api.open-meteo.com"];
ui.prefersBorder = nullable(true);
registerUiResource(server, "ui://weather/dashboard", "weather_dashboard",
        dashboardHtml, ui);             // serve the ui:// HTML with text/html;profile=mcp-app
```

A `@tool` carries its UI link via `@ui(resourceUri, visibility…)` (folded into the
tool's `_meta.ui`); the dynamic path uses `setUiToolMeta(tool, UiToolMeta(...))`.
`clientSupportsApps(server)` reports whether the connected client opted into the
extension. The runnable [Apps example](examples/apps/) verifies the whole surface
over both transports.

The extension's `ui/` postMessage dialect (iframe ↔ host) and sandbox rendering
are a **host (browser) concern** and intentionally out of scope for this
transport-level SDK — when the embedded app calls a tool, the host proxies it to
the server as an ordinary `tools/call`, so the server implements no `ui/` methods.

## MCP Tasks (asynchronous execution)

The [MCP Tasks extension](https://modelcontextprotocol.io/extensions/tasks/overview)
(`io.modelcontextprotocol/tasks`, [SEP-2663](https://modelcontextprotocol.io/seps/2663-tasks-extension))
lets a server answer a long-running `tools/call` with a durable task handle
instead of blocking — the client polls `tasks/get` until it completes, and may
`tasks/update` (mid-flight input) or `tasks/cancel`. Mark a function `@task` and it
becomes one of these tools: the call returns a handle at once, the body runs
asynchronously, and its return value becomes the result; the injected `TaskContext`
reports progress, observes cancellation, and elicits input mid-task.

```d
auto rt = server.enableTasks();   // keep the runtime; pass a TaskStore for durability

struct Approval { bool deploy; }

@task("deploy", "Deploy a build, confirming first; finishes when the deploy signals back.")
@taskTtl(10.minutes) @taskPollInterval(2.seconds)
string deploy(string gitRef, TaskContext tc) @safe
{
    if (!tc.hasInput("ok"))
        return tc.requireInput([InputRequest.elicitation!Approval("ok", "Deploy " ~ gitRef ~ "?")]);
    if (!tc.inputAs!ElicitResult("ok").contentAs!Approval().deploy)
        return "skipped";
    startDeploy(gitRef, tc.taskId);             // fictional: kicks off the deploy, returns at once
    return tc.detach("deploying " ~ gitRef);    // leave it working; the webhook below completes it
}

// The deploy system's callback — runs on any node, holds no fiber:
void onDeployFinished(string taskId, bool ok) @safe
{
    if (ok)
        rt.complete(taskId, CallToolResult([Content.makeText("deployed")]).toJson());
    else
        rt.fail(taskId, internalError("deploy failed"));
}
```

The three exits cover the lifecycle: `return` a value completes the task,
`tc.requireInput(...)` suspends it for a client answer (delivered via `tasks/update`),
and `tc.detach(...)` leaves it `working` for `onDeployFinished` to complete out of
band via `rt.complete` / `rt.fail` — no fiber held, so it works on any node. See
[`examples/tasks`](examples/tasks/) for cancellation, durable stores, and the client side.

On the client, `callToolAwait` hides the whole flow — it drives the poll loop and
returns the final `CallToolResult`, so task and non-task tools look identical. When
you need to survive a restart, call plain `callTool` instead: if the server made a
task the result is the handle (`result.isTask`, with the seed `Task` in
`result.task`). Persist `result.task.taskId`, then resume any time — even in a fresh
process — with `awaitTask(taskId)`, which polls to completion (and surfaces mid-task
input requests to an optional callback).

```d
auto r = client.callTool("deploy", args);   // sync or task — you needn't know
if (r.isTask)
{
    store.save(r.task.taskId);               // durable handle; survives a restart
    auto done = client.awaitTask(r.task.taskId);
}
else
    use(r);                                  // synchronous tool, nothing to resume
```

> **Not supported: the experimental 2025-11-25 tasks.** The `tasks` feature that
> shipped in the 2025-11-25 core specification (a top-level `tasks` capability,
> `tasks/list`, `tasks/result`, the per-tool `execution.taskSupport` field, and
> the per-request `task` parameter) was a stopgap the spec has since replaced with
> this extension. It is **intentionally not implemented** — those methods answer
> `-32601` and no `tasks` capability is advertised. Only the SEP-2663 extension
> above is supported, and only under the draft protocol version.

## Event-loop model

`McpClient` speaks vibe.d async I/O: call every `McpClient` method from inside the
vibe event loop — wrap your calls in a `runTask` under `runEventLoop()` (the
examples' shared scaffold does this for you). The same API (`initialize` /
`listTools` / `callTool` / `listResources` / `readResource` / `listPrompts` /
`getPrompt` / `subscribe` / `setLogLevel`, plus the auto-paginated list helpers and
`enableModern()`) works over every transport. `McpClient.http(url)` builds a client
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
keeping the **server 39/39** and **client 287/287** baseline honest.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup,
the build/test/lint commands, project conventions, and the PR flow.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). This aligns the SDK with the [Model Context Protocol project](https://github.com/modelcontextprotocol/modelcontextprotocol), which is licensed under Apache-2.0.
