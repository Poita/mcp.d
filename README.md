# dlang-mcp-sdk

[![CI](https://github.com/Poita/mcp.d/actions/workflows/ci.yml/badge.svg)](https://github.com/Poita/mcp.d/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Poita/mcp.d/branch/main/graph/badge.svg)](https://codecov.io/gh/Poita/mcp.d)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A production-grade [Model Context Protocol](https://modelcontextprotocol.io) (MCP) SDK for
the D programming language — client and server, built on [vibe-d](https://vibed.org).

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

The core invariant: **a stateless server stores nothing across calls, and
`McpServer` holds no mutable per-connection state.** Per-connection state lives
in a `ConnectionState` object (`mcp.server.connection`) — protocol version,
client capabilities, log level, resource subscriptions, and the in-flight
cancellation registry. In stateful mode there is exactly one `ConnectionState`
per session, owned by the transport keyed by `Mcp-Session-Id`. In stateless mode
the transport builds a transient `ConnectionState` per request and discards it,
so two concurrent peers sharing one `McpServer` cannot leak version, capability,
or cancellation state into one another (issue #550).

### The three effective modes

| | Resolution of per-connection state | Notes |
|---|---|---|
| **Modern stateless** (stateless + request >= draft) | Per-request `_meta` (protocolVersion + clientCapabilities + logLevel) | No `initialize` (uses `server/discover`); input via MRTR; subscriptions ride the open stream; **no** blocking server->client elicitation/sampling |
| **Legacy stateless** (stateless + request < draft) | `MCP-Protocol-Version` header (default `2025-03-26`; stdio assumes `2025-11-25`); client capabilities **unknown** (assumed none) | `initialize`/`notifications/initialized` are no-ops (no session id minted); a `tools/call` may be the first request with no prior `initialize`; correlation features are forbidden |
| **Stateful** (opt-in, pre-draft only) | `ConnectionState` resolved by `Mcp-Session-Id`, created at `initialize` | The draft is **excluded** from negotiation (clamped down to `<= 2025-11-25`); `server/discover` is not served; DELETE terminates the session |

### Feature-gating matrix

| Feature | Modern stateless | Legacy stateless | Stateful |
|---|---|---|---|
| `initialize` handshake | n/a (`server/discover`) | no-op (no session id) | mints `Mcp-Session-Id` |
| Per-request `_meta` version/caps | yes | n/a (header + empty caps) | n/a (session-negotiated) |
| GET SSE stream | listen on open stream | forbidden (error) | yes |
| `resources/subscribe` | n/a (`subscriptions/listen`) | forbidden (error) | yes |
| Blocking server->client (elicit/sample) | forbidden (MRTR instead) | forbidden (error) | yes |
| `logging/setLevel` | n/a (per-request `_meta`) | per-request / n/a | yes (session-scoped) |
| Session id minted | never | never | yes |

The Streamable HTTP transport derives session minting purely from
`server.mode` (`ServerMode.stateful` => mint and require `Mcp-Session-Id`;
`ServerMode.stateless` => never). There is no separate `enableSessions` option.

## Example: a server with the ergonomic UDA API

Write plain typed D methods and annotate them — both the **input schema** (from
the parameter types) and the **output schema** (from the return type) are derived
automatically, and arguments/results are marshalled for you (FastMCP-style):

```d
import mcp;
import std.typecons : Nullable;

/// Each annotated method becomes an MCP feature. The `inputSchema` is generated
/// from the parameter types (`Nullable!T` params are optional); the `outputSchema`
/// is generated from the return type (a struct → its object schema; a scalar/
/// array → wrapped under `result`; a plain `string` → unstructured text content).
final class MyServer
{
    @tool("add", "Add two integers")
    long add(long a, long b) @safe
    {
        return a + b;
    }

    @tool("greet", "Greet someone, optionally loudly")
    string greet(string name, Nullable!bool loud) @safe
    {
        auto msg = "Hello, " ~ name ~ "!";
        return (!loud.isNull && loud.get) ? msg ~ "!!!" : msg;
    }

    @resource("file:///readme", "README", "text/plain")
    string readme() @safe
    {
        return "Hello!";
    }

    @prompt("greet_prompt", "Greeting prompt")
    string greetPrompt(string topic) @safe
    {
        return "Say hello about " ~ topic;
    }
}

void main()
{
    auto server = new McpServer("my-server", "1.0.0");
    registerHandlers(server, new MyServer);   // reflects the UDAs at compile time
    runStreamableHttp(server, 3000);          // or: runStdio(server);
}
```

Prefer decorating **module-level free functions** (FastMCP-style) instead of a
class? Use `registerModule` — it reflects every annotated free function in a
module and registers it. (A `RequestContext` must be an explicit parameter, since
free functions have no `this`.)

```d
import mcp;

@tool("add", "Add two integers")
long add(long a, long b) @safe { return a + b; }

@resource("file:///readme", "README", "text/plain")
string readme() @safe { return "Hello!"; }

@prompt("greet_prompt", "Greeting prompt")
string greetPrompt(string topic) @safe { return "Say hello about " ~ topic; }

void main()
{
    auto server = new McpServer("my-server", "1.0.0");
    registerModule!(__traits(parent, add))(server);  // or registerModule!(my.module)(server)
    // registerModules!(modA, modB)(server);          // variadic convenience
    runStdio(server);
}
```

A tool/prompt handler may also take a `RequestContext` parameter to report
progress, log, or request sampling/elicitation from the client:

```d
@tool("crunch", "Process items, reporting progress")
string crunch(int count, RequestContext ctx) @safe
{
    foreach (i; 0 .. count)
        ctx.reportProgress(i + 1, nullable(cast(double) count));
    return "done";
}
```

Prefer dynamic registration (e.g. tools known only at runtime)? The lower-level
`server.registerDynamicTool(Tool, delegate)` / `registerResource` /
`registerDynamicPrompt` API is the explicit escape hatch for runtime-defined
tools/prompts whose schema has no compile-time D type — the handler receives the
raw `Json` arguments. `registerHandlers` is built on top of it.

### Protecting an HTTP server (OAuth 2.1 Resource Server)

Set a `ResourceServerConfig` on `StreamableHttpOptions.auth` to turn the
Streamable HTTP transport into an OAuth 2.1 protected resource (RFC 6750 / 8707 /
9728). Every request must then present a valid `Authorization: Bearer` token; the
transport validates it (and its RFC 8707 audience), returns `401` with a
`WWW-Authenticate: Bearer` header pointing at the metadata document on failure,
`403 insufficient_scope` when a required scope is missing, and serves the RFC 9728
Protected Resource Metadata at `/.well-known/oauth-protected-resource`. The
validated token is available to handlers via `ctx.auth` (a `TokenInfo`).

```d
StreamableHttpOptions opts;
opts.auth.resource = "https://mcp.example.com/mcp";
opts.auth.authorizationServers = ["https://auth.example.com"];
opts.auth.scopesSupported = ["mcp:read", "mcp:write"];
opts.auth.requiredScope = "mcp:read";          // optional scope gate
opts.auth.validator = (string token) @safe {   // your verification (e.g. JWT)
    TokenInfo ti;
    ti.valid = verify(token);                   // returns false -> 401
    ti.subject = "...";
    ti.scopes = ["mcp:read"];
    ti.audience = ["https://mcp.example.com/mcp"];
    return ti;
};
runStreamableHttp(server, 3000, opts);
```

#### Identity-provider presets

Rather than hand-wiring each IdP's issuer / JWKS URI / endpoints, use the
turnkey presets in `mcp.auth.providers`. Each is a one-liner over `jwtVerifier`
(#179) or `OAuthProxy` (#183).

**JWT/JWKS providers** return a ready `ResourceServerConfig` (issuer + JWKS URI +
audience pinned):

```d
opts.auth = entraId("<tenant-id>", "api://my-mcp-server", ["mcp.read"]);
opts.auth = auth0("my-tenant.us.auth0.com", "https://api.example.com");
opts.auth = workosAuthKit("https://your-app.authkit.app", "client-id");
opts.auth = descope("<project-id>", "my-audience");
opts.auth = scalekit("https://your-env.scalekit.dev", "audience");
```

| Preset | Issuer | JWKS URI |
| --- | --- | --- |
| `entraId(tenant, …)` | `https://login.microsoftonline.com/{tenant}/v2.0` | `…/discovery/v2.0/keys` |
| `auth0(domain, …)` | `https://{domain}/` | `https://{domain}/.well-known/jwks.json` |
| `workosAuthKit(issuer, …)` | the AuthKit domain | `{issuer}/oauth2/jwks` |
| `descope(projectId, …)` | `https://api.descope.com/{projectId}` | `…/.well-known/jwks.json` |
| `scalekit(envUrl, …)` | the environment URL | `{envUrl}/keys` |

**Non-DCR / opaque-token providers** (GitHub, Google) return an
`OAuthProxyConfig` you finish with your proxy `baseUrl`/`resource` and a
`tokenVerifier`, then mount via an `OAuthProxy`:

```d
auto cfg = github("<client-id>", "<client-secret>", ["read:user"]);
cfg.baseUrl = "https://mcp.example.com";
cfg.resource = "https://mcp.example.com/mcp";
cfg.tokenVerifier = (string t) @safe { /* map GitHub /user -> TokenInfo */ };
auto proxy = new OAuthProxy(cfg);   // publishes DCR + AS metadata to clients

auto g = google("<client-id>", "<client-secret>", ["openid", "email"]);
```

`github` pins `https://github.com/login/oauth/{authorize,access_token}`; `google`
pins `https://accounts.google.com/o/oauth2/v2/auth` + `https://oauth2.googleapis.com/token`.

A runnable version of this server (stdio + HTTP) lives in
[`examples/calculator`](examples/calculator/app.d):

```bash
dub run :calculator                 # stdio (for Claude Desktop)
dub run :calculator -- --http 3000  # Streamable HTTP on port 3000
```

## Example: a client calling that server

With the calculator server running over HTTP (`dub run :calculator -- --http 3000`),
a client can connect and call the `add` tool:

```d
import mcp;
import std.stdio : writeln;
import vibe.core.core : runTask, runEventLoop, exitEventLoop;
import vibe.data.json : Json;

void main()
{
    // McpClient uses vibe.d async I/O, so drive it from a task on the event loop.
    runTask(() nothrow {
        scope (exit) exitEventLoop();
        try
        {
            auto client = McpClient.http("http://127.0.0.1:3000/mcp");
            client.initialize();

            auto result = client.callTool("add", Json(["a": Json(2), "b": Json(40)]));
            writeln(result.content[0].text);                       // text view: "42"
            writeln(result.structuredContent["result"].get!long);  // structured: 42
        }
        catch (Exception e)
        {
            // handle connection / tool errors
        }
    });
    runEventLoop();
}
```

`McpClient` also offers `listTools` / `listResources` / `listResourceTemplates` /
`listPrompts` (auto-paginated), `readResource`, `getPrompt`, `setBearerToken` for OAuth,
and `enableDraft()` for the stateless draft protocol.

The auto-paginated list helpers return their result object (`ListToolsResult`,
`ListResourcesResult`, `ListResourceTemplatesResult`, `ListPromptsResult`) with every
page's items aggregated into the items field (`.tools`, `.resources`,
`.resourceTemplates`, `.prompts`) and `nextCursor` drained to null. Each result —
along with `readResource`'s `ReadResourceResult` — also exposes the draft
`CacheableResult` freshness hint as `.cache` (a `Nullable!CacheHint` with `ttlMs` and
`cacheScope`), populated from the first page when the server sends one. On the server,
supply the hint per result: pass a `CacheHint` to `registerResource` /
`registerResourceTemplate`, or call `setListCacheHint("tools/list", CacheHint(...))`
for a `*/list` method (hints are draft-gated and never alter 2025-11-25 output).

`McpClient` is transport-agnostic: it speaks pure JSON-RPC over a
`ClientTransport`. `McpClient.http(url)` builds one over Streamable HTTP;
`McpClient.stdio(readLine, writeLine)` and `McpClient.spawn(command)` build one
over stdio (see below). You can also construct `new McpClient(transport)` with a
custom `ClientTransport` directly.

### Connecting over stdio (launching a server as a subprocess)

To act as an MCP host over the **stdio** transport — launching the server as a
child process and speaking newline-delimited JSON-RPC over its stdin/stdout —
use `McpClient.spawn`:

```d
import mcp;

void main()
{
    auto client = McpClient.spawn(["dub", "run", ":calculator"]);
    scope (exit) client.close();   // close child's stdin and wait for exit

    client.initialize();

    auto tools = client.listTools().tools;
    auto result = client.callTool("add", Json(["a": Json(2), "b": Json(40)]));
    // ...
}
```

Over stdio this synchronous style is fully supported: there is no event loop and
no background tasks, yet the client still answers server-initiated requests
(`ping`, `sampling/createMessage`, `elicitation/create`, `roots/list`) that arrive
while one of your calls is in flight — the reply is written inline to the server's
stdin from the same read loop. Wire your `onSampling` / `onElicitation` /
`onListRoots` handlers before the first call and they are invoked synchronously.

### The event-loop model

`McpClient` speaks vibe.d async I/O, and there is one rule: **call every
`McpClient` method from inside the vibe event loop.** Over HTTP that is required —
the reply to a server→client request travels on a separate HTTP request and is
sent from a background task, which only runs while `runEventLoop()` is pumping (see
the HTTP client example above, which wraps its calls in `runTask` /
`runEventLoop`). Over stdio the requirement is relaxed: the read loop is the only
channel, so replies are sent inline and the synchronous `spawn` example above needs
no event loop. If you prefer one uniform model, drive the stdio client from a
`runTask` under `runEventLoop()` exactly like the HTTP example — both work.

The same `McpClient` API (`initialize` / `listTools` / `callTool` /
`listResources` / `readResource` / `listPrompts` / `getPrompt` / `subscribe` /
`setLogLevel`) works over every transport. For a custom byte channel, use
`McpClient.stdio(readLine, writeLine)` with your own `readLine`/`writeLine`
pair; `McpClient.spawn` is the convenience wrapper around
`std.process.pipeProcess`. The server side is `runStdio(server)` /
`serveStdio` in `mcp.transport.stdio`.

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
