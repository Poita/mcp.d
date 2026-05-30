# dlang-mcp-sdk

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

## Example: a server with the ergonomic UDA API

Write plain typed D methods and annotate them — the JSON Schema is derived from
the parameter types and the arguments are marshalled for you (FastMCP-style):

```d
import mcp;
import std.typecons : Nullable;

/// Each annotated method becomes an MCP feature. The input schema is generated
/// from the parameter types; `Nullable!T` parameters are optional.
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
    auto server = new MCPServer("my-server", "1.0.0");
    registerHandlers(server, new MyServer);   // reflects the UDAs at compile time
    runStreamableHttp(server, 3000);          // or: runStdio(server);
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
`server.registerTool(Tool, delegate)` / `registerResource` / `registerPrompt`
API is available too — `registerHandlers` is built on top of it.

A runnable version of this server (stdio + HTTP) lives in
[`examples/calculator`](examples/calculator/app.d):

```bash
dub run :calculator                 # stdio (for Claude Desktop)
dub run :calculator -- --http 3000  # Streamable HTTP on port 3000
```

## Running the conformance suite

```bash
dub build -c conformance-server
./conformance-server --port 3000 &
npx @modelcontextprotocol/conformance server --url http://127.0.0.1:3000/mcp
```

## Architecture

```
source/mcp/
  protocol/   versions  jsonrpc  errors  capabilities  types  draft
  transport/  stdio  streamable_http  sse_context   (both transports + SSE streaming)
  server/     server  context        (transport-agnostic dispatch + per-request Context)
  client/     client                 (MCPClient, auto-pagination, SSE + resumption)
  api/        attributes  schema  reflection   (@tool/@resource/@prompt UDA layer)
  auth/       oauth  client  jwt      (OAuth 2.1: PKCE, DCR, JWT assertions, token exchange)
```

`MCPServer` is a transport-agnostic JSON-RPC dispatch core (`handle` / `handleRaw`);
transports (stdio + Streamable HTTP) are thin drivers over it. All wire types serialize
through presence-aware `toJson`/`fromJson` so optional fields are omitted, not nulled.

See `docs/superpowers/specs` and `docs/superpowers/plans` for the design and staged plans.

## License

MIT — see [LICENSE](LICENSE).
