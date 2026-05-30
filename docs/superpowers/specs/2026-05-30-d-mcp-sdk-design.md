# Design: `dlang-mcp-sdk` — production-grade D MCP SDK

**Date:** 2026-05-30
**Status:** Approved (design)

## Goals

- **Client + server**, both transports (stdio + Streamable HTTP).
- **All protocol versions**: `2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`, `draft`, with negotiation at `initialize`.
- **Passes the official conformance suite** (`@modelcontextprotocol/conformance`) for both server and client scenarios — this is the acceptance gate.
- **FastMCP-style UDA ergonomics**: `@tool` / `@resource` / `@resourceTemplate` / `@prompt` / `@param` with compile-time registration and auto JSON-Schema generation.
- **Batteries-included**: OAuth 2.1 (server validation + client flows), all utilities, SSE resumability.

## Decisions (locked)

- **Build fresh** in `/Users/peter/dlang-mcp-sdk` (existing `mcp.d` / `claude-mcp-dlang` used only as reference maps, not copied).
- **Runtime foundation: vibe-d** (`vibe-d:data` for JSON, `vibe-d:http` for HTTP/SSE/fibers).
- **Transports: stdio + modern Streamable HTTP** only. Protocol *semantics* negotiated for all versions; the deprecated 2024-11-05 two-endpoint HTTP+SSE wire transport is **out of scope**.
- **License: MIT.** Test framework: **`unit-threaded`**.

## Conformance harness facts (grounding)

- npm package `@modelcontextprotocol/conformance`, TypeScript/Node.
- **Server testing**: harness connects to a running server at an HTTP URL
  (`npx @modelcontextprotocol/conformance server --url http://localhost:PORT/mcp`).
- **Client testing**: harness launches a scenario server, appends its URL to the client
  command, and sets `MCP_CONFORMANCE_SCENARIO` / `MCP_CONFORMANCE_CONTEXT` env vars.
- Spec version selected via `--spec-version` (supports dated releases and `draft`).
- Results: timestamped dir with `checks.json` (pass/fail) + logs.

## Module layout (`source/mcp/`)

```
protocol/
  versions.d        ProtocolVersion enum, SUPPORTED list, negotiation
  jsonrpc.d         JSON-RPC 2.0: Request/Response/Notification/Error + batching
  types.d           all MCP message types (Tool, Resource, Prompt, Content, ...)
  capabilities.d    ClientCapabilities, ServerCapabilities
  errors.d          MCP/JSON-RPC error codes & typed exceptions
transport/
  transport.d       Transport interface (send / incoming stream / close)
  stdio.d           stdio transport (server + client)
  streamable_http.d Streamable HTTP server transport (vibe.d)
  http_client.d     Streamable HTTP client transport
  session.d         session-id mgmt, SSE event store / resumability
  inmemory.d        in-memory transport pair for integration tests
server/
  server.d          MCPServer: dispatch, lifecycle, capabilities
  registry.d        tool/resource/prompt registries
  context.d         RequestContext (progress, logging, cancellation, sampling, elicitation)
  handlers.d        handler signatures
client/
  client.d          MCPClient: initialize, calls, auto-pagination, notifications
api/
  attributes.d      @tool @resource @resourceTemplate @prompt @param @completion @requiredScopes
  reflection.d      compile-time registration from UDAs
  schema.d          D type -> JSON Schema generation
auth/
  types.d
  server.d          bearer validation, scope enforcement, WWW-Authenticate, PRM
  jwt.d             JWT verify (RS256/ES256), JWKS cache
  introspection.d   RFC 7662 token introspection
  client.d          OAuth2 client: discovery, DCR, PKCE, client-credentials, token store
util/
  progress.d  logging.d  pagination.d  cancellation.d  uri.d
package.d           curated public re-exports
```

Plus `examples/` (stdio_server, http_server, client, auth_server, fastmcp_style),
`conformance/` (server.d + client.d targets + run script), and `tests/`.

## Key components

### Protocol versioning
`enum ProtocolVersion { v2024_11_05, v2025_03_26, v2025_06_18, v2025_11_25, draft }`.
`initialize` negotiates the highest mutually-supported version. Type/capability shapes
and feature availability are gated on the negotiated version (e.g. elicitation arrived in
`2025-06-18`). Unknown future versions degrade to the latest known.

### Transport
Common `Transport` interface. stdio = newline-delimited JSON over stdin/stdout.
Streamable HTTP (vibe.d) = single `/mcp` endpoint: POST returns JSON or upgrades to SSE;
GET opens the SSE stream; `Mcp-Session-Id` header carries sessions; `Last-Event-ID` plus
an event store provide resumability. The in-memory transport pair drives fast integration
tests without sockets.

### Server
JSON-RPC dispatch + lifecycle (initialize / initialized / ping). Features: tools
(list/call), resources (list/read/templates/subscribe/updated), prompts (list/get),
completion (complete), logging (setLevel + notifications), pagination (opaque cursors),
progress, cancellation, and server->client **sampling / roots / elicitation**.

### Ergonomic UDA API (FastMCP-inspired)
```d
class Calc {
    @tool("add", "Add two numbers")
    int add(@param("a") int a, @param("b") int b) { return a + b; }
}
auto s = new MCPServer("calc", "1.0");
s.register(new Calc);     // compile-time reflection over UDAs
s.runStdio();             // or s.runHTTP(8080)
```
JSON Schema is auto-derived from parameter types: structs -> object schema, enums ->
string enum, `Nullable!T` -> optional, arrays -> array schema, etc. A handler may accept a
`Context` parameter for `ctx.reportProgress`, `ctx.info/debug/...`, `ctx.sample(...)`,
`ctx.elicit(...)`, and `ctx.cancelled`.

### Client
`initialize()` performs version negotiation. `listTools / callTool / listResources /
readResource / listPrompts / getPrompt / complete` with **auto-pagination**. User-provided
callbacks handle server->client sampling/roots/elicitation. Notification subscriptions for
resource updates, logging, and progress.

### Auth (OAuth 2.1)
*Server*: validate bearer tokens (JWT via JWKS, or RFC 7662 introspection), enforce scopes
via `@requiredScopes`, emit `401 + WWW-Authenticate` and Protected Resource Metadata.
*Client*: AS / PRM discovery, Dynamic Client Registration, PKCE authorization-code and
client-credentials flows, token storage and refresh.

## Error handling

Typed exceptions map to JSON-RPC codes (`-32700` parse, `-32600` invalid request,
`-32601` method not found, `-32602` invalid params, `-32603` internal, plus MCP-specific
codes). **Tool execution failures are returned as `isError` content per spec, not as
protocol errors** — a deliberate distinction and a common conformance pitfall.

## Testing strategy

TDD throughout (write the failing test first, per project conventions). `unit-threaded`,
with **one `unittest` block per test**. Layers:

- **Unit**: per-version type serialization round-trips, JSON-RPC batching, schema
  generation, version negotiation, registries, pagination cursors, auth (JWT /
  introspection).
- **Integration**: full client<->server flows over the in-memory transport pair.
- **Conformance** (acceptance gate): scripted runs of `@modelcontextprotocol/conformance`
  for server and client scenarios, per `--spec-version`.

`dfmt` + `dscanner` kept clean. Requires Node/`npx` available for conformance runs.

## Build & tooling

`dub.json`: library target + configurations (`unittest`, `conformance-server`,
`conformance-client`); examples as sub-packages. Dependencies: `vibe-d:data`,
`vibe-d:http`. Git initialized; commit after each change; README with install/usage.

## Build sequence

1. Skeleton: dub + git + dfmt/dscanner + `versions` / `jsonrpc` / `errors` (TDD).
2. `types` + `capabilities` (all versions) + schema generation.
3. In-memory transport + server core + lifecycle + **tools** -> first conformance green
   (initialize / tools).
4. resources + prompts + completion + logging + pagination + progress + cancellation.
5. stdio transport + client core.
6. Streamable HTTP transport + sessions + SSE resumability + HTTP client.
7. server->client: sampling, roots, elicitation.
8. UDA ergonomic layer + examples.
9. auth (server validation + client OAuth).
10. Full conformance pass (all versions) + README + production hardening.
