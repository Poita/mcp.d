# Tools example (server + client e2e), dual-transport

A focused, self-contained example demonstrating **Tools** in the D MCP SDK
([mcp.d](https://github.com/Poita/mcp.d)) from both sides. It is its own dub
package with a path dependency on the root `mcp` library, so it never touches
the root `dub.json`.

The single server binary speaks MCP over **either stdio or Streamable HTTP**,
selected at runtime, and the single client binary is a **self-verifying e2e
test** that drives the server over **both** transports with the same
transport-agnostic assertions.

Both sides build on the shared **examples/common** scaffold (`examples-common`): the server's transport selection is the scaffold's `runServerFromArgs`, and the client uses `runClient` + `connectFromArgs` (which spawns the sibling `tools-server` over stdio via `McpClient.spawnSibling`, or connects to `--http <url>`) plus the shared `check`/`checkEq` assertion helpers.

## What it teaches

**Server side (`server.d`)** — declaring tools with the `@tool` reflection API
(ergonomic UDA style; no low-level raw-Json registration):

- **Typed arguments** mapped into an inferred JSON Schema:
  - scalars (`double a, double b`),
  - an `enum` parameter (`Op`) → schema `enum` of its members,
  - an optional `Nullable!int round` → present in `properties` but **not** in
    `required`,
  - a `struct` parameter (`Vec2`) → an object sub-schema.
- **Inferred output schema + `structuredContent`** from a `struct` return
  (`CalcResult`); scalar returns are wrapped under a `result` key; `string`
  returns become plain text content with no `structuredContent`.
- **Typed `Content.make*` factories**: the `describe_doc` tool returns a typed
  `CallToolResult` whose blocks are built with `Content.makeText` and
  `Content.makeResourceLink` — no hand-built content Json.
- **Behavioral marker UDAs** that populate `ToolAnnotations`:
  `@readOnly` → `readOnlyHint`, `@destructive` → `destructiveHint`,
  `@idempotent` → `idempotentHint`, and `@hintTitle("...")` → annotation title.
- **`@describe`** to document individual arguments.
- **`registerModule!(thisModule)(server)`** to register every module-level
  `@tool` free function in one call (no class instance required).
- **Transport selection** via the shared `runServerFromArgs` scaffold helper:
  `--http` switches the same server from `runStdio` to `runStreamableHttp`
  (with `--port`/`--host`).

**Client side (`client.d`)** — a **self-verifying end-to-end test** that works
over either transport. It asserts concrete expected values:

- `tools/list` contains `calc`, `magnitude`, `greet`, `erase`, `describe_doc`;
- `calc`'s input schema exposes the enum members and keeps the optional `round`
  arg out of `required`; `magnitude`'s `v` arg is an object sub-schema;
- the marker UDAs surface as the right `ToolAnnotations` hints (incl. the
  `@hintTitle`), read via the ergonomic `tool.toolAnnotations()` accessor;
- `calc(add, 3, 4)` returns `structuredContent` `{op: 0, result: 7}` (the enum
  field serializes as its ordinal);
- the optional `round` arg flows through (`mul(1/3, 1)` rounded to 2dp = 0.33);
- the scalar-returning `magnitude(3,4)` wraps its `5` under `result`;
- `greet("Ada")` returns the text `Hello, Ada!` with no `structuredContent`;
- `describe_doc("42")` returns two content blocks — a `text` block and a
  `resource_link` block to `doc://42`;
- calling an unknown tool raises an `McpException` with code
  `invalidParams` (-32602).

The client exercises the SDK's typed client ergonomics rather than hand-built
Json wherever the call is static: it passes typed parameter structs to
`client.callTool(name, T args)` (e.g. `callTool("calc", CalcArgs("add", 3, 4))`)
and decodes structured output with `result.structuredContentAs!T` into small
result structs (`CalcOutput`, `ScalarOutput`); a dynamic Json arguments object is
kept only for the genuinely optional `round` argument.

On success it prints `OK: ...` and exits `0`; on **any** failed assertion it
prints what differed and exits **non-zero**, so the example doubles as a CI
regression test over every supported transport.

## Running it

Build both configurations first (over stdio the client spawns the sibling
`tools-server` binary next to its own executable via `McpClient.spawnSibling`):

```sh
# from this directory (examples/tools)
dub build -c server      # produces ./tools-server
dub build -c client      # produces ./tools-client
```

### Over stdio (default)

The client spawns the server, so running the client is the whole demo:

```sh
dub run -c client        # spawns ./tools-server and runs the e2e (exit 0 == pass)
```

### Over Streamable HTTP

Start the server with `--http` in one terminal, then point the client at its
`/mcp` endpoint in another:

```sh
# terminal 1 — start the HTTP server (default port 8530)
dub run -c server -- --http --port 8530

# terminal 2 — run the same e2e against it
dub run -c client -- --http http://127.0.0.1:8530/mcp
```

A non-zero exit code from the client means a behavioral assertion failed.

## A note on auth

This example does not enable authentication. OAuth 2.1 Resource Server
enforcement in this SDK is an **HTTP-only** feature: it relies on the
`Authorization: Bearer` request header and the RFC 9728 Protected Resource
Metadata document served over HTTP (`StreamableHttpOptions.auth`). The stdio
transport has no request headers and no HTTP surface, so there is nowhere to
carry or challenge a bearer token. If you need auth, run the HTTP transport and
configure `StreamableHttpOptions.auth` (see the dedicated auth example).
