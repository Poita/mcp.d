# Tools example (server + client e2e)

A focused, self-contained example demonstrating **Tools** in the D MCP SDK
([mcp.d](https://github.com/Poita/mcp.d)) from both sides. It is its own dub
package with a path dependency on the root `mcp` library, so it never touches
the root `dub.json`.

## What it teaches

**Server side (`server.d`)** — declaring tools with the `@tool` reflection API:

- **Typed arguments** mapped into an inferred JSON Schema:
  - scalars (`double a, double b`),
  - an `enum` parameter (`Op`) → schema `enum` of its members,
  - an optional `Nullable!int round` → present in `properties` but **not** in
    `required`,
  - a `struct` parameter (`Vec2`) → an object sub-schema.
- **Inferred output schema + `structuredContent`** from a `struct` return
  (`CalcResult`); scalar returns are wrapped under a `result` key; `string`
  returns become plain text content with no `structuredContent`.
- **Behavioral marker UDAs** that populate `ToolAnnotations`:
  `@readOnly` → `readOnlyHint`, `@destructive` → `destructiveHint`,
  `@idempotent` → `idempotentHint`, and `@hintTitle("...")` → annotation title.
- **`@describe`** to document individual arguments.
- **`registerModule!(thisModule)(server)`** to register every module-level
  `@tool` free function in one call (no class instance required).

The server speaks MCP over **stdio** (`runStdio`) — the deployable shape.

**Client side (`client.d`)** — a **self-verifying end-to-end test**. It spawns
the built server binary, drives it over stdio, and asserts concrete expected
values:

- `tools/list` contains `calc`, `magnitude`, `greet`, `erase`;
- `calc`'s input schema exposes the enum members and keeps the optional `round`
  arg out of `required`; `magnitude`'s `v` arg is an object sub-schema;
- the marker UDAs surface as the right `ToolAnnotations` hints (incl. the
  `@hintTitle`);
- `calc(add, 3, 4)` returns `structuredContent` `{op: 0, result: 7}` (the enum
  field serializes as its ordinal);
- the optional `round` arg flows through (`mul(1/3, 1)` rounded to 2dp = 0.33);
- the scalar-returning `magnitude(3,4)` wraps its `5` under `result`;
- `greet("Ada")` returns the text `Hello, Ada!` with no `structuredContent`;
- calling an unknown tool raises an `McpException` with code
  `invalidParams` (-32602).

On success it prints `OK: ...` and exits `0`; on **any** failed assertion it
prints what differed and exits **non-zero**, so the example doubles as a CI
regression test.

## Running it

This is a stdio example: the client spawns the server, so running the client is
the whole demo. Build both configurations first (the client looks for the
`tools-server` binary next to its own executable), then run the client:

```sh
# from this directory (examples/tools)
dub build -c server      # produces ./tools-server
dub build -c client      # produces ./tools-client
dub run   -c client      # spawns the server and runs the e2e (exit 0 == pass)
```

Or run the built binary directly:

```sh
./tools-client; echo "exit=$?"
```

A non-zero exit code means a behavioral assertion failed.
