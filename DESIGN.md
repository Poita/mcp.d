# Design decisions

A running log of deliberate, load-bearing API decisions for the D MCP SDK and
the rationale behind them. Each entry records a decision that should not be
relitigated without new information.

## Client API is untyped on the request side

**Decision.** The `McpClient` request verbs (`callTool`, `getPrompt`, …) accept
their arguments as `vibe.data.json.Json`, not as statically-typed parameter
structs. There is intentionally **no** typed-argument overload such as
`callTool(T)(string name, T args)`. This decision is final: do not revisit it by
re-adding a typed request surface.

**Rationale.**

- An MCP client is a conduit for LLM-produced JSON. The real flow is: the host
  calls `listTools`, hands the returned schemas to a model, and receives raw JSON
  arguments back from the model — which it forwards verbatim. The arguments are
  never known to the host at compile time, so a statically-typed argument struct
  only ever serves *tests*, not the production call path it purports to ergonomize.
- The removed typed overload silently **mis-serialized enum fields**. vibe's
  default serialization writes an enum numerically (by ordinal), while the
  server's reflected input schemas declare string enums by member *name*. A typed
  `callTool("calc", CalcArgs(Op.add, …))` would therefore send `"op": 0` against a
  schema that requires `"op": "add"` — a class of bug the typed surface actively
  invites and hides. Building the `arguments` JSON explicitly makes the wire shape
  the thing the caller sees and controls.

**Retained.** Result-side typed *decoding* is intentionally kept and encouraged:
`CallToolResult.structuredContentAs!T`, typed result structs, etc. The asymmetry
is deliberate — a *result* has a known shape the SDK reflected, so decoding it
into a struct is sound; a *request* argument does not.
