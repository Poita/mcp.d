# examples/elicitation — 2025-era blocking elicitation (dual-transport, typed APIs)

A self-contained dub package demonstrating **blocking elicitation** on the
released (2025-*) MCP protocol (issue #355). The server is one binary that runs
over **either** transport — newline-delimited JSON-RPC on **stdio** (the
default) or **Streamable HTTP** (`--http`) — and the bundled client is a
self-verifying e2e test that drives and asserts the same behavior over whichever
transport it connects on. It depends on the root `mcp` package via a path
dependency and does **not** modify the root `dub.json`.

## What it teaches

A tool often needs more input than its arguments carry. On the 2025 protocol the
server can pause mid-handler and ask the connected client for structured input
with a genuine server->client request:

```d
ElicitResult result = ctx.elicit!TripDetails("Please provide trip details for " ~ destination);
final switch (result.action) { /* accept / decline / cancel */ }
TripDetails details = result.contentAs!TripDetails; // decode the accepted form
```

`ctx.elicit!TripDetails(message)` **blocks** until the client's `onElicitation`
handler answers, then returns a typed `ElicitResult`. The `requestedSchema` is
derived wholesale from the `TripDetails` struct — the SEP-1034/1330 restricted
schema is a flat object of primitive fields, optionally with `enum`, `default`,
`minimum`/`maximum`. This example sends:

- `travelers` — `integer` with `minimum: 1`, `maximum: 9` (required),
- `cabin` — `string` `enum` `["economy","premium","business"]` with
  `default: "economy"`,
- `insurance` — `boolean` with `default: false`.

The handler branches on the user's decision (`accept` / `decline` / `cancel`)
and, on `accept`, applies the schema defaults for any field the user omitted.

### Typed-API adoption (#436 / #437 / #464 / #465 / #466 / #468 / #470)

This example uses the SDK's **typed elicitation APIs** rather than hand-built
Json, on both sides of the wire:

- the `requestedSchema` is **derived wholesale** from the flat struct
  `TripDetails` by `ctx.elicit!TripDetails(message)`: the object type, the
  `required` set and the `cabin` enum members come from reflection, while the
  rich facets (field titles, the `travelers` integer bounds, the `cabin` enum
  default, the `insurance` boolean default) are declared as field UDAs
  (`@title`/`@minimum`/`@maximum`/`@schemaDefault`, #465) that `jsonSchemaOf`
  now emits — so the server builds **no schema Json by hand** (SEP-1034/1330);
- `ctx.elicit!T` returns a typed `ElicitResult`; the handler branches on
  `.action` and, on `accept`, decodes the collected values with
  `result.contentAs!TripDetails` instead of hand-reading the `content` Json;
- `plan_trip` returns a `TripPlan` struct, so the SDK infers the output schema
  and emits `structuredContent` the client decodes with
  `result.structuredContentAs!TripPlan` (#464);
- the **client** spawns the stdio server with `McpClient.spawn([serverBinaryPath()])`
  + `scope(exit) client.close()` (#470) — no hand-rolled `ProcessPipes`
  plumbing — passes tool arguments as the typed `PlanArgs(destination)` struct
  (#468), and answers `accept` with `ElicitResult.accept(AcceptForm(3))` (#466).
  Installing `onElicitation` alone advertises form elicitation (the inbound gate
  honours `effectiveCapabilities()`, #463), so no raw capability flags are set.

The server is written in the SDK's ergonomic **UDA style**: `plan_trip` is an
annotated typed method on `TripApi`, wired up with a single `registerHandlers`
call. Its `destination` argument is marshalled from the inferred input schema and
`RequestContext ctx` is auto-injected (and omitted from the schema).

### Contrast with MRTR (`examples/mrtr`)

MRTR (SEP-2322) is the **stateless draft** input flow: there is no
server->client channel, so a tool that needs input ENDS the call with
`ToolResponse.inputRequired(...)` and the client resubmits a fresh `tools/call`
carrying the answers in `inputResponses` (plus an opaque `requestState`). Here,
on the 2025 released protocol, elicitation is a **single blocking** `tools/call`
with a real `elicitation/create` round-trip inside it — no resubmission, no
`requestState`. (The server->client blocking deadlock over Streamable HTTP was
fixed in #377; over stdio the reply is answered inline on the same channel,
#448/#449.)

## Files

- `dub.json` — package with `server` and `client` configurations.
- `server.d` — the `elicitation-server`; one binary, stdio (default) or HTTP.
- `client.d` — the `elicitation-client`; a self-verifying e2e test over either
  transport.

## How to run

### stdio (default)

The client spawns the server binary itself and talks to it over stdin/stdout, so
a single command runs the whole end-to-end test:

```sh
dub build -c server          # build the binary the client will spawn
dub run -c client            # spawns elicitation-server over stdio; exits 0 on OK
```

### Streamable HTTP

Start the server with `--http` (and an optional `--port`, default `9355`), then
point the client at its `/mcp` endpoint:

```sh
# terminal 1 — serve over HTTP on http://127.0.0.1:9355/mcp
dub run -c server -- --http --port 9355

# terminal 2 — run the self-verifying client against the HTTP endpoint
dub run -c client -- --http http://127.0.0.1:9355/mcp   # prints "OK: ..." and exits 0
```

The client's assertions are **transport-agnostic**: the same `run` body verifies
that the elicitation request carried the rich schema, that an `accept` (omitting
the optional fields) yields
`{status:"booked", travelers:3, cabin:"economy", insurance:false}`, that
`decline`/`cancel` map to `declined`/`cancelled`, and that a client advertising
no elicitation capability makes the call fail (the server refuses to send an
elicitation request to a client that did not declare the capability). On any
mismatch it prints what differed and exits **non-zero**.

## Auth (HTTP only)

This example does not enable auth. If you want to put it behind OAuth, do so on
the **HTTP** transport only: OAuth is an HTTP-layer concern (bearer tokens on the
`Authorization` header, the `WWW-Authenticate` challenge, and the protected-
resource / authorization-server metadata are all defined over HTTP). The stdio
transport has no HTTP request to carry those headers or to perform the browser
redirect an authorization-code flow needs, so auth is not applicable there — run
stdio locally as a trusted subprocess instead. See `examples/auth` for the HTTP
OAuth pattern.
