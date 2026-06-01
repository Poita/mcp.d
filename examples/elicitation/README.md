# examples/elicitation — 2025-era blocking elicitation (server + client e2e)

A self-contained dub package demonstrating **blocking elicitation** on the
released (2025-*) MCP protocol, over the **Streamable HTTP** transport
(issue #355). It depends on the root `mcp` package via a path dependency and
does **not** modify the root `dub.json`.

## What it teaches

A tool often needs more input than its arguments carry. On the 2025 protocol the
server can pause mid-handler and ask the connected client for structured input
with a genuine server->client request:

```d
auto raw = ctx.elicit("Please provide trip details for " ~ destination, schema);
auto result = ElicitResult.fromJson(raw);  // {action, content}
```

`ctx.elicit(message, requestedSchema)` **blocks** until the client's
`onElicitation` handler answers, then returns the client's `ElicitResult`. The
`requestedSchema` is the SEP-1034/1330 restricted schema — flat objects of
primitive fields, optionally with `enum`, `default`, `minimum`/`maximum`. This
example sends:

- `travelers` — `integer` with `minimum: 1`, `maximum: 9` (required),
- `cabin` — `string` `enum` `["economy","premium","business"]` with
  `default: "economy"`,
- `insurance` — `boolean` with `default: false`.

The handler branches on the user's decision (`accept` / `decline` / `cancel`)
and, on `accept`, applies the schema defaults for any field the user omitted.

The server is written in the SDK's ergonomic **UDA style**: `plan_trip` is an
annotated typed method on `TripApi`, wired up with a single `registerHandlers`
call. Its `destination` argument is marshalled from the inferred input schema,
`RequestContext ctx` is auto-injected (and omitted from the schema), and the
returned `TripPlan` struct becomes the tool's `structuredContent`.

### Contrast with MRTR (`examples/mrtr`)

MRTR (SEP-2322) is the **stateless draft** input flow: there is no
server->client channel, so a tool that needs input ENDS the call with
`ToolResponse.inputRequired(...)` and the client resubmits a fresh `tools/call`
carrying the answers in `inputResponses` (plus an opaque `requestState`). Here,
on the 2025 released protocol, elicitation is a **single blocking** `tools/call`
with a real `elicitation/create` round-trip inside it — no resubmission, no
`requestState`. (The server->client blocking deadlock over Streamable HTTP was
fixed in #377, so this completes.)

## Files

- `dub.json` — package with `server` and `client` configurations.
- `server.d` — the `elicitation-server`; serves Streamable HTTP on a fixed port.
- `client.d` — the `elicitation-client`; a self-verifying e2e test.

## How to run (two terminals)

```sh
# terminal 1 — start the server (serves http://127.0.0.1:9355/mcp)
dub run -c server

# terminal 2 — run the self-verifying client e2e
dub run -c client          # prints "OK: ..." and exits 0 on success
```

Pass a different URL as the client's first argument if you bound a custom
host/port: `dub run -c client -- http://127.0.0.1:9355/mcp`.

The client is the acceptance test: it asserts the elicitation request carried the
rich schema, that an `accept` (omitting the optional fields) yields
`{status:"booked", travelers:3, cabin:"economy", insurance:false}`, that
`decline`/`cancel` map to `declined`/`cancelled`, and that a client advertising
no elicitation capability makes the call fail (the server refuses to send an
elicitation request to a client that did not declare the capability). On any mismatch it prints what
differed and exits **non-zero**.
