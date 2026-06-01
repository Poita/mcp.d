# MRTR — Multi Round-Trip Requests (SEP-2322)

A self-contained example of the **stateless draft input flow** in the D MCP SDK,
running and e2e-tested over **both stdio and Streamable HTTP**. It is its own dub
package (a `path` dependency on the root `mcp`), so it builds and runs
independently of the SDK's root build.

## What MRTR is (and what it teaches)

On the 2025-era protocols a server gathers extra input by opening a
*server→client* request (`elicitation/create`, `sampling/createMessage`,
`roots/list`) and blocking on the answer. The **draft** revision is stateless and
has **no server→client channel**, so it uses **Multi Round-Trip Requests**
instead:

1. A `tools/call` handler that needs more input does **not** block. It ends the
   call by returning `ToolResponse.inputRequired([...])` — a set of
   `InputRequest`s (each one a would-be `elicitation` / `sampling` / `roots`
   request) plus an optional opaque `requestState` blob the server owns.
2. The client gathers an answer for each request (via its `onElicitation` /
   `onSampling` / `onListRoots` handlers) and **resubmits a fresh `tools/call`**
   carrying the answers in `params.inputResponses` and echoing `requestState`
   back verbatim.
3. The handler runs again, now reading `ctx.inputResponses()` and
   `ctx.requestState()`, and returns the final `CallToolResult`.

There is no suspension and no per-session state on the server — every round is a
plain, independent request. Contrast this with the blocking elicitation example,
which uses `ctx.elicit(...)` on a stateful connection.

### The demo tool

`book_meeting {topic}` needs two pieces of input before it can confirm a booking:

- a **date** (an `elicitation` `InputRequest`), and
- a one-line **agenda** (a `sampling` `InputRequest`).

Round 1 returns both requests and stashes the topic into `requestState`. Round 2
reads the answers + the echoed topic and returns the confirmation (text +
structured content).

### Typed APIs exercised (SEP-2322 / #436 / #437)

The server is UDA style (`@tool` + `registerHandlers`) and builds **no hand-built
MRTR `Json`** — it uses the typed builders and decoders throughout:

- **`InputRequest.elicitation!MeetingDate(id, message)`** — derives the
  elicitation `requestedSchema` from the flat `MeetingDate` struct via
  `jsonSchemaOf!T` (no hand-built schema `Json`).
- **`InputRequest.sampling(id, CreateMessageRequest)`** — builds the sampling
  request from a typed `CreateMessageRequest` (typed `SamplingMessage` +
  `Content.makeText`), not a hand-built params object.
- **`ToolResponse.inputRequired(reqs, RequestState)`** + **`ctx.requestStateAs!RequestState`**
  — the opaque `requestState` is a typed `RequestState` struct (serialized on the
  way out, decoded on the retry) rather than a `"topic="`-prefixed string parsed
  by hand.
- **`ctx.isResubmit()` / `ctx.hasInputResponse(id)`** — detect the resubmit round
  instead of open-coding `(id in ctx.inputResponses())` membership checks.
- **`ctx.inputResponseAs!ElicitResult(id)`** and
  **`ctx.inputResponseAs!CreateMessageResult(id)`** — decode the round-2 answers
  as typed results; the date is read via `ElicitResult.contentAs!MeetingDate`
  after branching on `.action`.
- **`Content.makeText`** for the final content and a typed **`Booking`** struct
  serialized into `structuredContent`.

The **client** likewise adopts the typed/ergonomic SDK APIs on every path that
has a clean one — no hand-built `Json` on the args, handler replies, or the
structured result:

- **typed `callTool("book_meeting", BookMeetingArgs("Q3 roadmap"))`** (#468) —
  the wire `{topic}` object is serialized from a struct.
- **typed inbound `InputRequest` readers** (#503) — the surfaced requests are read
  via `req.elicitationMessage()` / `req.requestedSchema()` (the elicitation) and
  `req.asSampling()` (the sampling, decoded back into a typed
  `CreateMessageRequest`) instead of raw `req.params[...]` indexing.
- **`ElicitResult.accept(MeetingDate("2026-06-15"))`** (#466) and
  **`CreateMessageResult.text("mock-llm", "...")`** (#467) — the mock
  `onElicitation` / `onSampling` replies are built from the typed convenience
  constructors instead of assembling the result structs field by field.
- **`CallToolResult.structuredContentAs!Booking`** (#464) — the structured
  result is decoded in one shot into a typed `Booking` struct, replacing the
  field-by-field raw-`Json` reads.

Installing `onElicitation` / `onSampling` alone now auto-advertises the matching
capabilities (`effectiveCapabilities`), so no raw capability-flag setting is
needed.

### Shared `examples/common` scaffold

Both sides use the shared `examples_common` scaffold (`dub` package
`examples-common`, a `path` dependency on `../common`) for their boilerplate:

- the server's transport selection is **`runServerFromArgs(server, args, 8765)`**
  (`--http` / `--port` / `--host` -> Streamable HTTP, else stdio);
- the client's transport selection is **`connectFromArgs(args, "mrtr-server")`**
  (`--http <url>` -> `McpClient.http`, else `McpClient.spawnSibling("mrtr-server")`
  over stdio), driven inside **`runClient(scenario)`** which runs the vibe event
  loop uniformly and maps any thrown assertion to a non-zero exit;
- the e2e assertions use the scaffold's shared **`check`** helper.

Other client APIs: `enableDraft`, `discover`, `listTools`, `callTool` (which
transparently drives the MRTR loop), `CallToolResult.isInputRequired` /
`inputRequests` / `requestState`.

## Running it — BOTH transports

One server binary serves either transport; the same client binary drives either.

```sh
# build both sides
dub build -c server
dub build -c client
```

### stdio (default)

The client spawns the built `mrtr-server` binary (with no `--http`) and speaks
newline-delimited JSON-RPC over the pipe — no port, no second terminal:

```sh
dub run -c client            # spawns ./mrtr-server, runs the e2e; exits 0 on OK
```

### Streamable HTTP

Start the server with `--http` (binds `127.0.0.1:8765/mcp` by default), then run
the client against its URL:

```sh
# terminal 1: start the HTTP server
dub run -c server -- --http --port 8765

# terminal 2: run the client against it
dub run -c client -- --http http://127.0.0.1:8765/mcp ; echo "exit=$?"
```

Or in one shell:

```sh
dub build -c server && dub build -c client
./mrtr-server --http --port 8765 &
sleep 1
./mrtr-client --http http://127.0.0.1:8765/mcp ; echo "exit=$?"
kill %1
```

## Auth (HTTP only)

This example does not enable auth, but note that **OAuth-style authorization is an
HTTP-only concern in MCP**: it rides on HTTP request headers / the
`WWW-Authenticate` 401 challenge of the Streamable HTTP transport. The stdio
transport has no such channel — a stdio server trusts its parent process — so
there is nothing to authenticate over stdio. If you add auth to a server like
this, gate it behind `--http`.

## The client is a self-verifying e2e test (over every transport)

`client.d` asserts concrete expected values and **exits non-zero on any
mismatch**, so CI can run it as an end-to-end regression test over both stdio and
HTTP with the SAME assertions:

- the first `book_meeting` call (no handlers) surfaces the raw
  `InputRequiredResult`; the client asserts the two `InputRequest` ids/types, the
  elicitation message, the `requestedSchema` **derived from the server struct**
  (a `date` property), the sampling `maxTokens`, and the opaque `requestState`
  (`topic=Q3 roadmap`);
- after installing mock `onElicitation` (returns `date=2026-06-15`) and
  `onSampling` (returns the agenda text), the second call drives the MRTR loop to
  completion; the client asserts the final text, the structured content
  (`topic`/`date`/`agenda`), and that the server completed in `rounds == 2`.

On success it prints `OK: ...` and exits 0.
