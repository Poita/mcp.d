# MRTR — Multi Round-Trip Requests (SEP-2322)

A self-contained example of the **stateless draft input flow** in the D MCP SDK.
It is its own dub package (a `path` dependency on the root `mcp`), so it builds
and runs independently of the SDK's root build.

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

### APIs exercised

- Server: `McpServer.registerDynamicTool(Tool, MrtrToolHandler)`,
  `ToolResponse.inputRequired(requests, requestState)`,
  `ToolResponse.complete(...)`, `RequestContext.inputResponses()`,
  `RequestContext.requestState()`, `runStreamableHttp`.
- Client: `McpClient.http`, `enableDraft`, `discover`, `listTools`, `callTool`
  (which transparently drives the MRTR loop), `onElicitation`, `onSampling`,
  `CallToolResult.isInputRequired` / `inputRequests` / `requestState`.

## Running it (Streamable HTTP — two terminals)

The transport is HTTP, so the server runs as its own process and the client
connects to its URL.

```sh
# build both sides
dub build -c server
dub build -c client

# terminal 1: start the server (binds 127.0.0.1:8765/mcp)
./mrtr-server --port 8765

# terminal 2: run the client against it
./mrtr-client http://127.0.0.1:8765/mcp
```

Or in one shell:

```sh
dub build -c server && dub build -c client
./mrtr-server --port 8765 &
sleep 1
./mrtr-client http://127.0.0.1:8765/mcp ; echo "exit=$?"
kill %1
```

## The client is a self-verifying e2e test

`client.d` asserts concrete expected values and **exits non-zero on any
mismatch**, so CI can run it as an end-to-end regression test:

- the first `book_meeting` call (no handlers) surfaces the raw
  `InputRequiredResult`; the client asserts the two `InputRequest` ids/types, the
  elicitation message, and the opaque `requestState` (`topic=Q3 roadmap`);
- after installing mock `onElicitation` (returns `date=2026-06-15`) and
  `onSampling` (returns the agenda text), the second call drives the MRTR loop to
  completion; the client asserts the final text, the structured content
  (`topic`/`date`/`agenda`), and that the server completed in `rounds == 2`.

On success it prints `OK: ...` and exits 0.
