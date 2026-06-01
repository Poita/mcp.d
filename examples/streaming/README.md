# examples/streaming — Progress / logging / cancellation + typed elicitation & sampling

A self-contained example (its own dub package) showing how the **server** emits
and the **client** consumes MCP's in-flight channels, plus the **typed**
server→client round-trip APIs — over **BOTH transports**: stdio and Streamable
HTTP. One server binary serves either transport; one client verifies both.

- **Progress** — `ctx.reportProgress(done, total, message)` →
  `notifications/progress`, observed via `McpClient.onProgress`.
- **Logging** — `ctx.log(level, data, logger)` → `notifications/message`,
  observed via `McpClient.onLogMessage`.
- **Cancellation** — a long-running handler polls `ctx.isCancelled` and stops
  early; on Streamable HTTP the cancellation signal is the client closing its
  response stream (basic/utilities/cancellation §Transport-Specific
  Cancellation), which the handler also detects as a failed send.
- **Typed elicitation** — `ctx.elicit!Confirm(message)` derives the
  `requestedSchema` from a flat struct via `jsonSchemaOf!T` and returns a typed
  `ElicitResult` (branch on `.action`, decode with `.contentAs!Confirm`) — no
  hand-built schema Json (#436).
- **Typed sampling** — `ctx.sample(CreateMessageRequest)` builds the request
  from typed `SamplingMessage` + `Content.makeText` and parses the typed
  `CreateMessageResult` reply (#437).

The `client.d` is **not just a demo — it is a self-verifying end-to-end test**.
Every observation is asserted against the value the server promised; on any
mismatch it prints what differed and exits non-zero. On success it prints a
one-line `OK [stdio]:` / `OK [http]:` summary and exits 0.

## What it teaches

The server (`server.d`, ergonomic UDA style — `@tool` + `registerHandlers`)
exposes three tools:

- `countdown(steps, delayMs)` — walks `steps` units of work. Each step sleeps,
  reports progress `i/steps`, and logs an `info` line tagged with the logger
  name `countdown`. It honors cancellation and returns structured output
  `{ completed, total, cancelled }` (inferred from the struct return).
- `summarize(text)` — mid-handler it **blocks** on the typed server→client
  round-trip: a typed elicitation (schema derived from the flat `Confirm`
  struct) confirms the tone, then typed sampling produces a summary. Returns
  `{ status, tone, model, summary }`. These round-trips work over **both**
  transports.
- `cancel_stats()` — returns `{ cancelled }`, the number of `countdown` runs
  that observed a cancellation. Used by the client to confirm, out of band, that
  a mid-flight cancellation was actually honored.

The client (`client.d`) verifies, in order:

1. **List + progress + logging** (transport-agnostic): `listTools()` contains
   `countdown` / `summarize` / `cancel_stats`; a `countdown` call carrying a
   `progressToken` streams exactly N progress notifications (monotonically
   increasing, echoing the token, last == total) and N `info` log messages from
   the `countdown` logger before the final result.
2. **Typed elicitation + sampling** (transport-agnostic): the client's mocked
   `onElicitation` accepts with concrete values and its mocked `onSampling`
   returns a concrete model + text; the structured result echoes them exactly.
3. **Error code** (transport-agnostic): an unknown tool raises `McpException`
   with `invalidParams` (-32602).
4. **Cancellation** (HTTP only): a long `countdown` is started on its own task;
   once the first progress proves it is in flight, the client tears down its
   stream and a fresh `cancel_stats` read confirms the counter increased.

## Run it

### stdio (default)

The client spawns the server binary itself and talks to it over stdin/stdout —
a single command, no ports.

```sh
dub build -c server && dub build -c client
dub run -c client            # spawns ./streaming-server (stdio); exits 0 on OK
```

### Streamable HTTP

Start the server with `--http` in one terminal, then point the client at its
URL in another.

```sh
# terminal 1 — start the HTTP server (serves http://127.0.0.1:9357/mcp)
dub run -c server -- --http --port 9357

# terminal 2 — run the self-verifying client against that URL
dub run -c client -- --http http://127.0.0.1:9357/mcp
```

Override the bind address/port if needed:

```sh
dub run -c server -- --http --port 9999 --host 127.0.0.1
dub run -c client -- --http http://127.0.0.1:9999/mcp
```

### One-shot (what CI does for HTTP)

```sh
dub build -c server && dub build -c client
./streaming-server --http --port 9357 &   # background
SERVER=$!
sleep 3
./streaming-client --http http://127.0.0.1:9357/mcp   # the e2e; check the exit code
RC=$?
kill $SERVER
exit $RC
```

A non-zero client exit code means a behavioral regression — the client prints
`FAIL: <what differed>`.

## Notes

- **Why this client only runs cancellation over HTTP.** Over Streamable HTTP the
  cancellation signal is the client dropping its per-request SSE response stream
  (a disconnect). Over stdio the signal is a `notifications/cancelled` message,
  which the **SDK server honours mid-handler** via its cooperative input drain
  (a handler's `ctx.isCancelled`/`reportProgress` poll dispatches any pending
  inbound message, flipping the in-flight token; see `serveStdio`'s cancellation
  unittest). This *client* skips phase 4 over stdio only because its simple
  synchronous loop cannot inject a notification while a `callTool` is in flight —
  not an SDK limitation. Progress, logging, structured results, and the typed
  elicitation/sampling round-trips all run over both transports.
- **Auth is HTTP only.** OAuth (bearer tokens, the protected-resource metadata
  handshake, the authorization-server flow) is defined over HTTP request
  headers; the stdio transport has no header channel, so authentication is not
  applicable to the stdio path. See `examples/auth` for the HTTP auth example.
- The example is its own dub package with a path dependency on the root `mcp`
  SDK (`"mcp": { "path": "../.." }`). It does not modify the root `dub.json`.
