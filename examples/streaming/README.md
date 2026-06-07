# examples/streaming — Progress / logging / cancellation

A self-contained example (its own dub package) showing how the **server** emits
and the **client** consumes MCP's in-flight channels — over **BOTH transports**:
stdio and Streamable HTTP. One server binary serves either transport; one client
verifies both.

- **Progress** — `ctx.reportProgress(done, total, message)` (integer-step
  convenience, #501) → `notifications/progress`, observed via a per-call
  progress sink, `callTool(name, args, onProgress)` (#494).
- **Logging** — `ctx.log(LogLevel.info, message, logger)` (typed-level, plain
  string payload, #501) → `notifications/message`, observed via
  `McpClient.onLogMessage`.
- **Cancellation** — a long-running handler polls `ctx.isCancelled` and stops
  early; on Streamable HTTP the cancellation signal is the client closing its
  response stream (basic/utilities/cancellation §Transport-Specific
  Cancellation), which the handler also detects as a failed send.

The `client.d` is **not just a demo — it is a self-verifying end-to-end test**.
Every observation is asserted against the value the server promised; on any
mismatch it prints what differed and exits non-zero. On success it prints a
one-line `OK [stdio]:` / `OK [http]:` summary and exits 0.

## What it teaches

The server (`server.d`, ergonomic UDA style — `@tool` + `registerHandlers`)
exposes two tools:

- `countdown(steps, delayMs)` — walks `steps` units of work. Each step sleeps,
  reports progress `i/steps`, and logs an `info` line tagged with the logger
  name `countdown`. It honors cancellation and returns structured output
  `{ completed, total, cancelled }` (inferred from the struct return).
- `cancel_stats()` — returns `{ cancelled }`, the number of `countdown` runs
  that observed a cancellation. Used by the client to confirm, out of band, that
  a mid-flight cancellation was actually honored.

The client (`client.d`) verifies, in order:

1. **List + progress + logging** (transport-agnostic): `listTools()` contains
   `countdown` and `cancel_stats`; a `countdown` call made with a per-call
   progress sink (`callTool(name, args, onProgress)`) streams exactly N progress
   notifications (monotonically increasing, each carrying the call's minted
   token, last == total) and N `info` log messages from the `countdown` logger
   before the final result.
2. **Error code** (transport-agnostic): an unknown tool raises `McpException`
   with `invalidParams` (-32602).
3. **Cancellation** (HTTP only): a long `countdown` is started on its own task;
   once the first progress proves it is in flight, the client tears down its
   stream and a fresh `cancel_stats` read confirms the counter increased.

## Run it

### stdio (default)

The client spawns the sibling `streaming-server` binary itself (via the
scaffold's `connectFromArgs` -> `McpClient.spawnSibling`) and talks to it over
stdin/stdout — a single command, no ports.

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
  unittest). This *client* skips phase 3 over stdio only because its simple
  synchronous loop cannot inject a notification while a `callTool` is in flight —
  not an SDK limitation. Progress, logging, and structured results all run over
  both transports.
- **Typed elicitation and sampling are not shown here.** Server→client
  round-trips (`ctx.elicit`, `ctx.sample`) require a stateful connection. This
  example is stateless and only demonstrates client→server tool calls. See
  `examples/elicitation` and `examples/sampling` for those patterns.
- **Auth is HTTP only.** OAuth (bearer tokens, the protected-resource metadata
  handshake, the authorization-server flow) is defined over HTTP request
  headers; the stdio transport has no header channel, so authentication is not
  applicable to the stdio path. See `examples/auth` for the HTTP auth example.
- The example is its own dub package with path dependencies on the root `mcp`
  SDK (`"mcp": { "path": "../.." }`) and on the shared `examples/common` scaffold
  (`"examples-common": { "path": "../common" }`), which supplies the `check`
  assertion helper, the `runClient` event-loop driver, and the
  `connectFromArgs` / `runServerFromArgs` transport pickers. It does not modify
  the root `dub.json`.
