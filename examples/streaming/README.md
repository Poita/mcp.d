# examples/streaming — Progress / logging / cancellation

A self-contained example (its own dub package) showing how the **server** emits
and the **client** consumes the three "in-flight" channels of MCP over the
**Streamable HTTP** transport:

- **Progress** — `ctx.reportProgress(done, total, message)` →
  `notifications/progress`, observed via `McpClient.onProgress`.
- **Logging** — `ctx.log(level, data, logger)` → `notifications/message`,
  observed via `McpClient.onLogMessage`.
- **Cancellation** — a long-running handler polls `ctx.isCancelled` and stops
  early; on Streamable HTTP the cancellation signal is the client closing its
  response stream (basic/utilities/cancellation §Transport-Specific
  Cancellation), which the handler also detects as a failed send.

The `client.d` is **not just a demo — it is a self-verifying end-to-end test**.
Every observation is asserted against the value the server promised; on any
mismatch it prints what differed and exits non-zero. On success it prints a
one-line `OK:` summary and exits 0. CI runs the client to catch behavioral
regressions.

## What it teaches

The server (`server.d`) exposes:

- `countdown(steps, delayMs)` — walks `steps` units of work. Each step sleeps,
  reports progress `i/steps`, and logs an `info` line tagged with the logger
  name `countdown`. It honors cancellation and returns structured output
  `{ completed, total, cancelled }`.
- `cancel_stats()` — returns `{ cancelled }`, the number of `countdown` runs
  that observed a cancellation. Used by the client to confirm, out of band, that
  a mid-flight cancellation was actually honored.

The client (`client.d`) verifies, in order:

1. **Progress + logging** (pinned to the released protocol 2025-11-25, where
   `logging/setLevel` and full notification streaming are available):
   `listTools()` contains `countdown`; a call carrying a `progressToken` streams
   exactly N progress notifications (monotonically increasing, echoing the
   token, last == total) and N `info` log messages from the `countdown` logger
   *before* the final result `{completed:N, total:N, cancelled:false}`.
2. **Cancellation** (draft protocol): a long `countdown` is started on its own
   task; once the first progress proves it is in flight, the client tears down
   its stream. The server stops the work early.
3. **Verify + health**: a fresh client reads `cancel_stats` and asserts the
   counter increased (concrete proof the cancellation was honored), then runs
   another `countdown` to confirm the server is still healthy.

## Run it (two terminals)

Streamable HTTP, so the server runs in one terminal and the client connects to
its URL in another.

```sh
# terminal 1 — start the server (serves http://127.0.0.1:9357/mcp)
dub run -c server

# terminal 2 — run the self-verifying client; exits 0 on OK, non-zero on mismatch
dub run -c client
```

Override the address if needed:

```sh
dub run -c server -- --port 9999 --host 127.0.0.1
dub run -c client -- http://127.0.0.1:9999/mcp
```

### One-shot (what CI does)

```sh
dub build -c server && dub build -c client
./streaming-server &                 # background
SERVER=$!
sleep 1
./streaming-client                   # the e2e; check the exit code
RC=$?
kill $SERVER
exit $RC
```

A non-zero client exit code means a behavioral regression — the client prints
`FAIL: <what differed>`.

## Notes

- The example is its own dub package with a path dependency on the root `mcp`
  SDK (`"mcp": { "path": "../.." }`). It does not modify the root `dub.json`.
- The progress/logging assertions pin protocol 2025-11-25 so logs and
  `logging/setLevel` behave deterministically; the cancellation phase uses the
  draft revision, whose Streamable HTTP cancellation is the dropped response
  stream.
