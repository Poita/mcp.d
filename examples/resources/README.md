# Resources example (server + self-verifying e2e client)

A focused, runnable demonstration of **MCP Resources** from both sides, over the
**Streamable HTTP** transport. It is its own dub package with a path dependency
on the root `mcp` SDK (it does not modify the root `dub.json`).

## What it teaches

Server side (`server.d`):

- **Direct resource** — a static resource `config://app` registered with
  `McpServer.registerResource`, including a draft `CacheableResult` freshness
  hint (`ttlMs` + `cacheScope`) emitted on `resources/read`.
- **Resource template** — `note:///{id}` registered with
  `registerResourceTemplate`; the reader receives the concrete URI and the
  captured `{id}`.
- **Subscriptions** — `enableResourceSubscriptions()` advertises the capability;
  `notifyResourceUpdated(uri)` pushes `notifications/resources/updated` to
  subscribers on the standalone server→client SSE stream.
- **List-changed** — `enableResourcesListChanged()` + `notifyResourcesListChanged()`
  emit `notifications/resources/list_changed` when the available set changes.
- A `set_note` tool mutates (or creates) a note, then pushes the appropriate
  notifications — giving the client something concrete to observe.

Client side (`client.d`) — also a **self-verifying end-to-end test**:

1. `resources/list` contains `config://app`.
2. `resources/templates/list` contains `note:///{id}`.
3. Reading `config://app` returns the expected JSON text.
4. Reading `note:///welcome` (template expansion) returns the seeded body with
   `mimeType: text/plain`.
5. Reading an unknown URI fails with the `resourceNotFound` (**-32002**) code.
6. A draft-protocol read of `config://app` surfaces the freshness hint
   (`ttlMs == 60000`, `cacheScope == public`).
7. After `subscribe` + opening the server→client stream, calling `set_note`
   delivers a `notifications/resources/updated` for the subscribed URI **and** a
   `notifications/resources/list_changed` for the newly-created note resource;
   the new note then reads back its pushed body.

On success the client prints a single `OK: ...` line and exits `0`. On any
mismatch it prints what differed and exits **non-zero**, so CI can run it as a
regression test.

## How to run

This is an HTTP example, so the server and client run as two processes. The
server serves on `http://127.0.0.1:8349/mcp`.

Terminal 1 — start the server:

```bash
dub run -c server
```

Terminal 2 — run the client (the e2e test):

```bash
dub run -c client
echo "exit: $?"   # 0 on success, non-zero on any failed assertion
```

Or scripted (what CI does):

```bash
dub build -c server && dub build -c client
./resources-server &        # background
SRV=$!
sleep 2
./resources-client          # exits 0 iff all assertions held
RC=$?
kill $SRV
exit $RC
```

> Note: on shutdown vibe.d may print harmless `leaking eventcore driver`
> warnings for the still-open SSE socket. They do not affect the exit code.
