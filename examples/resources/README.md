# Resources example (dual-transport server + self-verifying e2e client)

A focused, runnable demonstration of **MCP Resources** from both sides, over
**BOTH transports** — stdio and Streamable HTTP — from a single server binary
and a single self-verifying client. It is its own dub package with a path
dependency on the root `mcp` SDK (it does not modify the root `dub.json`).

## What it teaches

Server side (`server.d`), written in the ergonomic **UDA style**
(`@resource` / `@resourceTemplate` / `@tool` + `registerHandlers`):

- **Direct resource** — a static `@resource` `config://app`, carrying a draft
  `CacheableResult` freshness hint declared with `@cache(ttlMs, scope)` that
  rides on `resources/read`.
- **Resource template** — `@resourceTemplate("note:///{id}")`; the reader
  receives the captured `{id}` as a typed argument.
- **Subscriptions** — `enableResourceSubscriptions()` advertises the capability;
  `notifyResourceUpdated(uri)` pushes `notifications/resources/updated` to
  subscribers.
- **List-changed** — `enableResourcesListChanged()` + `notifyResourcesListChanged()`
  emit `notifications/resources/list_changed` when the available set changes.
- A `@tool` `set_note` mutates (or creates) a note, then pushes the appropriate
  notifications. It **returns a typed `SetNoteResult` struct**, so the reflection
  layer derives both the tool's `outputSchema` and each call's
  `structuredContent` from the struct fields — no hand-built result Json.

One binary, either transport. Transport selection (and the client's
spawn-vs-HTTP wiring + the shared `check`/`runClient` harness) is provided
by the `examples-common` scaffold (`runServerFromArgs` / `connectFromArgs` /
`runClient`), so this example carries no transport boilerplate of its own:

```bash
dub run -c server                       # stdio (default)
dub run -c server -- --http --port 8349 # Streamable HTTP on 127.0.0.1:8349/mcp
```

Client side (`client.d`) — also a **self-verifying end-to-end test**. The SAME
client verifies the server over both transports; the assertions are
transport-agnostic. It speaks the stateless **draft** protocol for two reasons:
the `CacheableResult` hint rides inline on every `resources/read`, and a
`subscriptions/listen` stream is the one push mechanism the SDK supports over
**both** transports (the legacy standalone GET SSE stream is HTTP-only).

It asserts:

1. `resources/list` contains `config://app`.
2. `resources/templates/list` contains `note:///{id}`.
3. Reading `config://app` returns the expected JSON text.
4. Reading `note:///welcome` (template expansion) returns the seeded body with
   `mimeType: text/plain`.
5. Reading an unknown URI raises an error. **Note:** the draft aligns the
   `resources/read` not-found code to `invalidParams` (**-32602**); the stable
   revisions used `resourceNotFound` (**-32002**). We speak draft, so we expect
   `-32602`.
6. The draft read of `config://app` surfaces the freshness hint
   (`ttlMs == 60000`, `cacheScope == public`).
7. After `subscriptions/listen`, calling `set_note` delivers a
   `notifications/resources/updated` for the subscribed URI **and** a
   `notifications/resources/list_changed` for the newly-created note resource;
   the new note then reads back its pushed body, and the tool's typed
   `structuredContent` (`uri` + `created`) is asserted.

On success the client prints a single `OK [stdio|http]: ...` line and exits `0`.
On any mismatch it prints what differed and exits **non-zero**, so CI can run it
as a regression test.

## How to run

### stdio

The client spawns the server binary itself (no `--http`) and drives it over its
stdin/stdout — so it is a single command. Build both configs first:

```bash
dub build -c server && dub build -c client
dub run -c client            # spawns ./resources-server, runs every assertion
echo "exit: $?"              # 0 on success, non-zero on any failed assertion
```

### Streamable HTTP

The server and client run as two processes. The server serves on
`http://127.0.0.1:<port>/mcp`.

Terminal 1 — start the server over HTTP:

```bash
dub run -c server -- --http --port 8349
```

Terminal 2 — run the client (the e2e test) against that URL:

```bash
dub run -c client -- --http http://127.0.0.1:8349/mcp
echo "exit: $?"
```

Or scripted (what CI does), covering both transports:

```bash
dub build -c server && dub build -c client

# stdio
./resources-client; echo "stdio exit: $?"

# http
./resources-server --http --port 8349 &
SRV=$!
sleep 2
./resources-client --http http://127.0.0.1:8349/mcp; echo "http exit: $?"
kill $SRV
```

## Auth (HTTP only)

OAuth/bearer-token authorization is an **HTTP-only** concern in MCP: the
Authorization framework is defined over HTTP headers (`Authorization: Bearer …`)
and the `WWW-Authenticate` / protected-resource-metadata discovery flow, none of
which exist on the stdio transport (a stdio server is a trusted local
subprocess, not a network peer). So if you extend this example with auth, gate it
behind `--http` and configure it via `StreamableHttpOptions`; the stdio path
stays unauthenticated by design. See `examples/auth` for the HTTP auth flow.

> Note: on shutdown vibe.d may print harmless `leaking eventcore driver`
> warnings for a still-open SSE socket. They do not affect the exit code.
