# MCP Events example (server + client e2e), dual-transport

A self-contained example of the **`io.modelcontextprotocol/events`** extension
in the D MCP SDK ([mcp.d](https://github.com/Poita/mcp.d)): a server declares an
event type, and a client receives its occurrences over all three delivery modes —
**poll**, **push** (stream), and **webhook**. It is its own dub package with path
dependencies on the root `mcp-d` library and the shared `examples/common`
scaffold, so it never touches the root `dub.json`.

Events is a modern-only extension (2026-07-28), so the client enables the modern
protocol before negotiation. The single server binary speaks **stdio or
Streamable HTTP**, and the single client binary is a **self-verifying e2e test**
that runs the same assertions over either transport.

## What it teaches

**Server side (`server.d`)**:

- **`server.enableEvents(null, opts)`** returns the `EventsRuntime`; a `null`
  store selects the in-memory webhook subscription store.
- **`rt.define!(IncidentArgs, Incident)("incident.created", ...)`** declares a
  typed push-source event type: `IncidentArgs` derives the subscription
  `inputSchema`, `Incident` derives the `payloadSchema`. Because the upstream has
  no addressable history, there is no fetch handler; the SDK serves `events/poll`
  from an in-memory ring buffer fed by `publish`.
- **`.match(...)`** filters delivery per subscription: a subscriber's `severity`
  argument only receives incidents of that severity (an empty filter matches
  all).
- **`raise_incident`** is an ordinary `@tool` that calls the handle's
  `publish(Incident(...))`, which stamps the event id, timestamp and cursor and
  fans the occurrence out to poll buffers, open streams and the webhook delivery
  queue.
- **Webhook prerequisites for a dev server**: the spec forbids webhook
  subscriptions on unauthenticated servers, so `EventsOptions.assumePrincipal`
  treats every caller as one fixed principal (suitable only for a single-tenant
  server that authenticates outside the SDK), and
  `EventsOptions.allowPrivateCallbackHosts` lets the SSRF guard accept a
  loopback `http` callback. A production server leaves both off.

**Client side (`client.d`)** asserts:

1. `server/discover` advertises the events extension (`eventsExtensionKey`) in
   `capabilities.extensions`, and `client.eventsSupported()` is true.
2. `events/list` (`listEvents`) declares `incident.created` with its delivery
   modes.
3. **Poll** — a bootstrap `pollEvents` returns no events and a cursor; after
   raising a `P1` incident, polling from that cursor drains it.
4. **Push** — `streamEvents` opens an `events/stream` whose callback receives the
   raised `P2` incident as a typed `EventOccurrence`.
5. **Webhook** — the client runs a `WebhookReceiver` on a loopback HTTP listener
   (port 8647), subscribes with `subscribeWebhook` and a `generateWhsecSecret()`
   secret, and receives the `P3` incident after the server verifies the endpoint
   and POSTs a signed delivery. The webhook channel is independent of the MCP
   transport, so this works over stdio too.

On success it prints `OK: ...` and exits `0`; any failed assertion prints what
differed and exits non-zero.

## Running it

```sh
# from this directory (examples/events)
dub build -c server      # produces ./events-server
dub build -c client      # produces ./events-client
```

### Over stdio (default)

```sh
./events-client          # spawns ./events-server and runs the e2e (exit 0 == pass)
```

### Over Streamable HTTP

```sh
# terminal 1
./events-server --http --port 8646

# terminal 2
./events-client --http http://127.0.0.1:8646/mcp
```

Either way the client also listens on `127.0.0.1:8647` for webhook deliveries.

See the [MCP Events](../../README.md#mcp-events-triggers) section of the root
README for pull sources (`@event` fetch handlers), durable delivery queues and
multi-node deployments.
