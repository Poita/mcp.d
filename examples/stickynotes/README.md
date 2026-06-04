# Sticky Notes example (stateful: tools + resources + elicitation)

A small **stateful** MCP server that combines the three things a real server
usually does at once:

- **Tools that mutate state** — `add_note`, `remove_note`, `remove_all`.
- **A resource per piece of state** — every note is its own direct resource at
  `note:///{id}`, so the live board is browsable via `resources/list` and each
  note is readable via `resources/read`. The set is dynamic: tools register and
  unregister note resources at runtime and emit
  `notifications/resources/list_changed`.
- **An elicitation guarding a destructive action** — `remove_all` issues a
  blocking server→client `ctx.elicit!ConfirmClear` and only wipes the board if
  the user explicitly confirms.

It runs over **both** stdio and Streamable HTTP. The server is stateful because
a server→client elicitation needs a session to correlate its reply over HTTP
(stdio works too, as a single implicit session).

## Tools

| Tool | Args | Behaviour |
| --- | --- | --- |
| `add_note` | `text` | Stores the note under a fresh id, registers its `note:///{id}` resource, announces the list change. Returns `{id, uri}`. |
| `remove_note` | `id` | Deletes one note and unregisters its resource. Returns `{removed, id}` (`removed:false` for an unknown id — not an error). |
| `remove_all` | — | Blocks on a `ConfirmClear` elicitation; clears every note only on `accept` with `confirm:true`. Decline / cancel / unchecked all leave the board intact. Returns `{status, removed}`. |

## Run it

**stdio** (the client spawns the server):

```bash
dub run -c client
```

**HTTP** (two terminals):

```bash
# terminal 1 — server
dub run -c server -- --http --port 8537

# terminal 2 — client
dub run -c client -- --http http://127.0.0.1:8537/mcp
```

The `client.d` is a self-verifying end-to-end test: it adds notes, lists and
reads their resources, removes one, then drives `remove_all` through cancel /
unchecked / confirm (asserting the board is only cleared on an explicit
confirmation), and finally checks that a client without elicitation support
makes `remove_all` fail rather than deleting silently. It exits non-zero on any
mismatch, so CI runs it on both transports.

## SDK pieces shown

- `McpServer.stateful` (sessioned, required for server→client requests over HTTP).
- `registerHandlers` with `@tool` methods returning typed result structs (the
  reflection layer derives each tool's `outputSchema` + `structuredContent`).
- `registerResource` / `removeResource` + `notifyResourcesListChanged` for a
  resource set that changes at runtime.
- `ctx.elicit!T` for a typed, blocking confirmation whose `requestedSchema` is
  derived from the `ConfirmClear` struct.
