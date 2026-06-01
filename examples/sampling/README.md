# examples/sampling — server-initiated LLM Sampling (dual-transport)

A self-contained MCP example showing **Sampling** from both sides, over BOTH
the stdio and Streamable HTTP transports (issue #354).

Sampling inverts the usual MCP direction: instead of the client driving the
server, the *server* borrows the *client's* LLM. Inside a tool the server sends
a `sampling/createMessage` request (`RequestContext.sample`); the client answers
it with its own model via an `onSampling` handler. The server never holds an API
key — it just asks the client to run the model.

The MCP stdio transport is bidirectional, so this server→client hop works over
**both** transports. (The Streamable-HTTP keep-alive deadlock that used to bite
this path was fixed in #377.)

## What it teaches

**Server (`server.d`, ergonomic UDA style):** `@tool` methods on a class,
registered with `registerHandlers`. Each tool takes a `RequestContext ctx` and
calls `ctx.sample(...)` using the **typed APIs**:

- builds a typed `CreateMessageRequest` + `SamplingMessage` with
  `Content.makeText` (no hand-built Json);
- calls `ctx.sample(CreateMessageRequest)` and reads the typed
  `CreateMessageResult`;
- returns a struct (`SummaryResult` / `ModelResult`) so the SDK infers the
  output schema and emits `structuredContent`.

Tools:

- `summarize(text)` — returns `{summary, model, stopReason}` from the client's
  `CreateMessageResult`.
- `model_name()` — a minimal 1-token sample that reports which model the client
  used (`{model}`).

One binary, either transport:

```sh
./sampling-server                      # default: stdio
./sampling-server --http --port 9354   # Streamable HTTP on http://127.0.0.1:9354/mcp
```

**Client (`client.d`, self-verifying e2e test, dual-transport):** installs an
`onSampling` handler that acts as a **deterministic mock model**, built with the
**typed client APIs**:

- the `onSampling` handler returns `CreateMessageResult.text(model, text)`
  instead of assembling the `role`/`content`/`model`/`stopReason` reply by hand;
- it calls a tool with a typed argument struct
  (`callTool("summarize", SummarizeArgs(text))`) rather than hand-building a Json
  arguments object;
- it decodes the structured result in one step with
  `result.structuredContentAs!SummaryResult` instead of reading
  `structuredContent["x"].get!...` field by field.

The same transport-agnostic assertions run over either transport, so the client
doubles as a CI regression test for both. It verifies:

- `listTools()` contains `summarize` and `model_name`;
- the `onSampling` handler was actually invoked (the server reached back);
- the handler received the server's system prompt and user text;
- `summarize` returns the mock model's exact `summary`/`model`/`stopReason`;
- `model_name` returns the mock model's `model` identifier.

On success it prints `OK: ...` and exits 0; on ANY mismatch it prints what
differed and exits non-zero.

## Build

```sh
dub build -c server
dub build -c client
```

## Run over stdio (default)

The client spawns the server binary (built above, run WITHOUT `--http`) and
drives it over stdio — a single command, no second terminal:

```sh
dub run -c client          # or: ./sampling-client
echo $?                    # 0 on success, non-zero on any failed assertion
```

## Run over Streamable HTTP (two terminals)

Terminal 1 — start the server with `--http` (listens on `http://127.0.0.1:9354/mcp`):

```sh
dub run -c server -- --http --port 9354     # or: ./sampling-server --http --port 9354
```

Terminal 2 — run the self-verifying client against it:

```sh
dub run -c client -- --http http://127.0.0.1:9354/mcp
echo $?                    # 0 on success, non-zero on any failed assertion
```

The HTTP port defaults to `9354`; override the server with `--port N` and pass
the matching `http://127.0.0.1:N/mcp` URL to the client's `--http`.

## A note on auth

This example does not enable authentication. If you want to require OAuth on the
sampling endpoint, that is an **HTTP-only** concern: OAuth 2.1 bearer-token auth
is defined by MCP over HTTP (the `Authorization` header + the HTTP-served
metadata/protected-resource discovery endpoints). The stdio transport has no
HTTP request line or headers to carry a bearer token, so auth is not applicable
there — stdio servers are launched as a trusted local subprocess instead. See
`examples/auth` for the HTTP auth flow.
