# examples/sampling — server-initiated LLM Sampling

A self-contained MCP example showing **Sampling** from both sides over the
Streamable HTTP transport (issue #354).

Sampling inverts the usual MCP direction: instead of the client driving the
server, the *server* borrows the *client's* LLM. Inside a tool the server sends
a `sampling/createMessage` request (`RequestContext.sample`); the client answers
it with its own model via an `onSampling` handler. The server never holds an API
key — it just asks the client to run the model.

## What it teaches

**Server (`server.d`, ergonomic UDA style):** `@tool` methods on a class,
registered with `registerHandlers`. Each tool takes a `RequestContext ctx` and
calls `ctx.sample(...)`:

- `summarize(text)` — builds a typed `CreateMessageRequest` (a system prompt +
  one user message), calls `ctx.sample`, and returns
  `{summary, model, stopReason}` from the client's typed `CreateMessageResult`.
- `model_name()` — a minimal 1-token sample that reports which model the client
  used (`{model}`).

The server runs over Streamable HTTP because the sampling round-trip is a
*server→client* request mid-tool-call; the keep-alive deadlock that used to bite
this path on Streamable HTTP was fixed in #377.

**Client (`client.d`, self-verifying e2e test):** installs an `onSampling`
handler that acts as a **deterministic mock model**. Because the mock is
deterministic, the client knows exactly what each tool result must be and
asserts it precisely — proving the mocked sampling value flowed
server → client → server. It verifies:

- `listTools()` contains `summarize` and `model_name`;
- the `onSampling` handler was actually invoked (the server reached back);
- the handler received the server's system prompt and user text;
- `summarize` returns the mock model's exact `summary`/`model`/`stopReason`;
- `model_name` returns the mock model's `model` identifier.

On success it prints `OK: ...` and exits 0; on ANY mismatch it prints what
differed and exits non-zero, so it doubles as a CI regression test.

## Build

```sh
dub build -c server
dub build -c client
```

## Run (Streamable HTTP — two terminals)

Terminal 1 — start the server (listens on `http://127.0.0.1:9354/mcp`):

```sh
dub run -c server          # or: ./sampling-server --port 9354
```

Terminal 2 — run the self-verifying client against it:

```sh
dub run -c client          # or: ./sampling-client http://127.0.0.1:9354/mcp
echo $?                     # 0 on success, non-zero on any failed assertion
```

The server port (and the client's target URL) default to `9354`; override the
server with `--port` and pass the matching `http://.../mcp` URL to the client.
