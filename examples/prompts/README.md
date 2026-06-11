# Prompts + completion example (dual-transport: stdio + HTTP)

A self-contained, runnable example demonstrating the MCP **prompts** surface of
the D MCP SDK from **both sides** — a server that exposes prompts, and a client
that drives it *and doubles as an end-to-end regression test* — over **both**
the stdio and Streamable HTTP transports.

This directory is its own dub package: it depends on the root `mcp` library and
on the shared `examples-common` scaffold (`../common`) via path dependencies; it
does not modify the root `dub.json`. The scaffold supplies the `check`/`checkEq`
assertion helpers, the `runClient` event-loop wiring, and the
`connectFromArgs`/`runServerFromArgs` transport selectors used below.

## What it teaches

Server (`server.d`) — one binary, either transport:

- **`@prompt` with typed arguments.** Prompt methods are plain D methods
  annotated with `@prompt(...)`; their parameters become the prompt's typed
  arguments, and `@describe(...)` documents each one. The reflection layer
  (`registerHandlers`) derives the `prompts/list` descriptors and the typed
  dispatch for `prompts/get` automatically.
- **Typed content, no hand-built Json.** The `code_review` prompt returns a
  `GetPromptResult` whose messages are built with the SDK's typed content
  helpers `Content.makeText(...)` and `Content.makeEmbeddedText(uri, mimeType,
  text)` — the snippet travels as an *embedded resource* (uri + mimeType +
  text), not just inline prose.
- **`completion/complete` for prompt-argument autocompletion.** A completion
  handler (`setCompletionRequestHandler`) prefix-matches the partial value of the
  `language` argument against a known-language list. Registering a handler makes
  the server advertise the `completions` capability.
- **Transport selection via the scaffold.** `main` hands the configured server
  to `runServerFromArgs(server, args, 8533)`: default is **stdio** (`runStdio`);
  passing `--http` runs the *same* configured server over **Streamable HTTP**
  (`runStreamableHttp`) on `--port` (default `8533`) / `--host` (default
  `127.0.0.1`). The prompt + completion surface is identical on both.

Client (`client.d`) — a **self-verifying e2e test** over both transports:

- selects its transport via the scaffold's `connectFromArgs(args,
  "prompts-server")`: with `--http <url>` it connects via `McpClient.http(url)`;
  without it, it spawns the sibling `prompts-server` binary (no `--http`) via
  `McpClient.spawnSibling("prompts-server")`, which owns the subprocess and
  drives it over stdio (`client.close()` runs the MCP stdio shutdown sequence).
  The whole scenario runs inside the scaffold's `runClient(...)`. The assertions
  are transport-agnostic, so the **same** checks verify both runs.
- asserts `prompts/list` contains exactly `greet` and `code_review`, with their
  titles and argument descriptors;
- asserts `prompts/get greet` renders the `name` argument (built as a JSON
  object — the client request surface is untyped, see the repo-root `DESIGN.md`)
  into the message text;
- asserts `prompts/get code_review` returns an embedded-resource block, decoded
  via the typed `Content.embeddedResource()` -> `ResourceContents`, whose
  `uri`/`mimeType`/`text` match what was submitted;
- asserts `completion/complete` prefix-matches (`ru` → `[rust]`, `p` →
  `[python]`, `` `` → all 9 languages);
- asserts an unknown prompt name raises a JSON-RPC `invalidParams` (-32602).

On success it prints `OK: ...` and exits 0; on any
failed assertion it prints what differed and exits non-zero, so CI can run the
client directly as a regression test on either transport.

## How to run

Build both binaries once:

```sh
# from this directory (examples/prompts/)
dub build -c server      # builds the prompts-server binary
dub build -c client      # builds the prompts-client binary
```

### STDIO (default)

The client spawns the built server binary, so running the client is the whole
end-to-end test:

```sh
dub run -c client        # spawns prompts-server (sibling) over stdio, runs all assertions, exits 0 on OK
```

### HTTP (Streamable HTTP)

Start the server with `--http` (optionally choose a port), then point the client
at its `/mcp` endpoint:

```sh
# terminal 1 — start the HTTP server (default port 8533)
dub run -c server -- --http --port 8533

# terminal 2 — drive it over HTTP
dub run -c client -- --http http://127.0.0.1:8533/mcp
```

Expected output on success (either transport):

```
OK: prompts/list (2), greet typed-arg render, code_review embedded resource, ...
```

The process exit code is `0` on success and non-zero on any assertion failure.

## A note on authentication

This example does not configure auth. If you need to add it, do so over **HTTP
only**: MCP authorization is defined as OAuth 2.x bearer tokens carried in HTTP
`Authorization` headers, which is meaningful only for the HTTP transport. The
stdio transport is a local, parent-spawned subprocess with no HTTP request
surface, so there is no transport-level place to attach a bearer token —
`McpClient.setBearerToken` is a no-op over stdio.
