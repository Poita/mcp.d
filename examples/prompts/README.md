# Prompts + completion example

A self-contained, runnable example demonstrating the MCP **prompts** surface of
the D MCP SDK from **both sides** — a server that exposes prompts, and a client
that drives it *and doubles as an end-to-end regression test*.

This directory is its own dub package (it depends on the root `mcp` library via
a path dependency); it does not modify the root `dub.json`.

## What it teaches

Server (`server.d`):

- **`@prompt` with typed arguments.** Prompt methods are plain D methods
  annotated with `@prompt(...)`; their parameters become the prompt's typed
  arguments, and `@describe(...)` documents each one. The reflection layer
  (`registerHandlers`) derives the `prompts/list` descriptors and the typed
  dispatch for `prompts/get` automatically.
- **Embedded-resource content in a message.** The `code_review` prompt returns a
  `GetPromptResult` whose second message is an *embedded resource* content block
  (`Content.makeEmbeddedText(uri, mimeType, text)`) — the snippet travels as a
  resource (uri + mimeType + text), not just inline prose.
- **`completion/complete` for prompt-argument autocompletion.** A completion
  handler (`setCompletionRequestHandler`) prefix-matches the partial value of the
  `language` argument against a known-language list. Registering a handler makes
  the server advertise the `completions` capability.

Client (`client.d`) — a **self-verifying e2e test**:

- asserts `prompts/list` contains exactly `greet` and `code_review`, with their
  titles and typed-argument descriptors;
- asserts `prompts/get greet` renders the typed `name` argument into the message
  text;
- asserts `prompts/get code_review` returns an embedded-resource block whose
  `uri`/`mimeType`/`text` match what was submitted;
- asserts `completion/complete` prefix-matches (`ru` → `[rust]`, `p` →
  `[python]`, `` `` → all 9 languages);
- asserts an unknown prompt name raises a JSON-RPC `invalidParams` (-32602).

On success it prints `OK: ...` and exits 0; on any failed assertion it prints
what differed and exits non-zero.

## How to run

This is a **STDIO** example: the client spawns the built server binary, so
running the client is the whole end-to-end test.

```sh
# from this directory (examples/prompts/)
dub build -c server      # builds the prompts-server binary
dub run   -c client      # spawns the server, runs all assertions, exits 0 on OK
```

`dub run -c client` builds `client` if needed, then runs it. The client locates
the `prompts-server` binary next to itself (dub places sibling-config target
binaries in the package directory), spawns it over STDIO, and drives the whole
handshake + prompts + completion flow through an `McpClient`.

Expected output on success:

```
OK: prompts/list (2), greet typed-arg render, code_review embedded resource, ...
```

The process exit code is `0` on success and non-zero on any assertion failure,
so CI can run the client directly as a regression test.
