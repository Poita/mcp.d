# examples/common — shared scaffold for mcp.d example servers and clients

This directory is a standalone dub library (`examples-common`) that every other
example in `examples/` depends on. Its sole source file,
`examples_common.d`, factors out four things every example server/client pair
repeats so they share one implementation instead of copy-pasting it.

## What it provides

### Assertion helpers — `check` / `checkEq`

Each example client is a **self-verifying e2e harness**: it makes MCP calls and
asserts on the results, exiting non-zero on any mismatch so CI can gate on it.

- `check(cond, msg)` — throws and prints `FAIL: <msg>` when `cond` is false.
- `checkEq(actual, expected, label)` — compares with `==` and includes both
  values in the failure message.

### Event-loop driver — `runClient`

`runClient(scenario)` drives the vibe event loop so the **same** scenario body
works over both a synchronous stdio (`McpClient.spawnSibling`) transport and an
HTTP transport: the stdio client's blocking request/response completes inside the
loop, and the HTTP client's background streams get a loop to run on. Any
`Throwable` that escapes the scenario is reported as a `FAIL:` line and mapped
to exit code 1.

### Client transport selector — `connectFromArgs`

`connectFromArgs(args, siblingServerName)` picks the transport from `argv`:

- `--http <url>` (alias `--url <url>`) → `McpClient.http(url)` (Streamable HTTP)
- otherwise → `McpClient.spawnSibling(siblingServerName)` (stdio, spawning
  the named sibling binary next to the running executable)

The returned client is not yet initialized; call `.initialize()` before use.

### Server transport selector — `runServerFromArgs`

`runServerFromArgs(server, args, defaultPort)` mirrors the client helper for
servers:

- `--http` → `runStreamableHttp(server, port, host)` using `--port` (default
  `defaultPort`) and `--host` (default `127.0.0.1`)
- otherwise → `runStdio(server)`

### HTTP-only server helpers — `parseHttpServerArgs` / `runHttpServerFromArgs`

For examples that serve over **HTTP only** (e.g. the auth example, which must
never silently degrade to an unauthenticated stdio transport):

- `parseHttpServerArgs(args, defaultPort, opts, port, host)` — parses
  `--port`/`-p` and `--host`/`-h` from `args`, updates `opts.bindAddresses`
  from the parsed host unless the caller pinned a non-default set, and writes
  the resolved values back through `port`/`host` out-params.
- `runHttpServerFromArgs(server, args, defaultPort, opts, port, host)` — calls
  `parseHttpServerArgs` then `runStreamableHttp(server, port, opts)`.

### Shared wire type — `WhoamiResult`

A `struct` shared by the auth example server and client so both sides agree on
the JSON layout of the `whoami` tool result at compile time rather than at
runtime.

## Using it in a new example

Add a path dependency in your `dub.json`:

```json
"dependencies": {
    "mcp-d":          { "path": "../.." },
    "examples-common": { "path": "../common" }
}
```

Then import the helpers you need:

```d
import examples_common;
```
