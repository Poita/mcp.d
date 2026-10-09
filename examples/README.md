# mcp.d examples

Each subdirectory is its own dub package with a `server` and a `client`
configuration; the client is a self-verifying end-to-end test of the server.
`scripts/run-examples.sh` (or `just examples`) builds and runs every pair over
stdio and Streamable HTTP, which takes roughly 15 minutes; `just example <name>`
runs a single one.

Start from [`hello/`](hello/) when copying an example into your own project: it
depends only on `mcp-d` and uses nothing outside the public `mcp` /
`mcp.transport` modules.

## Copying an example that uses `examples/common`

Every other example depends on the repo-only [`examples/common`](common/)
scaffold (`examples-common`), which wraps the SDK's own entry points in
argv-driven helpers. To lift one out of the repository, drop the
`examples-common` dependency and replace the scaffold calls with the SDK calls
they wrap:

| Scaffold call | Replace with |
| --- | --- |
| `runServerFromArgs(server, args, port)` | `runStdio(server)`, or `runStreamableHttp(server, opts)` with a `StreamableHttpOptions opts` (`import mcp.transport;`) |
| `runHttpServerFromArgs(server, args, port, opts, ...)` | `runStreamableHttp(server, opts)` after setting `opts.port` / `opts.bindAddresses` |
| `runClient(() @safe { ...; return 0; })` | `runWithEventLoop(() @safe { ... })` (`import mcp;`); it rethrows a failure instead of returning 1 |
| `connectFromArgs(args, "x-server")` | `McpClient.spawn(["./x-server"])` (stdio) or `McpClient.http(url)` |
| `check(cond, msg)` / `checkEq(a, b, label)` | your own assertions or error handling |

The examples also use fine-grained imports (`mcp.server.server`,
`mcp.api.attributes`, ...); in your own code `import mcp;` covers the public
API, plus `import mcp.transport;` for the transports and `import mcp.auth;` for
OAuth.
