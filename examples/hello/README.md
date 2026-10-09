# Hello example (standalone server + client)

The smallest complete mcp.d server/client pair, and the one to copy when starting
a new project. Unlike the other examples it does **not** use the repo-only
`examples/common` scaffold: it depends on `mcp-d` alone and imports only `mcp`
(the public API) and `mcp.transport` (the stdio / Streamable HTTP runners).

- `server.d` registers one `@tool` (`greet`) and serves it over stdio, or over
  Streamable HTTP with `--http [--port N]` (default port 8540).
- `client.d` spawns `hello-server` over stdio, or connects to `--http <url>`,
  calls `greet`, prints the reply, and exits non-zero if it is wrong.

## Running it

```sh
# from this directory (examples/hello)
dub build -c server            # produces ./hello-server
dub run -c client              # stdio: spawns ./hello-server, prints "Hello, Ada!"

dub run -c server -- --http    # terminal 1: Streamable HTTP on 127.0.0.1:8540
dub run -c client -- --http http://127.0.0.1:8540/mcp   # terminal 2
```

## Using it outside this repository

Copy `server.d` / `client.d` and replace the path dependency in `dub.json` with
the git one from the top-level README's
[Installation](../../README.md#installation) section:

```json
"mcp-d": { "repository": "git+https://github.com/Poita/mcp.d.git", "version": "~main" }
```

To serve on a public interface (a container, a PaaS), also set
`opts.bindAddresses` and `opts.allowedHosts`; see [`deploy/`](../../deploy/README.md).
