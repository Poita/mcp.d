# MCP Apps example (server + client e2e), dual-transport

A self-contained example of the **MCP Apps** extension (interactive UI a host
renders inline) in the D MCP SDK ([mcp.d](https://github.com/Poita/mcp.d)). It
is its own dub package with path dependencies on the root `mcp-d` library and the
shared `examples/common` scaffold, so it never touches the root `dub.json`.

On the server side, MCP Apps is metadata plus a resource convention: a tool
links to a `ui://` HTML resource, the host fetches that resource and renders it
sandboxed, and the rendered app talks to the host over a postMessage bridge that
never reaches the server. The single server binary speaks **stdio or Streamable
HTTP**, and the single client binary is a **self-verifying e2e test** that runs
the same assertions over either transport.

## What it teaches

**Server side (`server.d`)**:

- **`@tool` + `@ui(...)`** — `get_weather` is a module-level `@tool` whose
  `@ui("ui://weather/dashboard", "model", "app")` records the linked resource
  and its visibility roles in the tool's `_meta.ui`.
- **Typed structured output** — the tool returns a `Weather` struct, so the SDK
  infers the output schema and emits `structuredContent` the host can feed into
  the rendered app.
- **`registerUiResource`** publishes the `ui://weather/dashboard` HTML with the
  `text/html;profile=mcp-app` MIME type (`mcpAppMimeType`) and a `_meta.ui`
  built from `UiResourceOptions.meta` (a `UiResourceMeta`): a CSP `connectDomains` allowlist and the
  `prefersBorder` hint.
- **`enableApps(server)`** declares the extension capability, surfaced to modern
  clients in the `extensions` map.
- **`registerModule!(apps_server)(server)`** registers every module-level
  `@tool` in one call; `runServerFromArgs` picks the transport.

**Client side (`client.d`)** asserts:

- `tools/list`: `get_weather` carries `_meta.ui.resourceUri ==
  "ui://weather/dashboard"` and `_meta.ui.visibility == ["model", "app"]`;
- `resources/list`: the `ui://` resource uses the app MIME type and carries
  `_meta.ui.prefersBorder`;
- `resources/read`: one content block with the app MIME type, the HTML body, and
  the `_meta.ui.csp.connectDomains` hint;
- `get_weather("Paris")` returns structured content decoded with
  `structuredContentAs!WeatherOutput`.

On success it prints `OK: ...` and exits `0`; any failed assertion prints what
differed and exits non-zero.

## Running it

```sh
# from this directory (examples/apps)
dub build -c server      # produces ./apps-server
dub build -c client      # produces ./apps-client
```

### Over stdio (default)

```sh
./apps-client            # spawns ./apps-server and runs the e2e (exit 0 == pass)
```

### Over Streamable HTTP

```sh
# terminal 1
./apps-server --http --port 8538

# terminal 2
./apps-client --http http://127.0.0.1:8538/mcp
```
