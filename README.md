# dlang-mcp-sdk

A production-grade [Model Context Protocol](https://modelcontextprotocol.io) (MCP) SDK for
the D programming language — client and server, built on [vibe-d](https://vibed.org).

## Goals

- Full MCP support across every protocol version (`2024-11-05` → `draft`) with negotiation.
- Both transports: **stdio** and **Streamable HTTP**.
- FastMCP-style ergonomic server API via D attributes (`@tool`, `@resource`, `@prompt`).
- Batteries included: OAuth 2.1, SSE resumability, all protocol utilities.
- Validated against the official `@modelcontextprotocol/conformance` suite.

## Status

Active development. **22 of 30** official server conformance scenarios pass today
(lifecycle, tools with every content type, resources, resource templates, prompts,
completion, logging, and DNS-rebinding protection). See the roadmap below.

```
✓ server-initialize        ✓ tools-call-image          ✓ resources-list
✓ ping                     ✓ tools-call-audio          ✓ resources-read-text
✓ tools-list               ✓ tools-call-embedded-…     ✓ resources-read-binary
✓ tools-call-simple-text   ✓ tools-call-mixed-content  ✓ resources-templates-read
✓ tools-call-error         ✓ completion-complete       ✓ prompts-list / get (×4)
✓ logging-set-level        ✓ dns-rebinding-protection
```

## Build & test

```bash
ulimit -n 65536        # required: dub misbehaves under ghostty's `ulimit -n unlimited`
dub build              # build the library
dub test               # run all unit tests (7 modules)
```

Formatting and linting:

```bash
dub run dfmt -- --inplace source/
dub run dscanner -- --styleCheck source/
```

## Example: a Streamable HTTP server

```d
import mcp;
import std.typecons : nullable;
import vibe.data.json : Json;

void main()
{
    auto server = new MCPServer("my-server", "1.0.0");

    // A tool.
    Tool add = {name: "add", description: nullable("Add two integers")};
    server.registerTool(add, (Json args) @safe {
        CallToolResult r;
        r.content = [Content.makeText("sum computed")];
        r.structuredContent = Json(["result": Json(args["a"].get!int + args["b"].get!int)]);
        return r;
    });

    // A resource.
    Resource readme = {uri: "file:///readme", name: "README", mimeType: nullable("text/plain")};
    server.registerResource(readme,
        () @safe => ResourceContents.makeText("file:///readme", "text/plain", "Hello!"));

    // A prompt.
    Prompt greet = {name: "greet", description: nullable("Greeting prompt")};
    server.registerPrompt(greet, (Json args) @safe {
        GetPromptResult res;
        res.messages = [PromptMessage("user", Content.makeText("Say hello"))];
        return res;
    });

    runStreamableHttp(server, 3000);   // serves POST/GET/DELETE at /mcp
}
```

## Running the conformance suite

```bash
dub build -c conformance-server
./conformance-server --port 3000 &
npx @modelcontextprotocol/conformance server --url http://127.0.0.1:3000/mcp
```

## Architecture

```
source/mcp/
  protocol/   versions  errors  jsonrpc  capabilities  types
  transport/  streamable_http   (stdio + SSE streaming: planned)
  server/     server            (transport-agnostic dispatch core)
```

`MCPServer` is a transport-agnostic JSON-RPC dispatch core (`handle` / `handleRaw`);
transports are thin drivers over it. All wire types serialize through presence-aware
`toJson`/`fromJson` so optional fields are omitted, not nulled.

## Roadmap

The remaining conformance scenarios require the **server→client streaming channel** over
SSE, plus follow-on features:

- [ ] Streamable HTTP SSE upgrade + per-request `Context` (progress / logging notifications)
- [ ] Server→client requests: **sampling**, **elicitation**
- [ ] Resource **subscribe / unsubscribe** + `resources/updated` notifications
- [ ] SSE resumability (`Last-Event-ID` + event store), session management
- [ ] stdio transport + `MCPClient` (with auto-pagination)
- [ ] FastMCP-style UDA layer (`@tool`/`@resource`/`@prompt` + auto JSON-Schema)
- [ ] OAuth 2.1 (server token validation + client flows)

See `docs/superpowers/specs` and `docs/superpowers/plans` for the design and staged plans.

## License

MIT — see [LICENSE](LICENSE).
