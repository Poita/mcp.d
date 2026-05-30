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

Under active development. **Foundation in place**: protocol version negotiation, JSON-RPC
2.0 framing/batching, and typed error handling. See
[`docs/superpowers/plans`](docs/superpowers/plans) for the staged build.

## Build & test

```bash
ulimit -n 65536        # required: dub misbehaves under ghostty's `ulimit -n unlimited`
dub build              # build the library
dub test               # run all unittests
```

Formatting and linting:

```bash
dub run dfmt -- --inplace source/
dub run dscanner -- --styleCheck source/
```

## License

MIT — see [LICENSE](LICENSE).
