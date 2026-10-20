/**
 * mcp.transport — opt-in transport wiring for the MCP SDK.
 *
 * `import mcp;` exposes only the curated public API (protocol types,
 * `McpServer` / `McpClient`, the UDA / reflection layer, and the error
 * builders). Server / client transport plumbing — stdio, Streamable HTTP,
 * the SSE channel, session management, the OAuth-proxy mount, and 2026-07-28
 * transport helpers — is brought in explicitly with `import mcp.transport;`.
 */
module mcp.transport;

// The named server-side transport seam (`ServerCore`),
// symmetric to the client's `ClientTransport`. A custom server transport drives
// its `McpServer` through this interface; it lives here so it is reachable from
// the same import a transport author already pulls in.
public import mcp.server.transport;

public import mcp.transport.stdio;
public import mcp.transport.streamable_http;
public import mcp.transport.session;
public import mcp.transport.sse_context;
public import mcp.transport.oauth_proxy_mount;

// The modern transport plumbing — header encoding and param-header extraction
// (`mcp.protocol.http_headers`), `_meta` key validation
// (`mcp.protocol.meta_keys`), `subscriptions/listen` stamping
// (`mcp.protocol.subscriptions`), and MRTR shapes and request-state parsing
// (`mcp.protocol.mrtr`) — is reachable here rather than from the top-level
// surface.
public import mcp.protocol.mrtr;
public import mcp.protocol.meta_keys;
public import mcp.protocol.http_headers;
public import mcp.protocol.subscriptions;
