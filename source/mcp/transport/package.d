/**
 * mcp.transport — opt-in transport wiring for the MCP SDK.
 *
 * `import mcp;` exposes only the curated public API (protocol types,
 * `McpServer` / `McpClient`, the UDA / reflection layer, and the error
 * builders). Server / client transport plumbing — stdio, Streamable HTTP,
 * the SSE channel, session management, the OAuth-proxy mount, and the draft
 * transport helpers — is brought in explicitly with `import mcp.transport;`.
 */
module mcp.transport;

public import mcp.transport.stdio;
public import mcp.transport.streamable_http;
public import mcp.transport.session;
public import mcp.transport.sse_context;
public import mcp.transport.oauth_proxy_mount;

// The draft module is predominantly transport-layer plumbing (header
// encoding, param-header extraction, request-state parsing, MRTR shapes),
// so it is reachable here rather than from the top-level surface.
public import mcp.protocol.modern;
