/**
 * mcp.transport — opt-in transport wiring for the MCP SDK.
 *
 * The bare `import mcp;` deliberately exposes only the curated, stable public
 * API (protocol types, `McpServer` / `McpClient`, the UDA / reflection layer,
 * and the error builders). Server / client transport plumbing — stdio,
 * Streamable HTTP, the SSE channel, session management, the OAuth-proxy mount,
 * and the draft transport helpers — lives here and is brought in explicitly
 * with `import mcp.transport;` (issue #301).
 */
module mcp.transport;

public import mcp.transport.stdio;
public import mcp.transport.streamable_http;
public import mcp.transport.session;
public import mcp.transport.sse_context;
public import mcp.transport.oauth_proxy_mount;

// The draft module is predominantly transport-layer plumbing (header
// encoding, param-header extraction, request-state parsing, MRTR shapes).
// It is reachable here rather than from the lean top-level surface.
public import mcp.protocol.draft;
