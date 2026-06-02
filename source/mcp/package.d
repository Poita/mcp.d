/**
 * mcp — a production-grade Model Context Protocol SDK for D.
 *
 * Importing `mcp` re-exports the curated, stable public API:
 *
 *   - the protocol types (`mcp.protocol.*`: versions, errors, JSON-RPC,
 *     capabilities, core types, sampling),
 *   - the server / client entry points (`McpServer`, `McpClient`,
 *     `RequestContext`),
 *   - the declarative UDA / reflection layer (`@tool`, `@resource`,
 *     `@prompt`, `registerModule`, schema generation), and
 *   - the error builders (`McpException`, `ErrorCode`, `toErrorJson`,
 *     `makeErrorResponse`).
 *
 * Transport wiring and auth plumbing are deliberately kept out of the
 * top-level surface to avoid name collisions and to signal stable-public-API
 * vs internal plumbing. Bring them in explicitly when needed:
 *
 *   - `import mcp.transport;` — stdio / Streamable HTTP / SSE / session /
 *     OAuth-proxy mount / draft transport helpers,
 *   - `import mcp.auth;`      — token verifiers / OAuth client / login /
 *     resource-server / OAuth proxy.
 */
module mcp;

// --- Protocol types ---
public import mcp.protocol.versions;
public import mcp.protocol.errors;
public import mcp.protocol.jsonrpc;
public import mcp.protocol.capabilities;
public import mcp.protocol.types;
public import mcp.protocol.sampling;

// --- Server / client entry points ---
public import mcp.server.context;
public import mcp.server.server;
public import mcp.client.client;
public import mcp.client.subscription;

// --- Declarative UDA / reflection API ---
public import mcp.api.attributes;
public import mcp.api.schema;
public import mcp.api.reflection;

// --- User-facing draft (next-version) result/hint types ---
// These are referenced by members already on the lean public surface:
// `McpServer.setListCacheHint(string, CacheHint)` and `McpClient.discover()`
// returning `DiscoverResult`. Re-export the user-facing result/hint types
// (but not the transport/wire plumbing that also lives in
// `mcp.protocol.draft`) so they are usable with `import mcp;` alone.
public import mcp.protocol.draft : DiscoverResult, CacheHint, CacheScope, RequestMeta;
