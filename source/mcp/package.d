/**
 * mcp — a production-grade Model Context Protocol SDK for D.
 *
 * Public entry point. Importing `mcp` re-exports the stable public API.
 * Re-exports grow as modules land (see docs/superpowers/plans).
 */
module mcp;

public import mcp.protocol.versions;
public import mcp.protocol.errors;
public import mcp.protocol.jsonrpc;
public import mcp.protocol.capabilities;
public import mcp.protocol.types;
public import mcp.protocol.draft;
public import mcp.server.context;
public import mcp.server.server;
public import mcp.api.attributes;
public import mcp.api.schema;
public import mcp.api.reflection;
public import mcp.transport.sse_context;
public import mcp.transport.streamable_http;
public import mcp.client.client;
