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
public import mcp.server.server;
