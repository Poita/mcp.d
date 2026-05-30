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
