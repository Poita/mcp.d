# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Removed

- **Client typed-argument request overloads.** `McpClient.callTool(T)(string,
  T args, …)` and `McpClient.getPrompt(T)(string, T args, …)` are gone. The
  client request surface is now untyped (`Json` arguments only). MCP clients
  forward LLM-produced JSON arguments, so typed argument structs only ever served
  tests and silently mis-serialized enum fields (numeric ordinal vs. the
  schema-declared string member name). Result-side typed decoding
  (`structuredContentAs!T`, etc.) is retained. See `DESIGN.md`.
