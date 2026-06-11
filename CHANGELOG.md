# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Changed

- **`CallToolResult.structuredContentAs!T` now throws on a missing/non-object
  `structuredContent`** (`McpException(invalidParams)`) instead of returning
  `T.init`. Asking for a typed structured result asserts the tool produces one, so
  an absent payload is a contract violation rather than a silently-empty struct.

### Added

- **`McpClient.connect(DiscoverResult prior)`** — a zero-round-trip reconnect that
  runs the same version selection as `connect()` over a previously obtained
  `server/discover` result, without any network probe. On a modern (draft) version
  it adopts the prior capabilities/serverInfo/instructions directly; on a stable
  version it runs a single `initialize` handshake.
- **`McpClient.discoverResult()`** — the most recent `DiscoverResult` the client
  obtained or adopted (`discover()`, `connect()`'s probe, or
  `connect(DiscoverResult)`), so callers can persist it (it round-trips via
  `toJson`/`fromJson`) and feed it back for the zero-RTT reconnect.
- **Test coverage for the typed list-change observers** (`onToolsListChanged`,
  `onPromptsListChanged`, `onResourcesListChanged`, `onResourceUpdated`):
  exercises the `prompts/list_changed` callback, confirms each typed observer
  fires *in addition to* the generic `onNotification`, and that a
  `resources/updated` with no `uri` fires no typed observer.
- **`CallToolResult.ensureOk()`** — returns normally on a success result; on an
  error result throws `McpException(internalError)` whose message surfaces the
  first text content block (or a generic message when there is none). Turns a
  tool's in-band error result into an exception at the call site.

### Removed

- **Client typed-argument request overloads.** `McpClient.callTool(T)(string,
  T args, …)` and `McpClient.getPrompt(T)(string, T args, …)` are gone. The
  client request surface is now untyped (`Json` arguments only). MCP clients
  forward LLM-produced JSON arguments, so typed argument structs only ever served
  tests and silently mis-serialized enum fields (numeric ordinal vs. the
  schema-declared string member name). Result-side typed decoding
  (`structuredContentAs!T`, etc.) is retained. See `DESIGN.md`.
