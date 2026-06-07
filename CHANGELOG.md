# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- **The experimental 2025-11-25 tasks feature is not supported.** The stopgap
  `tasks` surface from the 2025-11-25 core spec (top-level `tasks` capability,
  `tasks/list`, `tasks/result`, per-tool `execution.taskSupport` / the
  `@toolExecution` UDA, and the per-request `task` parameter) was removed; the
  spec replaced it with the SEP-2663 extension below. Those methods now answer
  `-32601`.

### Added

- **MCP Tasks extension** (`io.modelcontextprotocol/tasks`, SEP-2663) for
  asynchronous `tools/call` execution, draft protocol only: `enableTasks`
  advertises the extension and serves `tasks/get` / `tasks/update` /
  `tasks/cancel` against a pluggable `TaskStore` (in-memory default). A
  `TaskRuntime` drives the task lifecycle (create / progress / complete / fail /
  input-required / cancel), a pluggable `TaskIdGenerator` mints unguessable IDs,
  and status changes are pushed as `notifications/tasks`.
- Full MCP protocol-version support across every revision with negotiation:
  `2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`, and `draft`
  (`2026-07-28`). Mutual-version selection picks the newest version both peers
  support.
- Both transports: **stdio** and **Streamable HTTP**, including the legacy
  HTTP+SSE (`2024-11-05`) two-endpoint fallback and SSE resumability via
  `Last-Event-ID` / `retry:`.
- FastMCP-style ergonomic server API via D attributes (`@tool`, `@resource`,
  `@prompt`) with automatic JSON-Schema generation.
- **OAuth 2.1** client suite: token-endpoint auth (`none` / `basic` / `post` /
  `private_key_jwt` ES256), authorization-server metadata discovery (all
  variants plus `2025-03-26` backward compatibility and endpoint fallback),
  scope selection / step-up / retry-limit, offline-access, Dynamic Client
  Registration (DCR), pre-registration, resource-mismatch handling, and
  cross-app access (token-exchange to JWT-bearer).
- **DRAFT (`2026-07-28`)** support, applied only when the negotiated protocol
  version is `draft` so it never changes `2025-11-25` / `2025-06-18` wire
  output: stateless per-request `_meta`, `server/discover` with
  `supportedVersions`, `subscriptions/listen`, `CacheableResult`
  (`ttlMs` / `cacheScope`), MRTR (multiple-response-type) types, the standard
  request headers (`Mcp-Method` / `Mcp-Name` / `MCP-Protocol-Version`) with
  `HeaderMismatch` validation, and `x-mcp-header` mirroring — on both client
  and server.
- Full protocol-utility coverage: tools with every content type, resources +
  templates + subscribe, prompts, completion, logging, progress/logging
  streaming, sampling, and elicitation (incl. SEP-1034 / SEP-1330).
- DNS-rebinding protection for the Streamable HTTP transport.
- Validation against the official `@modelcontextprotocol/conformance` suite:
  **server 39/39** and **client 287/287** passing.

### Fixed

- First audit-driven fix wave: spec-conformance corrections to message shapes,
  error codes, and field names across the protocol layer surfaced by the
  conformance suite.
- Second audit-driven fix wave: pre-production readiness fixes covering
  transport edge cases, version negotiation, and OAuth flow corner cases.

[Unreleased]: https://github.com/Poita/mcp.d/commits/main
