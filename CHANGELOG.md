# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `runWithEventLoop` (`mcp.client.runner`, re-exported from `mcp`): a scoped
  entry affordance that runs an `McpClient` scenario inside a fresh vibe event
  loop, returns the scenario's value, and rethrows any exception on the caller's
  side. Use it from non-vibe processes whose MCP work has a scoped lifetime (CLI
  tools, batch jobs, tests). A "Concurrency model" section in the README documents
  the fiber-blocking (Go-style) verb model and records the deliberate decision not
  to ship a cross-thread synchronous wrapper.

### Changed

- The README's "Event-loop model" section is replaced by a fuller "Concurrency
  model" section; `examples_common.runClient` now delegates to `runWithEventLoop`.
