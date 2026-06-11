# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project is pre-1.0 and makes no backward-compatibility guarantees yet.

## [Unreleased]

### Changed

- `McpServer.enableResourceSubscriptions()` now **throws** on a stateless server
  instead of silently doing nothing: the message names `McpServer.stateful()` as
  the remedy. The draft `subscriptions/listen` resource-update push still works on
  a stateless server — it is driven by each listen stream's own per-URI filter and
  does not need (or use) `enableResourceSubscriptions()`.
- Stateless-mode runtime rejections now name the remedy in their message/`data`:
  the server->client gates (`elicit`/`sample`/`elicitUrl`/`listRoots`) name both
  `ToolResponse.inputRequired` (MRTR) and `McpServer.stateful()`; `resources/
  subscribe`/`unsubscribe` and `logging/setLevel` -32601s carry a `data.reason`
  naming `McpServer.stateful()`; and the standalone GET stream 405 names it in its
  body on a stateless server. Error codes are unchanged.
- Renamed the dynamic (raw-`Json`) server registration methods to drop the
  `Dynamic` prefix, since they are the primary escape hatch and the un-prefixed
  resource/template/task registrations already omit it:

  | Old name                | New name          |
  | ----------------------- | ----------------- |
  | `registerDynamicTool`   | `registerTool`    |
  | `registerDynamicPrompt` | `registerPrompt`  |

  `registerResource`, `registerResourceTemplate`, and `registerTaskTool` are
  unchanged.
