# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project is pre-1.0 and makes no backward-compatibility guarantees yet.

## [Unreleased]

### Changed

- Renamed the dynamic (raw-`Json`) server registration methods to drop the
  `Dynamic` prefix, since they are the primary escape hatch and the un-prefixed
  resource/template/task registrations already omit it:

  | Old name                | New name          |
  | ----------------------- | ----------------- |
  | `registerDynamicTool`   | `registerTool`    |
  | `registerDynamicPrompt` | `registerPrompt`  |

  `registerResource`, `registerResourceTemplate`, and `registerTaskTool` are
  unchanged.
