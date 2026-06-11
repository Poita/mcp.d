# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project is pre-1.0, so breaking changes may occur in any release.

## [Unreleased]

### Changed

- **UDA annotations now live on the method declaration, never inline on a
  parameter.** The two previously parameter-attached UDAs are gone:
  - `@describe` is replaced by the method-level, repeatable
    `@describeParam("paramName", "description")`. The old dual-shape `describe`
    struct (parameter-attached single-arg and method-level two-arg) is removed in
    favor of a single shape.
  - `@mcpHeader("Name")` (parameter-attached) becomes the method-level two-arg
    `@mcpHeader("paramName", "Name")`, mirroring the named tool parameter into the
    `Mcp-Param-<Name>` request header.
- **New compile-time validation:** a `@describeParam` or `@mcpHeader` whose
  `parameter` does not name an actual schema parameter of the annotated method is
  now a `static assert` failure (previously a mismatched method-level `@describe`
  silently matched nothing). Naming an injected context parameter (a trailing
  `RequestContext` / `TaskContext`, which has no schema property) is likewise a
  compile-time error.
