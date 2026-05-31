## Summary

<!-- What does this PR change, and why? Reference the issue, e.g. "Closes #123". -->

Closes #

## Spec rule / behavior

<!-- The MCP spec rule, field/shape/error code, or behavior this matches. Cite the
     authoritative schema (schema.ts line) or modelcontextprotocol.io section where
     relevant. For draft-only changes, confirm released-version wire output is unchanged. -->

## Checklist

- [ ] **Tests added** — a failing test was written first (TDD), one case per `unittest` block.
- [ ] **`dub test` passes** — all modules green locally (`ulimit -n 65536 && dub test`).
- [ ] **`dfmt` clean** — ran `dub run dfmt -- --inplace source/ conformance/`; `git diff --exit-code` is clean.
- [ ] **`dscanner` clean** — ran `./scripts/dscanner-lint.sh`.
- [ ] **Conformance unaffected** — server **38/38** and client **287/287** baseline not regressed.
- [ ] **Draft-only behavior gated** — any draft-only change does NOT alter `2025-11-25` / `2025-06-18` wire output.
- [ ] **Public API reachable** — new public API is exported via `source/mcp/package.d` and usable from `McpServer` / `McpClient` / `RequestContext` (or the UDA layer).
- [ ] **`CHANGELOG.md` updated** under `## [Unreleased]` if the change is user-visible.
