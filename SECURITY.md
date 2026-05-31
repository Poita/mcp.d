# Security Policy

`dlang-mcp-sdk` (the D MCP SDK) implements the Model Context Protocol, including
OAuth 2.1 token handling, DNS-rebinding protection, and the Streamable HTTP
transport. Because it sits on the trust boundary between MCP clients and servers,
we take security reports seriously and ask that they be disclosed responsibly.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Instead, use one of the following private channels:

1. **GitHub private vulnerability reporting (preferred).** Open a private
   advisory via the repository's
   [Security Advisories](https://github.com/Poita/mcp.d/security/advisories/new)
   page. This keeps the report confidential until a fix is published.
2. **Email.** If you cannot use GitHub advisories, email the maintainer at
   **peter.alexander.au@gmail.com** with the subject line `SECURITY: mcp.d`.

Please include as much of the following as you can:

- A description of the vulnerability and its impact.
- The affected component (e.g. OAuth client, Streamable HTTP transport,
  stdio transport, a specific protocol version).
- Steps to reproduce or a proof-of-concept.
- The version / commit of the SDK you tested against.
- Any suggested remediation, if you have one.

## Response Expectations

We aim to handle reports on the following timeline (best-effort, as this is a
volunteer-maintained project):

| Stage                          | Target                  |
| ------------------------------ | ----------------------- |
| Acknowledge receipt            | within 3 business days  |
| Initial assessment / triage    | within 7 business days  |
| Status update cadence          | at least every 14 days  |
| Fix or mitigation for confirmed issues | as soon as practicable, prioritized by severity |

When a fix is ready we will coordinate a disclosure date with the reporter,
publish a GitHub Security Advisory, and credit the reporter unless they prefer
to remain anonymous.

## Supported Versions

Security fixes are applied to the latest release on the default branch. The SDK
implements the following MCP protocol revisions; the wire dates are listed for
reference:

| MCP protocol revision | Wire identifier | Status                    |
| --------------------- | --------------- | ------------------------- |
| `2024-11-05`          | `2024-11-05`    | Supported (legacy)        |
| `2025-03-26`          | `2025-03-26`    | Supported                 |
| `2025-06-18`          | `2025-06-18`    | Supported                 |
| `2025-11-25`          | `2025-11-25`    | Supported (latest stable) |
| `draft`               | `2026-07-28`    | Supported (experimental)  |

Only the most recent commit on the default branch (`main`) receives security
updates. Users are encouraged to track `main` and update promptly when an
advisory is published.

## Scope

This policy covers the code in this repository. Vulnerabilities in upstream
dependencies (for example, [vibe-d](https://vibed.org)) should be reported to
their respective maintainers, though we appreciate a heads-up so we can pin or
patch as needed.
