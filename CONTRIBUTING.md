# Contributing to dlang-mcp-sdk

Thanks for your interest in contributing to the D
[Model Context Protocol](https://modelcontextprotocol.io) SDK! This guide covers
local setup, the build/test/lint commands, the project conventions you are
expected to follow, and the pull-request flow.

## Prerequisites

- A D toolchain with frontend **2.100+** — DMD 2.100+, or LDC 1.30+ — and
  [`dub`](https://dub.pm) (ships with the compiler).
- **OpenSSL 3.x** on the system. The `openssl` / `vibe-d:tls` dependency links
  against it for TLS (HTTPS transport, OAuth 2.1).
  - **Ubuntu/Debian:** ships with OpenSSL 3.x (`apt install libssl-dev` if the
    headers are missing).
  - **macOS:** `brew install openssl@3`, then export
    `PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"` so dub can find
    it.
- [Node.js / `npx`](https://nodejs.org) — only needed to run the official
  conformance suite (see below).

## Dev setup

Clone the repo and pull the dependencies (dub does this automatically on the
first build):

```bash
git clone https://github.com/Poita/mcp.d.git
cd mcp.d
ulimit -n 65536        # see the gotcha below — do this in every shell
dub build              # build the library; downloads deps on first run
```

### The `ulimit -n` gotcha

Always run `ulimit -n 65536` before `dub` in a shell. Some terminals (notably
**ghostty**) set `ulimit -n unlimited`, under which the D toolchain — which
opens many files at once — misbehaves and builds/tests fail in confusing ways.
Setting an explicit, finite descriptor limit fixes it. The conformance and
lint scripts already raise the limit internally, but interactive `dub build` /
`dub test` invocations do not, so set it yourself.

## Build, test, and lint commands

```bash
ulimit -n 65536                          # required (see gotcha above)

dub build                                # build the library
dub test                                 # run all unit tests (every module must pass)

dub run dfmt -- --inplace source/        # format the source in place
dub run dfmt -- --inplace source/ conformance/   # format source + conformance (matches CI)
dub run dscanner -- --styleCheck source/ # static analysis / style lint
./scripts/dscanner-lint.sh               # the exact lint gate CI runs (with documented filters)
```

If you have [`just`](https://just.systems) installed, the repo's `justfile`
wraps these (and the conformance suites) as one-word recipes — each sets the
`ulimit -n 65536` for you:

```bash
just            # list all recipes
just build      # dub build
just test       # dub test
just fmt        # dub run dfmt -- --inplace source/ conformance/
just lint       # ./scripts/dscanner-lint.sh
just conformance-server   # build + run the server conformance suite
just conformance-client   # build + run the client conformance suite
just conformance          # both suites
```

CI (`.github/workflows/ci.yml`) runs three gates on every push and PR, and your
change must pass all of them:

1. **dfmt format check** — `dub run dfmt -- --inplace source/ conformance/`
   followed by `git diff --exit-code` (dfmt has no `--check` flag, so the idiom
   is format-in-place then fail if the tree changed). Run dfmt before you commit.
2. **dscanner lint** — `./scripts/dscanner-lint.sh`. The dub config lives in
   `dscanner.ini`; the wrapper documents the one libdparse false-positive that
   is filtered out.
3. **build-and-test** — `dub build` + `dub test` on `{ldc-latest, dmd-latest}` ×
   `{ubuntu-latest, macos-latest}`.

### API documentation

API docs are generated from the ddoc comments in `source/mcp`:

```bash
scripts/gen-docs.sh        # auto: adrdox if on PATH, else dub's ddox -> docs/
```

`.github/workflows/docs.yml` builds the docs on every push/PR so doc generation
cannot silently break. The generated `docs/` directory is a git-ignored build
artifact.

## Project conventions

These conventions are enforced by review (and some by CI). Please follow them:

- **Write a failing test first.** Before fixing a bug or adding a feature, add a
  unit test that fails for the right reason, watch it fail, then write the
  minimal code to make it pass (TDD).
- **One test per `unittest` block.** Put each test case in its own `unittest`
  block rather than batching many assertions into one large block. This keeps
  failures isolated and readable.
- **Commit per change.** Make small, focused commits — one logical change (or
  bug fix) per commit — rather than large mixed commits.
- **Format and lint before committing.** Run `dub run dfmt -- --inplace source/`
  (and `conformance/` if you touched it) and `./scripts/dscanner-lint.sh` so the
  CI format/lint gates stay green.
- **Match the MCP spec exactly.** Field names, JSON shapes, and error codes must
  match the authoritative schema for the relevant protocol version. **Draft-only
  behavior must apply only when the negotiated protocol version is `draft`** — it
  must not change the wire output of released versions (`2025-11-25`,
  `2025-06-18`, …). Don't regress the conformance baseline (**server 38/38**,
  **client 287/287**).
- **Keep new public API reachable.** Anything new and public should be exported
  via `source/mcp/package.d` and usable from `McpServer` / `McpClient` /
  `RequestContext` (or the UDA layer), with a runnable path for callers.
- **Use `std.getopt`** for any command-line argument parsing.

## Running the conformance suite locally

The SDK is validated against the official
[`@modelcontextprotocol/conformance`](https://www.npmjs.com/package/@modelcontextprotocol/conformance)
suite. There are two harnesses — one tests our server, one tests our client.

### Server conformance

```bash
ulimit -n 65536
dub build -c conformance-server
./conformance-server --port 3000 &
npx @modelcontextprotocol/conformance server --url http://127.0.0.1:3000/mcp
```

### Client conformance

The client harness launches our `conformance-client` binary, appends the test
server URL to its command line, and selects the scenario via the
`MCP_CONFORMANCE_SCENARIO` environment variable:

```bash
ulimit -n 65536
dub build -c conformance-client
npx @modelcontextprotocol/conformance client --command "./conformance-client"
```

The conformance entry points live in `conformance/server.d` and
`conformance/client.d`.

## Pull-request flow

1. **Branch off the latest `main`.** Name the branch for the change, e.g.
   `fix/issue-167` or `feat/<short-description>`.
2. **Develop with TDD** following the conventions above. Keep the change focused
   on a single issue/feature.
3. **Run the gates locally** before pushing:
   ```bash
   ulimit -n 65536
   dub run dfmt -- --inplace source/ conformance/
   dub test
   ./scripts/dscanner-lint.sh
   ```
   All unit tests must pass and the format/lint gates must be clean.
4. **Update `CHANGELOG.md`** under `## [Unreleased]` when your change is
   user-visible (new feature, fix, or behavior change).
5. **Commit** with a clear message; reference the issue (e.g. `Closes #167`) in
   the body where applicable.
6. **Open a PR against `main`.** Describe what changed, the spec rule or behavior
   it matches, and the test that covers it. CI must be green before merge.

## License

By contributing you agree that your contributions are licensed under the project's
[Apache License 2.0](LICENSE).
