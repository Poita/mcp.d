# MCP Skills example (server + client e2e), dual-transport

A self-contained example of the **`io.modelcontextprotocol/skills`** extension
(SEP-2640) in the D MCP SDK ([mcp.d](https://github.com/Poita/mcp.d)). A skill is
an Agent Skill — a `SKILL.md` of instructions plus optional supporting files —
served over the Resources primitive under `skill://` URIs. It is its own dub
package with path dependencies on the root `mcp-d` library and the shared
`examples/common` scaffold, so it never touches the root `dub.json`.

The single server binary speaks **stdio or Streamable HTTP**, and the single
client binary is a **self-verifying e2e test** that runs the same assertions over
either transport.

## What it teaches

**Server side (`server.d`)** — three ways to declare a skill, five entries in
total:

- **`@skill(name, description)`** — the method returns the `SKILL.md` body and
  the SDK synthesizes the frontmatter. Used for `git-workflow` and `code-review`.
- **`@skillDir("team/release-helper")`** — the method returns a local directory
  (`assets/release-helper/`); the SDK serves its authored `SKILL.md` and every
  file in the tree (here `references/CHECKLIST.md`). The directory also holds a
  nested skill, `hotfix-helper/SKILL.md`, published as its own flat entry.
- **`registerDynamicSkill`** — `reports/daily` renders its body on every read,
  so its entry carries `resources: "dynamic"` instead of a digest manifest.
- **`registerHandlers(server, new SkillsApi)`** registers the `@skill` and
  `@skillDir` methods in one call; the first skill registration advertises the
  extension and enables `resources/directory/read`.

**Client side (`client.d`)** enables the modern protocol (it calls
`server/discover`) and asserts:

1. `server/discover` advertises the skills extension with `directoryRead`, and
   `connect()` negotiates 2026-07-28.
2. `skills/list` (`client.skillsList().entries`) returns all five entries, each with a `SKILL.md`
   uri and, for static skills, a manifest listing `SKILL.md` first with `sha256`
   digests and byte sizes; the raw result carries `ttlMs`/`cacheScope`. The
   dynamic `reports/daily` reads a generated body but fails
   `verifySkillMarkdown`, since it offers no content integrity.
3. `readSkill(client, "git-workflow")` returns the synthesized frontmatter and
   body.
4. `team/release-helper` carries its authored frontmatter (`license`,
   `metadata.version`) and serves `references/CHECKLIST.md`.
5. `client.skillsGet(uri).entry` fetches entries by uri via `skills/get`; the fetched `SKILL.md`
   and checklist pass `verifySkillMarkdown` / `verifyResourceDigest`, and the
   nested `hotfix-helper` answers with its own frontmatter.
6. `client.readDirectory` walks `skill://team/release-helper`, listing `SKILL.md` as a
   file and `references/` as a subdirectory, then descends into it.

On success it prints `OK: ...` and exits `0`; any failed assertion prints what
differed and exits non-zero.

## Running it

The `@skillDir` path is resolved from the source file's location at compile
time, so run the server from a source checkout.

```sh
# from this directory (examples/skills)
dub build -c server      # produces ./skills-server
dub build -c client      # produces ./skills-client
```

### Over stdio (default)

```sh
./skills-client          # spawns ./skills-server and runs the e2e (exit 0 == pass)
```

### Over Streamable HTTP

```sh
# terminal 1
./skills-server --http --port 8645

# terminal 2
./skills-client --http http://127.0.0.1:8645/mcp
```

See the [Skills](../../README.md#skills) section of the root README for the
full API.
