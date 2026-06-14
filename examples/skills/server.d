/**
 * MCP Skills example server — dual-transport (stdio + Streamable HTTP).
 *
 * Demonstrates the SDK's ergonomic skill UDAs for SEP-2640 (the
 * `io.modelcontextprotocol/skills` extension). A skill is an Agent Skill — a
 * `SKILL.md` of instructions plus optional supporting files — served over the
 * existing Resources primitive.
 *
 * Two ways to declare a skill are shown:
 *
 *   - `@skill` — the method returns the `SKILL.md` body; the SDK synthesizes the
 *     frontmatter. Used for git-workflow and code-review (single-file skills).
 *   - `@skillDir` — the method returns a local directory path; the SDK reads the
 *     authored `SKILL.md`, exposes every file in the tree as a resource (so
 *     subdirectories are walkable via `resources/directory/read`), and packs the
 *     directory into the requested archive forms. Used for team/release-helper,
 *     served from `assets/release-helper/` with a `.zip` archive.
 *
 * Transport selection is delegated to `runServerFromArgs`:
 *   stdio (default):  ./skills-server
 *   http:             ./skills-server --http --port 8645
 */
module skills_server;

import std.path : dirName, buildPath;

import mcp;
import examples_common : runServerFromArgs;

/// The fixed HTTP port for this example.
enum ushort defaultPort = 8645;

/// Skills declared the ergonomic way. The two `@skill` methods return their
/// `SKILL.md` body; the `@skillDir` method returns a local directory whose files
/// and archive are served wholesale.
final class SkillsApi
{
	@skill("git-workflow", "Follow this team's Git branching and commit conventions")
	string gitWorkflow() @safe
	{
		return "# Git Workflow\n\n" ~ "1. Branch from `main`: `git switch -c feature/<topic>`.\n"
			~ "2. Commit in small, reviewable steps.\n"
			~ "3. Open a PR; squash-merge once approved.\n";
	}

	@skill("code-review", "Review a change for correctness, clarity, and test coverage")
	string codeReview() @safe
	{
		return "# Code Review\n\n" ~ "- Confirm the change has a test that fails without it.\n"
			~ "- Check error paths, not just the happy path.\n"
			~ "- Prefer the smallest change that is correct and clear.\n";
	}

	// Served from a real directory under an organizational prefix, with a .zip
	// archive form. `__FILE_FULL_PATH__` resolves the asset dir absolutely, so
	// the path holds regardless of the server's working directory.
	@skillDir("team/release-helper", ArchiveFormat.zip)
	string releaseHelper() @safe
	{
		return buildPath(dirName(__FILE_FULL_PATH__), "assets", "release-helper");
	}
}

void main(string[] args) @safe
{
	auto server = new McpServer("skills-example", "1.0.0");

	// One call registers all three skills: the two @skill methods and the
	// @skillDir directory (files + archive). The first registration also
	// advertises the skills extension, stands up skill://index.json, and enables
	// resources/directory/read.
	registerHandlers(server, new SkillsApi);

	runServerFromArgs(server, args, defaultPort);
}
