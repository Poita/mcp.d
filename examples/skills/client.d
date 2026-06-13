/**
 * MCP Skills example client + self-verifying e2e test — dual-transport.
 *
 * Drives the `skills-example` server over EITHER transport with IDENTICAL
 * assertions, using the shared examples/common scaffold:
 *   - STDIO (default): spawns the sibling `skills-server` binary.
 *   - HTTP (`--http <url>`): connects to a running server via Streamable HTTP.
 *
 * Exercises the SEP-2640 skills flow. Because SEP-2640 adds no new methods,
 * everything here is plain Resources access wrapped in skill-aware helpers:
 *
 *   1. server/discover advertises the skills extension under `capabilities`.
 *   2. listSkills() reads skill://index.json and returns the discovery entries.
 *   3. readSkill("git-workflow") reads skill://git-workflow/SKILL.md and the
 *      synthesized frontmatter carries the name/description.
 *   4. The imperatively-registered pdf-forms skill exposes its sibling
 *      references/FORMS.md as its own resource.
 *
 * The extensions negotiation map is draft-only, so the client enables the draft
 * protocol (`enableModern`) before negotiation — exactly as the tasks example
 * does. The resource reads themselves work on any protocol version.
 */
module skills_client;

import std.algorithm : canFind, map;
import std.array : array;
import std.stdio : writeln;

import vibe.data.json : Json;

import mcp;
import examples_common : check, checkEq, runClient, connectFromArgs;

int main(string[] args) @safe
{
	return runClient(() @safe {
		auto client = connectFromArgs(args, "skills-server");
		scope (exit)
			client.close();

		// The extensions negotiation map is draft-only: switch to the draft
		// protocol before version negotiation so the skills extension is visible.
		client.enableModern();

		// --- 1. server/discover: skills extension must be advertised --------
		auto disc = client.discover();
		checkEq(disc.serverInfo.name, "skills-example", "discover.serverInfo.name");
		auto caps = disc.capabilities.toJson();
		check("extensions" in caps && caps["extensions"].type == Json.Type.object,
			"discover should include extensions in capabilities");
		check((skillsExtensionKey in caps["extensions"]) !is null,
			"discover capabilities.extensions should contain the skills extension key");

		auto negotiated = client.connect();
		checkEq(negotiated, ProtocolVersion.modern, "connect() should negotiate draft");

		// --- 2. listSkills(): the index enumerates every registered skill ---
		auto skills = listSkills(client);
		auto names = skills.map!(s => s.name).array;
		checkEq(skills.length, 3, "index should list three skills");
		check(names.canFind("git-workflow"), "index should list git-workflow");
		check(names.canFind("code-review"), "index should list code-review");
		check(names.canFind("pdf-forms"), "index should list pdf-forms");
		foreach (s; skills)
		{
			checkEq(s.type, "skill-md", "every entry should be a skill-md");
			check(s.url == skillUri(s.name), "entry url should be skill://<name>/SKILL.md");
		}

		// --- 3. readSkill(): SKILL.md carries synthesized frontmatter -------
		auto md = readSkill(client, "git-workflow");
		check(md.canFind("name: git-workflow"), "SKILL.md frontmatter should carry the name");
		check(md.canFind("description: \"Follow this team's Git"),
			"SKILL.md frontmatter should carry the description");
		check(md.canFind("# Git Workflow"), "SKILL.md should carry the instructions body");

		// --- 4. a multi-file skill exposes its supporting files -------------
		auto forms = client.readResource("skill://pdf-forms/references/FORMS.md");
		check(forms.contents.length > 0, "the supporting file should be readable");
		check(forms.contents[0].text.canFind("applicant_name"),
			"references/FORMS.md should carry the field reference");

		bool http;
		foreach (arg; args)
			if (arg == "--http" || arg == "--url")
				http = true;
		writeln("OK: skills example e2e passed over ", http ? "http" : "stdio",
			" — skills extension advertised, index lists git-workflow/code-review/pdf-forms,",
			" SKILL.md frontmatter synthesized, supporting references/FORMS.md served.");
		return 0;
	});
}
