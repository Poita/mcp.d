/**
 * MCP Skills example client + self-verifying e2e test — dual-transport.
 *
 * Drives the `skills-example` server over EITHER transport with IDENTICAL
 * assertions, using the shared examples/common scaffold:
 *   - STDIO (default): spawns the sibling `skills-server` binary.
 *   - HTTP (`--http <url>`): connects to a running server via Streamable HTTP.
 *
 * Exercises the SEP-2640 skills flow. Because SEP-2640 rides on the Resources
 * primitive, everything here is plain Resources access wrapped in skill-aware
 * helpers:
 *
 *   1. server/discover advertises the skills extension under `capabilities`.
 *   2. listSkills() reads skill://index.json and returns conformant entries
 *      (verbatim frontmatter, SKILL.md url + sha256 digest, archives).
 *   3. readSkill("git-workflow") reads skill://git-workflow/SKILL.md and the
 *      synthesized frontmatter carries the name/description.
 *   4. The prefixed office/pdf-forms skill exposes its sibling
 *      references/FORMS.md and a .tar.gz archive form, both addressable.
 *
 * The extensions negotiation map is draft-only, so the client enables the draft
 * protocol (`enableModern`) before negotiation — exactly as the tasks example
 * does. The resource reads themselves work on any protocol version.
 */
module skills_client;

import std.algorithm : canFind, filter, map;
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
		check(names.canFind("pdf-forms"), "index should list pdf-forms (final path segment)");
		// Every direct entry carries a SKILL.md url and a sha256:<hex> digest.
		foreach (s; skills)
		{
			check(s.url.length > 0, "entry should carry a SKILL.md url");
			check(s.digest.canFind("sha256:"), "entry should carry a sha256 digest");
		}

		// --- 3. readSkill(): SKILL.md carries synthesized frontmatter -------
		auto md = readSkill(client, "git-workflow");
		check(md.canFind("name: git-workflow"), "SKILL.md frontmatter should carry the name");
		check(md.canFind("description: \"Follow this team's Git"),
			"SKILL.md frontmatter should carry the description");
		check(md.canFind("# Git Workflow"), "SKILL.md should carry the instructions body");

		// --- 4. the prefixed multi-file skill: supporting file + archive ----
		auto pdf = skills.filter!(s => s.name == "pdf-forms").front;
		check(pdf.url == "skill://office/pdf-forms/SKILL.md",
			"pdf-forms should be served under its office/ prefix");

		auto forms = client.readResource("skill://office/pdf-forms/references/FORMS.md");
		check(forms.contents.length > 0, "the supporting file should be readable");
		check(forms.contents[0].text.canFind("applicant_name"),
			"references/FORMS.md should carry the field reference");

		// The archive form is listed in the index and readable as a blob.
		check(pdf.archives.length == 1, "pdf-forms should list one archive form");
		checkEq(pdf.archives[0].mimeType, "application/gzip", "archive mimeType");
		check(pdf.archives[0].digest.canFind("sha256:"), "archive should carry a digest");
		auto archive = client.readResource(pdf.archives[0].url);
		check(archive.contents.length > 0 && archive.contents[0].blob.length > 0,
			"the archive resource should be readable as a blob");

		bool http;
		foreach (arg; args)
			if (arg == "--http" || arg == "--url")
				http = true;
		writeln("OK: skills example e2e passed over ", http
			? "http" : "stdio",
			" — skills extension advertised; index lists git-workflow/code-review/pdf-forms",
			" with verbatim frontmatter + sha256 digests; SKILL.md frontmatter synthesized;",
			" prefixed office/pdf-forms serves references/FORMS.md and a .tar.gz archive.");
		return 0;
	});
}
