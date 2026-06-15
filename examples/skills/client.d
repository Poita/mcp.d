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
 *   3. readSkill("git-workflow") reads a @skill skill: synthesized frontmatter.
 *   4. The @skillDir-sourced team/release-helper skill carries its AUTHORED
 *      frontmatter, a references/CHECKLIST.md file, and a .zip archive form.
 *   5. resources/directory/read scope-lists the release-helper tree: files plus
 *      subdirectories (marked inode/directory), descended one level at a time.
 *
 * The extensions negotiation map is draft-only, so the client enables the draft
 * protocol (`enableModern`) before negotiation. The resource reads themselves
 * work on any protocol version.
 */
module skills_client;

import std.algorithm : any, canFind, filter, map;
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
		check(caps["extensions"][skillsExtensionKey]["directoryRead"].get!bool,
			"the skills capability should advertise directoryRead");

		auto negotiated = client.connect();
		checkEq(negotiated, ProtocolVersion.modern, "connect() should negotiate draft");

		// --- 2. listSkills(): the index enumerates every registered skill ---
		auto skills = listSkills(client);
		auto names = skills.map!(s => s.name).array;
		checkEq(skills.length, 3, "index should list three skills");
		check(names.canFind("git-workflow"), "index should list git-workflow");
		check(names.canFind("code-review"), "index should list code-review");
		check(names.canFind("release-helper"), "index should list release-helper");
		foreach (s; skills)
		{
			check(s.url.length > 0, "entry should carry a SKILL.md url");
			check(s.digest.canFind("sha256:"), "entry should carry a sha256 digest");
		}

		// --- 3. a @skill skill: synthesized frontmatter ---------------------
		auto md = readSkill(client, "git-workflow");
		check(md.canFind("name: git-workflow"), "SKILL.md frontmatter should carry the name");
		check(md.canFind("description: \"Follow this team's Git"),
			"SKILL.md frontmatter should carry the description");
		check(md.canFind("# Git Workflow"), "SKILL.md should carry the instructions body");

		// --- 4. the @skillDir skill: authored frontmatter, file, archive ----
		auto rel = skills.filter!(s => s.name == "release-helper").front;
		check(rel.url == "skill://team/release-helper/SKILL.md",
			"release-helper should be served under its team/ prefix");
		// The authored frontmatter (license + nested metadata) survives verbatim.
		check(rel.frontmatter["license"].get!string == "Apache-2.0",
			"authored license should pass through to the index frontmatter");
		check(rel.frontmatter["metadata"]["version"].get!string == "1.3.0",
			"authored metadata should pass through to the index frontmatter");

		auto checklist = client.readResource("skill://team/release-helper/references/CHECKLIST.md");
		check(checklist.contents.length > 0
			&& checklist.contents[0].text.canFind("Release Checklist"),
			"the supporting references/CHECKLIST.md should be readable");

		check(rel.archives.length == 1, "release-helper should list one archive form");
		checkEq(rel.archives[0].mimeType, "application/zip", "archive mimeType");
		check(rel.archives[0].digest.canFind("sha256:"), "archive should carry a digest");
		auto archive = client.readResource(rel.archives[0].url);
		check(archive.contents.length > 0 && archive.contents[0].blob.length > 0,
			"the archive resource should be readable as a blob");

		// --- 5. resources/directory/read: walk the skill's tree -------------
		auto root = readDirectory(client, "skill://team/release-helper");
		check(root.any!(e => e.name == "SKILL.md" && !e.isDirectory),
			"directory read should list SKILL.md as a file");
		check(root.any!(e => e.name == "references" && e.isDirectory),
			"directory read should list references/ as a subdirectory");
		auto refs = readDirectory(client, "skill://team/release-helper/references");
		check(refs.any!(e => e.name == "CHECKLIST.md"),
			"descending into references/ should list CHECKLIST.md");

		bool http;
		foreach (arg; args)
			if (arg == "--http" || arg == "--url")
				http = true;
		writeln("OK: skills example e2e passed over ", http ? "http" : "stdio",
			" — skills extension advertised (directoryRead); index lists",
			" git-workflow/code-review/release-helper with verbatim frontmatter + sha256",
			" digests; @skillDir team/release-helper serves authored frontmatter,",
			" references/CHECKLIST.md, and a .zip archive; resources/directory/read walks the tree.");
		return 0;
	});
}
