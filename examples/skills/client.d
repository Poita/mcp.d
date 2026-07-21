/**
 * MCP Skills example client + self-verifying e2e test — dual-transport.
 *
 * Drives the `skills-example` server over EITHER transport with IDENTICAL
 * assertions, using the shared examples/common scaffold:
 *   - STDIO (default): spawns the sibling `skills-server` binary.
 *   - HTTP (`--http <url>`): connects to a running server via Streamable HTTP.
 *
 * Exercises the SEP-2640 skills flow — the extension's three methods plus the
 * plain Resources reads skill content rides on:
 *
 *   1. server/discover advertises the skills extension under `capabilities`.
 *   2. listSkills() calls skills/list and returns conformant entries
 *      (verbatim frontmatter, SKILL.md uri, per-file resources manifest).
 *   3. readSkill("git-workflow") reads a @skill skill: synthesized frontmatter.
 *   4. The @skillDir-sourced team/release-helper skill carries its AUTHORED
 *      frontmatter and a references/CHECKLIST.md file, and its nested
 *      hotfix-helper skill is published as its own flat entry.
 *   5. getSkill() fetches one entry by URI via skills/get, and the fetched
 *      content is verified against the entry's digests and frontmatter
 *      (verifySkillMarkdown / verifyResourceDigest).
 *   6. resources/directory/read scope-lists the release-helper tree: files plus
 *      subdirectories (marked inode/directory), descended one level at a time.
 *
 * The example calls the draft-only server/discover, so the client enables the
 * draft protocol (`enableModern`) up front. The skills extension itself
 * negotiates from 2025-11-25; the resource reads work on any protocol version.
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

		// server/discover (used below) exists only on the draft protocol, so
		// negotiate it. The skills extension itself is visible from 2025-11-25.
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

		// --- 2. listSkills(): skills/list enumerates every registered skill ---
		auto skills = listSkills(client);
		auto names = skills.map!(s => s.name).array;
		checkEq(skills.length, 4, "skills/list should carry four entries");
		check(names.canFind("git-workflow"), "listing should carry git-workflow");
		check(names.canFind("code-review"), "listing should carry code-review");
		check(names.canFind("release-helper"), "listing should carry release-helper");
		check(names.canFind("hotfix-helper"),
			"the nested skill should be published as its own flat entry");
		foreach (s; skills)
		{
			check(s.uri.length > 0, "entry should carry a SKILL.md uri");
			check(s.resources.length > 0, "entry should carry a resources manifest");
			check(s.resources[0].uri == s.uri, "the manifest should list the SKILL.md itself first");
			check(s.resources[0].digest.canFind("sha256:"),
				"manifest entries should carry sha256 digests");
		}

		// --- 3. a @skill skill: synthesized frontmatter ---------------------
		auto md = readSkill(client, "git-workflow");
		check(md.canFind("name: git-workflow"), "SKILL.md frontmatter should carry the name");
		check(md.canFind("description: \"Follow this team's Git"),
			"SKILL.md frontmatter should carry the description");
		check(md.canFind("# Git Workflow"), "SKILL.md should carry the instructions body");

		// --- 4. the @skillDir skill: authored frontmatter and files ---------
		auto rel = skills.filter!(s => s.name == "release-helper").front;
		check(rel.uri == "skill://team/release-helper/SKILL.md",
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

		// --- 5. skills/get + host-side verification --------------------------
		auto fetched = getSkill(client, "skill://team/release-helper/SKILL.md");
		checkEq(fetched.name, "release-helper", "skills/get should return the entry by uri");
		auto relMd = readSkillUri(client, fetched.uri);
		check(verifySkillMarkdown(fetched, relMd) is null,
			"the fetched SKILL.md should verify against its entry (digest + frontmatter)");
		check(verifyResourceDigest(fetched, "skill://team/release-helper/references/CHECKLIST.md",
			cast(const(ubyte)[]) checklist.contents[0].text) is null,
			"CHECKLIST.md should verify against the entry's manifest digest");

		// The nested skill is an ordinary flat entry, retrievable by its own uri.
		auto hotfix = getSkill(client, "skill://team/release-helper/hotfix-helper/SKILL.md");
		checkEq(hotfix.name, "hotfix-helper", "the nested skill answers skills/get");
		check(hotfix.frontmatter["description"].get!string.canFind("hotfix"),
			"the nested entry carries its own authored frontmatter");

		// --- 6. resources/directory/read: walk the skill's tree -------------
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
		writeln("OK: skills example e2e passed over ", http
			? "http" : "stdio",
			" — skills extension advertised (directoryRead); skills/list carries",
			" git-workflow/code-review/release-helper plus the nested hotfix-helper,",
			" each with verbatim frontmatter and a per-file sha256 manifest; skills/get",
			" fetches entries by uri and the fetched content verifies (digest +",
			" frontmatter); resources/directory/read walks the tree.");
		return 0;
	});
}
