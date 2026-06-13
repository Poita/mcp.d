module mcp.api.skills;

import std.typecons : nullable;
import vibe.data.json : Json;

import mcp.server.server : McpServer;
import mcp.server.skill_index : SkillIndex;
import mcp.protocol.types : Resource, ResourceContents;

@safe:

/// The MCP Skills extension identifier (SEP-2640) — the key under
/// `capabilities.extensions` a server declares to advertise that it serves
/// Agent Skills as resources. The extension adds no new protocol methods: a
/// skill is a directory of files exposed through the existing Resources
/// primitive, so a host that already treats resources as a virtual filesystem
/// consumes MCP-served skills identically to local ones.
enum string skillsExtensionKey = "io.modelcontextprotocol/skills";

/// The MIME type a `SKILL.md` resource declares (Agent Skills are Markdown with
/// YAML frontmatter).
enum string skillMimeType = "text/markdown";

/// The well-known discovery resource URI a skills server serves so clients can
/// enumerate its skills (`resources/read` returns the discovery document).
enum string skillIndexUri = "skill://index.json";

/// The MIME type of the `skill://index.json` discovery document.
enum string skillIndexMimeType = "application/json";

/// The discovery-document `$schema` the index advertises (the Agent Skills
/// well-known index format SEP-2640 reuses).
enum string skillDiscoverySchema = "https://schemas.agentskills.io/discovery/0.2.0/schema.json";

/// A supporting file shipped alongside a skill's `SKILL.md` (a reference doc,
/// template, example, or asset). Served as a sibling resource at
/// `skill://<skill-name>/<path>`; `path` is relative to the skill root and may
/// contain `/` for nested files (e.g. `references/FORMS.md`).
struct SkillFile
{
	string path; /// path relative to the skill root, e.g. "references/GUIDE.md"
	string mimeType; /// MIME type of the content, e.g. "text/markdown"
	string content; /// the file body (UTF-8 text, or base64 when `isBlob`)
	bool isBlob; /// whether `content` is base64-encoded binary rather than text
}

/// A declarative skill: a `SKILL.md` (its `instructions` body, with frontmatter
/// synthesized from `name`/`description`/`metadata`) plus any supporting
/// `files`. Register it with `registerSkill`; the `@skill` UDA builds one of
/// these for you from an annotated method.
struct Skill
{
	string name; /// skill name (lowercase alphanumeric + single hyphens, 1..64 chars)
	string description; /// one-line description of when to use the skill
	string instructions; /// the `SKILL.md` body (Markdown; frontmatter is synthesized)
	string[string] metadata; /// optional extra frontmatter under `metadata:`
	SkillFile[] files; /// optional supporting files served as sibling resources
}

/// Whether `name` is a valid Agent Skills / SEP-2640 skill name: 1..64
/// characters of lowercase ASCII letters, digits, and single hyphens, with no
/// leading, trailing, or consecutive hyphens. The final URI segment of a
/// skill's resources is this name, so it must be URI-safe and stable.
bool isValidSkillName(string name) @safe pure nothrow
{
	if (name.length == 0 || name.length > 64)
		return false;
	if (name[0] == '-' || name[$ - 1] == '-')
		return false;
	bool prevHyphen;
	foreach (c; name)
	{
		const lower = (c >= 'a' && c <= 'z');
		const digit = (c >= '0' && c <= '9');
		const hyphen = (c == '-');
		if (!lower && !digit && !hyphen)
			return false;
		if (hyphen && prevHyphen)
			return false;
		prevHyphen = hyphen;
	}
	return true;
}

/// The `skill://<name>/SKILL.md` resource URI for a skill.
string skillUri(string name) @safe pure
{
	return "skill://" ~ name ~ "/SKILL.md";
}

/// The `skill://<name>/<path>` resource URI for a skill's supporting file.
string skillFileUri(string name, string path) @safe pure
{
	return "skill://" ~ name ~ "/" ~ path;
}

/// Double-quote and escape a string as a YAML flow scalar so an arbitrary
/// description / metadata value is always valid in the synthesized frontmatter.
private string yamlQuote(string s) @safe pure
{
	import std.array : Appender;

	Appender!string a;
	a ~= '"';
	foreach (c; s)
	{
		if (c == '\\' || c == '"')
			a ~= '\\';
		if (c == '\n')
		{
			a ~= "\\n";
			continue;
		}
		a ~= c;
	}
	a ~= '"';
	return a.data;
}

/// Render a complete `SKILL.md`: the YAML frontmatter (synthesized from `name`,
/// `description`, and any `metadata`) followed by the `instructions` body. The
/// `name` is emitted unquoted (it is constrained to a URI-safe token); the
/// description and metadata values are YAML-quoted so any content is safe.
string skillMarkdown(string name, string description, string instructions,
		string[string] metadata = null) @safe
{
	import std.array : Appender;
	import std.algorithm : sort;

	Appender!string a;
	a ~= "---\n";
	a ~= "name: " ~ name ~ "\n";
	a ~= "description: " ~ yamlQuote(description) ~ "\n";
	if (metadata.length)
	{
		a ~= "metadata:\n";
		// Emit keys in a stable (sorted) order so the rendered SKILL.md is
		// deterministic regardless of the associative array's iteration order.
		foreach (key; metadata.keys.sort)
			a ~= "  " ~ yamlQuote(key) ~ ": " ~ yamlQuote(metadata[key]) ~ "\n";
	}
	a ~= "---\n\n";
	a ~= instructions;
	return a.data;
}

/// Advertise the SEP-2640 skills extension on `server` and register the
/// `skill://index.json` discovery resource (whose reader serializes whatever
/// skills are registered at read time). Idempotent: safe to call before every
/// `registerSkill`, and called for you by `registerSkill` and the `@skill` UDA.
/// Declare it (directly or via a `registerSkill`) before `initialize` /
/// `server/discover` so the extension appears in the negotiated capabilities.
void enableSkills(McpServer server) @safe
{
	server.enableExtension(skillsExtensionKey);
	auto index = server.ensureSkillIndex();
	if (index.indexResourceRegistered)
		return;
	index.indexResourceRegistered = true;

	Resource descriptor;
	descriptor.uri = skillIndexUri;
	descriptor.name = "skills";
	descriptor.description = nullable("Index of the skills this server provides");
	descriptor.mimeType = nullable(skillIndexMimeType);

	server.registerResource(descriptor, () @safe {
		Json doc = Json.emptyObject;
		doc["$schema"] = skillDiscoverySchema;
		Json skills = Json.emptyArray;
		foreach (entry; index.entries)
			skills ~= entry;
		doc["skills"] = skills;
		return ResourceContents.makeText(skillIndexUri, skillIndexMimeType, doc.toString());
	});
}

/// Register `skill` on `server`: serve its `SKILL.md` (with synthesized
/// frontmatter) at `skill://<name>/SKILL.md`, serve each supporting file at
/// `skill://<name>/<path>`, advertise the skills extension, and add the skill
/// to the `skill://index.json` discovery document. Throws if `name` is not a
/// valid skill name (see `isValidSkillName`).
void registerSkill(McpServer server, Skill skill) @safe
{
	if (!isValidSkillName(skill.name))
		throw new Exception("invalid skill name '" ~ skill.name
				~ "': must be 1..64 chars of lowercase letters, digits, and single hyphens "
				~ "(no leading/trailing/consecutive hyphens)");

	enableSkills(server);
	auto index = server.ensureSkillIndex();

	const uri = skillUri(skill.name);
	const markdown = skillMarkdown(skill.name, skill.description,
			skill.instructions, skill.metadata);

	Resource descriptor;
	descriptor.uri = uri;
	descriptor.name = skill.name;
	descriptor.description = nullable(skill.description);
	descriptor.mimeType = nullable(skillMimeType);
	server.registerResource(descriptor, () @safe {
		return ResourceContents.makeText(uri, skillMimeType, markdown);
	});

	foreach (file; skill.files)
	{
		// Bind a per-iteration copy so each resource reader closes over its own
		// file rather than the shared loop variable.
		const f = file;
		const fileUri = skillFileUri(skill.name, f.path);
		Resource fileDescriptor;
		fileDescriptor.uri = fileUri;
		fileDescriptor.name = skill.name ~ "/" ~ f.path;
		if (f.mimeType.length)
			fileDescriptor.mimeType = nullable(f.mimeType);
		server.registerResource(fileDescriptor, () @safe {
			return f.isBlob ? ResourceContents.makeBlob(fileUri, f.mimeType,
				f.content) : ResourceContents.makeText(fileUri, f.mimeType, f.content);
		});
	}

	Json entry = Json.emptyObject;
	entry["name"] = skill.name;
	entry["type"] = "skill-md";
	entry["description"] = skill.description;
	entry["url"] = uri;
	index.entries ~= entry;
}

/// Convenience overload registering a skill from its parts (no supporting files
/// or metadata). Equivalent to `registerSkill(server, Skill(name, description,
/// instructions))`.
void registerSkill(McpServer server, string name, string description, string instructions) @safe
{
	registerSkill(server, Skill(name, description, instructions));
}

/// Whether the connected client advertised the skills extension at
/// initialization (valid after `initialize` / `server/discover`).
bool clientSupportsSkills(McpServer server) @safe
{
	auto ext = server.clientExtensions();
	return ext.type == Json.Type.object && (skillsExtensionKey in ext) !is null;
}

// --- Client-side convenience (non-normative SEP-2640 wrappers) --------------

import mcp.client.client : McpClient;

/// One entry from a server's `skill://index.json` discovery document.
struct SkillEntry
{
	string name; /// skill name (empty for an `mcp-resource-template` entry)
	string type; /// "skill-md" or "mcp-resource-template"
	string description; /// one-line description
	string url; /// full resource URI (`skill-md`) or RFC 6570 template

	static SkillEntry fromJson(Json j) @safe
	{
		SkillEntry e;
		if ("name" in j && j["name"].type == Json.Type.string)
			e.name = j["name"].get!string;
		if ("type" in j && j["type"].type == Json.Type.string)
			e.type = j["type"].get!string;
		if ("description" in j && j["description"].type == Json.Type.string)
			e.description = j["description"].get!string;
		if ("url" in j && j["url"].type == Json.Type.string)
			e.url = j["url"].get!string;
		return e;
	}
}

/// Read `skill://index.json` from `client` and return its skill entries. A
/// thin wrapper over `resources/read`: SEP-2640 defines no `skills/list`
/// method, so discovery is reading this well-known resource. Returns an empty
/// array if the server serves no index (which, per the spec, does NOT prove it
/// has no skills — large or generated catalogs may omit the index).
SkillEntry[] listSkills(McpClient client) @safe
{
	import vibe.data.json : parseJsonString;

	SkillEntry[] entries;
	auto result = client.readResource(skillIndexUri);
	foreach (content; result.contents)
	{
		if (content.text.length == 0)
			continue;
		auto doc = parseJsonString(content.text);
		if ("skills" in doc && doc["skills"].type == Json.Type.array)
			foreach (i; 0 .. doc["skills"].length)
				entries ~= SkillEntry.fromJson(doc["skills"][i]);
	}
	return entries;
}

/// Read a skill's `SKILL.md` from `client` by skill name — a wrapper over
/// `resources/read` of `skill://<name>/SKILL.md`. Returns the raw `SKILL.md`
/// text (frontmatter + body), or `null` if the server returned no text content.
string readSkill(McpClient client, string name) @safe
{
	auto result = client.readResource(skillUri(name));
	foreach (content; result.contents)
		if (content.text.length)
			return content.text;
	return null;
}

// --- Tests ------------------------------------------------------------------

unittest  // the extension key and discovery constants carry the SEP-2640 literals
{
	assert(skillsExtensionKey == "io.modelcontextprotocol/skills");
	assert(skillMimeType == "text/markdown");
	assert(skillIndexUri == "skill://index.json");
	assert(skillUri("git-workflow") == "skill://git-workflow/SKILL.md");
	assert(skillFileUri("pdf", "references/FORMS.md") == "skill://pdf/references/FORMS.md");
}

unittest  // isValidSkillName accepts well-formed names
{
	assert(isValidSkillName("git-workflow"));
	assert(isValidSkillName("pdf"));
	assert(isValidSkillName("a1-b2-c3"));
	assert(isValidSkillName("x"));
}

unittest  // isValidSkillName rejects malformed names
{
	assert(!isValidSkillName(""));
	assert(!isValidSkillName("-leading"));
	assert(!isValidSkillName("trailing-"));
	assert(!isValidSkillName("double--hyphen"));
	assert(!isValidSkillName("UpperCase"));
	assert(!isValidSkillName("has space"));
	assert(!isValidSkillName("under_score"));
	// 65 chars exceeds the 64-char limit.
	string tooLong;
	foreach (_; 0 .. 65)
		tooLong ~= "a";
	assert(!isValidSkillName(tooLong));
}

unittest  // skillMarkdown synthesizes frontmatter with name/description and body
{
	auto md = skillMarkdown("git-workflow", "Follow Git conventions",
			"# Git Workflow\n\n1. Branch.\n");
	assert(md == "---\nname: git-workflow\ndescription: \"Follow Git conventions\"\n---\n\n"
			~ "# Git Workflow\n\n1. Branch.\n");
}

unittest  // skillMarkdown quotes/escapes a description with special characters
{
	auto md = skillMarkdown("x", `He said "hi"`, "body");
	import std.algorithm : canFind;

	assert(md.canFind(`description: "He said \"hi\""`));
}

unittest  // skillMarkdown emits metadata in a deterministic sorted order
{
	string[string] meta = ["zeta": "1", "alpha": "2"];
	auto md = skillMarkdown("x", "d", "body", meta);
	import std.string : indexOf;

	const a = md.indexOf(`"alpha"`);
	const z = md.indexOf(`"zeta"`);
	assert(a >= 0 && z >= 0 && a < z, "alpha must sort before zeta");
}

unittest  // enableSkills advertises the extension and serves an empty index
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.mrtr : MetaKey;
	import vibe.data.json : parseJsonString;

	auto s = new McpServer("t", "1");
	enableSkills(s);

	Json params = Json.emptyObject;
	Json m = Json.emptyObject;
	m[MetaKey.protocolVersion] = "2026-07-28";
	m[MetaKey.clientInfo] = Json(["name": Json("c"), "version": Json("1")]);
	m[MetaKey.clientCapabilities] = Json.emptyObject;
	params["_meta"] = m;
	auto caps = s.handle(Message(makeRequest(Json(1), "server/discover",
			params))).get["result"]["capabilities"];
	assert(skillsExtensionKey in caps["extensions"]);

	Json rp = Json.emptyObject;
	rp["uri"] = skillIndexUri;
	auto contents = s.handle(Message(makeRequest(Json(2), "resources/read",
			rp))).get["result"]["contents"][0];
	assert(contents["mimeType"].get!string == skillIndexMimeType);
	auto doc = parseJsonString(contents["text"].get!string);
	assert(doc["$schema"].get!string == skillDiscoverySchema);
	assert(doc["skills"].type == Json.Type.array && doc["skills"].length == 0);
}

unittest  // registerSkill serves SKILL.md and lists the skill in the index
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import vibe.data.json : parseJsonString;

	auto s = new McpServer("t", "1");
	registerSkill(s, "git-workflow", "Follow Git conventions",
			"# Git Workflow\n\n1. Branch from main.\n");

	// The SKILL.md resource carries the markdown mime type and the rendered body.
	Json rp = Json.emptyObject;
	rp["uri"] = skillUri("git-workflow");
	auto contents = s.handle(Message(makeRequest(Json(1), "resources/read",
			rp))).get["result"]["contents"][0];
	assert(contents["mimeType"].get!string == skillMimeType);
	const md = contents["text"].get!string;
	import std.algorithm : canFind;

	assert(md.canFind("name: git-workflow"));
	assert(md.canFind("# Git Workflow"));

	// The index lists the skill with the spec entry shape.
	Json ip = Json.emptyObject;
	ip["uri"] = skillIndexUri;
	auto idx = s.handle(Message(makeRequest(Json(2), "resources/read", ip)))
		.get["result"]["contents"][0];
	auto doc = parseJsonString(idx["text"].get!string);
	assert(doc["skills"].length == 1);
	auto e = doc["skills"][0];
	assert(e["name"].get!string == "git-workflow");
	assert(e["type"].get!string == "skill-md");
	assert(e["description"].get!string == "Follow Git conventions");
	assert(e["url"].get!string == "skill://git-workflow/SKILL.md");
}

unittest  // registerSkill serves supporting files as sibling resources
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	Skill sk = {
		name: "pdf", description: "Process PDFs", instructions: "See references/FORMS.md.",
		files: [SkillFile("references/FORMS.md", "text/markdown", "# Forms\n")]
	};
	registerSkill(s, sk);

	Json rp = Json.emptyObject;
	rp["uri"] = "skill://pdf/references/FORMS.md";
	auto contents = s.handle(Message(makeRequest(Json(1), "resources/read",
			rp))).get["result"]["contents"][0];
	assert(contents["mimeType"].get!string == "text/markdown");
	assert(contents["text"].get!string == "# Forms\n");
}

unittest  // registerSkill rejects an invalid skill name
{
	import std.exception : assertThrown;

	auto s = new McpServer("t", "1");
	assertThrown!Exception(registerSkill(s, "Bad Name", "d", "body"));
}

unittest  // multiple skills accumulate in the index across calls
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import vibe.data.json : parseJsonString;

	auto s = new McpServer("t", "1");
	registerSkill(s, "alpha", "First", "a");
	registerSkill(s, "beta", "Second", "b");

	Json ip = Json.emptyObject;
	ip["uri"] = skillIndexUri;
	auto idx = s.handle(Message(makeRequest(Json(1), "resources/read", ip)))
		.get["result"]["contents"][0];
	auto doc = parseJsonString(idx["text"].get!string);
	assert(doc["skills"].length == 2);
	assert(doc["skills"][0]["name"].get!string == "alpha");
	assert(doc["skills"][1]["name"].get!string == "beta");
}

unittest  // clientSupportsSkills reflects what the client advertised at initialize
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	Json caps = Json.emptyObject;
	Json ext = Json.emptyObject;
	ext[skillsExtensionKey] = Json.emptyObject;
	caps["extensions"] = ext;
	Json params = Json.emptyObject;
	params["protocolVersion"] = "2025-06-18";
	params["capabilities"] = caps;
	s.handle(Message(makeRequest(Json(1), "initialize", params)));
	assert(clientSupportsSkills(s));
}

unittest  // clientSupportsSkills is false when the client did not advertise it
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	Json params = Json.emptyObject;
	params["protocolVersion"] = "2025-06-18";
	params["capabilities"] = Json.emptyObject;
	s.handle(Message(makeRequest(Json(1), "initialize", params)));
	assert(!clientSupportsSkills(s));
}

unittest  // SkillEntry.fromJson reads the discovery entry fields
{
	import vibe.data.json : parseJsonString;

	auto e = SkillEntry.fromJson(parseJsonString(
			`{"name":"git","type":"skill-md","description":"d","url":"skill://git/SKILL.md"}`));
	assert(e.name == "git");
	assert(e.type == "skill-md");
	assert(e.description == "d");
	assert(e.url == "skill://git/SKILL.md");
}
