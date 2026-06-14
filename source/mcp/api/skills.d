module mcp.api.skills;

import std.typecons : nullable;
import vibe.data.json : Json;

import mcp.server.server : McpServer;
import mcp.server.skill_index : SkillIndex;
import mcp.protocol.types : Resource, ResourceContents;

@safe:

/// The MCP Skills extension identifier (SEP-2640) — the key under
/// `capabilities.extensions` a server declares to advertise that it serves
/// Agent Skills as resources. The extension adds no new message types beyond the
/// optional `resources/directory/read` method: a skill is a directory of files
/// exposed through the existing Resources primitive, so a host that already
/// treats resources as a virtual filesystem consumes MCP-served skills
/// identically to local ones.
enum string skillsExtensionKey = "io.modelcontextprotocol/skills";

/// The MIME type a `SKILL.md` resource declares (Agent Skills are Markdown with
/// YAML frontmatter).
enum string skillMimeType = "text/markdown";

/// The well-known discovery resource URI a skills server serves so clients can
/// enumerate its skills (`resources/read` returns the discovery document).
enum string skillIndexUri = "skill://index.json";

/// The MIME type of the `skill://index.json` discovery document.
enum string skillIndexMimeType = "application/json";

/// The MIME type SEP-2640 assigns to a directory resource — the `mimeType` that
/// marks a `resources/directory/read` child as a subdirectory the client can
/// descend into (rather than a file to read).
enum string skillDirectoryMimeType = "inode/directory";

/// A supporting file shipped alongside a skill's `SKILL.md` (a reference doc,
/// template, example, or asset). Served as a sibling resource at
/// `skill://<skill-path>/<path>`; `path` is relative to the skill root and may
/// contain `/` for nested files (e.g. `references/FORMS.md`).
struct SkillFile
{
	string path; /// path relative to the skill root, e.g. "references/GUIDE.md"
	string mimeType; /// MIME type of the content, e.g. "text/markdown"
	string content; /// the file body (UTF-8 text, or base64 when `isBlob`)
	bool isBlob; /// whether `content` is base64-encoded binary rather than text
}

/// A pre-packed archive form of an entire skill directory (SEP-2640 "archives").
/// Reading the archive resource retrieves the whole skill — `SKILL.md` and all
/// supporting files — in one round trip; when several are listed they are
/// alternative encodings of identical content and a host picks a format it
/// supports. Served as a blob resource at `skill://<skill-path><suffix>`.
struct SkillArchive
{
	string suffix; /// URI/extension suffix, e.g. ".tar.gz" or ".zip"
	string mimeType; /// archive media type, e.g. "application/gzip", "application/zip"
	string content; /// the archive bytes, base64-encoded (served as a blob)
}

/// A declarative skill: a `SKILL.md` (its `instructions` body, with frontmatter
/// synthesized from `path`'s final segment, `description`, and `metadata`) plus
/// any supporting `files` and pre-packed `archives`. Register it with
/// `registerSkill`; the `@skill` UDA builds one of these from an annotated
/// method.
struct Skill
{
	/// The skill path: a `/`-separated locator whose final segment is the skill
	/// name (lowercase alphanumeric + single hyphens). May be a single segment
	/// (`git-workflow`) or carry an organizational prefix (`acme/billing/refunds`).
	string path;
	string description; /// one-line description of when to use the skill
	string instructions; /// the `SKILL.md` body (Markdown; frontmatter is synthesized)
	string[string] metadata; /// optional extra frontmatter under `metadata:`
	SkillFile[] files; /// optional supporting files served as sibling resources
	SkillArchive[] archives; /// optional pre-packed archive forms of the whole skill

	/// The skill name: the final segment of `path`, per SEP-2640's requirement
	/// that the last `<skill-path>` segment equal the frontmatter `name`.
	string name() const @safe pure
	{
		return skillName(path);
	}
}

/// The final segment of a skill path — the skill's `name`. For `acme/billing/refunds`
/// this is `refunds`; for `git-workflow` it is `git-workflow`.
string skillName(string path) @safe pure
{
	import std.string : lastIndexOf;

	const slash = path.lastIndexOf('/');
	return slash < 0 ? path : path[slash + 1 .. $];
}

/// Whether `name` is a valid Agent Skills / SEP-2640 skill name: 1..64
/// characters of lowercase ASCII letters, digits, and single hyphens, with no
/// leading, trailing, or consecutive hyphens. The final segment of a skill path
/// must satisfy this so the name is recoverable from the URI and URI-safe.
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

/// Whether `path` is a valid skill path: one or more non-empty `/`-separated
/// segments whose final segment is a valid skill name (`isValidSkillName`).
/// Prefix segments only need to be non-empty (RFC 3986 path segments).
bool isValidSkillPath(string path) @safe pure nothrow
{
	if (path.length == 0)
		return false;
	size_t segStart;
	string last;
	foreach (i, char c; path)
	{
		if (c != '/')
			continue;
		if (i == segStart) // empty segment (leading, trailing, or doubled '/')
			return false;
		last = path[segStart .. i];
		segStart = i + 1;
	}
	if (segStart == path.length) // trailing '/' leaves an empty final segment
		return false;
	last = path[segStart .. $];
	return isValidSkillName(last);
}

/// The `skill://<path>/SKILL.md` resource URI for a skill.
string skillUri(string path) @safe pure
{
	return "skill://" ~ path ~ "/SKILL.md";
}

/// The `skill://<path>/<file>` resource URI for a skill's supporting file.
string skillFileUri(string path, string file) @safe pure
{
	return "skill://" ~ path ~ "/" ~ file;
}

/// The `skill://<path><suffix>` resource URI for a skill's archive form.
string skillArchiveUri(string path, string suffix) @safe pure
{
	return "skill://" ~ path ~ suffix;
}

/// A `sha256:<hex>` digest of `bytes`, the integrity form SEP-2640 requires for
/// index `digest` fields (lowercase hex of the SHA-256 of the artifact's raw
/// bytes).
string skillDigest(scope const(ubyte)[] bytes) @safe
{
	import std.digest.sha : sha256Of;
	import std.digest : toHexString, LetterCase;

	return "sha256:" ~ toHexString!(LetterCase.lower)(sha256Of(bytes)).idup;
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

/// The skill's frontmatter rendered as a JSON object, matching the YAML
/// `skillMarkdown` synthesizes: `name` and `description` always, plus a nested
/// `metadata` object when present. This is the verbatim `frontmatter` SEP-2640
/// requires in each `skill://index.json` entry — identical in content to the
/// `SKILL.md` it describes.
private Json frontmatterJson(string name, string description, string[string] metadata) @safe
{
	import std.algorithm : sort;

	Json fm = Json.emptyObject;
	fm["name"] = name;
	fm["description"] = description;
	if (metadata.length)
	{
		Json m = Json.emptyObject;
		foreach (key; metadata.keys.sort)
			m[key] = metadata[key];
		fm["metadata"] = m;
	}
	return fm;
}

/// Advertise the SEP-2640 skills extension on `server` and register the
/// `skill://index.json` discovery resource (whose reader serializes whatever
/// skills are registered at read time). Idempotent: safe to call before every
/// `registerSkill`, and called for you by `registerSkill` and the `@skill` UDA.
/// Declare it (directly or via a `registerSkill`) before `initialize` /
/// `server/discover` so the extension appears in the negotiated capabilities.
void enableSkills(McpServer server) @safe
{
	// Advertise the extension with `directoryRead: true` and turn the method on:
	// this SDK serves skills as individual file resources, so `resources/directory/read`
	// can scope-list any skill subtree.
	Json settings = Json.emptyObject;
	settings["directoryRead"] = true;
	server.enableExtension(skillsExtensionKey, settings);
	server.enableDirectoryRead();
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
		Json skills = Json.emptyArray;
		foreach (entry; index.entries)
			skills ~= entry;
		doc["skills"] = skills;
		return ResourceContents.makeText(skillIndexUri, skillIndexMimeType, doc.toString());
	});
}

/// Register `skill` on `server`: serve its `SKILL.md` (with synthesized
/// frontmatter) at `skill://<path>/SKILL.md`, serve each supporting file at
/// `skill://<path>/<file>` and each archive at `skill://<path><suffix>`,
/// advertise the skills extension, and add a conformant entry — verbatim
/// `frontmatter`, the `SKILL.md` `url` and its `digest`, and any `archives` — to
/// the `skill://index.json` discovery document. Throws if `path` is not a valid
/// skill path (see `isValidSkillPath`).
void registerSkill(McpServer server, Skill skill) @safe
{
	if (!isValidSkillPath(skill.path))
		throw new Exception("invalid skill path '" ~ skill.path
				~ "': each '/'-separated segment must be non-empty and the final segment "
				~ "must be a valid skill name (1..64 chars of lowercase letters, digits, "
				~ "and single hyphens, no leading/trailing/consecutive hyphens)");

	enableSkills(server);
	auto index = server.ensureSkillIndex();

	const name = skill.name;
	const uri = skillUri(skill.path);
	const markdown = skillMarkdown(name, skill.description, skill.instructions, skill.metadata);

	Resource descriptor;
	descriptor.uri = uri;
	descriptor.name = name;
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
		const fileUri = skillFileUri(skill.path, f.path);
		Resource fileDescriptor;
		fileDescriptor.uri = fileUri;
		fileDescriptor.name = f.path;
		if (f.mimeType.length)
			fileDescriptor.mimeType = nullable(f.mimeType);
		server.registerResource(fileDescriptor, () @safe {
			return f.isBlob ? ResourceContents.makeBlob(fileUri, f.mimeType,
				f.content) : ResourceContents.makeText(fileUri, f.mimeType, f.content);
		});
	}

	Json entry = Json.emptyObject;
	entry["frontmatter"] = frontmatterJson(name, skill.description, skill.metadata);
	entry["url"] = uri;
	entry["digest"] = skillDigest(cast(const(ubyte)[]) markdown);

	if (skill.archives.length)
	{
		import std.base64 : Base64;

		Json archives = Json.emptyArray;
		foreach (archive; skill.archives)
		{
			const a = archive;
			const archiveUri = skillArchiveUri(skill.path, a.suffix);
			Resource archiveDescriptor;
			archiveDescriptor.uri = archiveUri;
			archiveDescriptor.name = name ~ a.suffix;
			if (a.mimeType.length)
				archiveDescriptor.mimeType = nullable(a.mimeType);
			server.registerResource(archiveDescriptor, () @safe {
				return ResourceContents.makeBlob(archiveUri, a.mimeType, a.content);
			});

			Json e = Json.emptyObject;
			e["url"] = archiveUri;
			e["mimeType"] = a.mimeType;
			e["digest"] = skillDigest(Base64.decode(a.content));
			archives ~= e;
		}
		entry["archives"] = archives;
	}

	index.entries ~= entry;
}

/// Convenience overload registering a skill from its parts (no supporting files,
/// archives, or metadata). Equivalent to `registerSkill(server, Skill(path,
/// description, instructions))`.
void registerSkill(McpServer server, string path, string description, string instructions) @safe
{
	registerSkill(server, Skill(path, description, instructions));
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

/// One archive form from a `skill://index.json` entry's `archives` array.
struct SkillArchiveRef
{
	string url; /// resource URI of the archive
	string mimeType; /// the archive format's media type
	string digest; /// `sha256:<hex>` digest of the archive bytes

	static SkillArchiveRef fromJson(Json j) @safe
	{
		SkillArchiveRef a;
		if ("url" in j && j["url"].type == Json.Type.string)
			a.url = j["url"].get!string;
		if ("mimeType" in j && j["mimeType"].type == Json.Type.string)
			a.mimeType = j["mimeType"].get!string;
		if ("digest" in j && j["digest"].type == Json.Type.string)
			a.digest = j["digest"].get!string;
		return a;
	}
}

/// One entry from a server's `skill://index.json` discovery document. `name` and
/// `description` are read from the verbatim `frontmatter` object (always present
/// per the Agent Skills spec); `url`/`digest` address the `SKILL.md` directly
/// (absent for archive-only entries), and `archives` lists pre-packed forms.
struct SkillEntry
{
	Json frontmatter; /// verbatim `SKILL.md` frontmatter as JSON
	string url; /// resource URI of the `SKILL.md` (empty for archive-only entries)
	string digest; /// `sha256:<hex>` of the `SKILL.md` (empty when `url` is empty)
	SkillArchiveRef[] archives; /// pre-packed archive forms of the skill

	/// The skill `name` from the frontmatter, or empty if absent.
	string name() const @safe
	{
		if (frontmatter.type == Json.Type.object && "name" in frontmatter
				&& frontmatter["name"].type == Json.Type.string)
			return frontmatter["name"].get!string;
		return null;
	}

	/// The skill `description` from the frontmatter, or empty if absent.
	string description() const @safe
	{
		if (frontmatter.type == Json.Type.object && "description" in frontmatter
				&& frontmatter["description"].type == Json.Type.string)
			return frontmatter["description"].get!string;
		return null;
	}

	static SkillEntry fromJson(Json j) @safe
	{
		SkillEntry e;
		if ("frontmatter" in j)
			e.frontmatter = j["frontmatter"];
		if ("url" in j && j["url"].type == Json.Type.string)
			e.url = j["url"].get!string;
		if ("digest" in j && j["digest"].type == Json.Type.string)
			e.digest = j["digest"].get!string;
		if ("archives" in j && j["archives"].type == Json.Type.array)
			foreach (i; 0 .. j["archives"].length)
				e.archives ~= SkillArchiveRef.fromJson(j["archives"][i]);
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

/// Read a skill's `SKILL.md` by its resource URI — a wrapper over
/// `resources/read`. Works whether or not the skill appears in any index (a
/// skill URI is always a valid `resources/read` argument). Returns the raw
/// `SKILL.md` text, or `null` if the server returned no text content.
string readSkillUri(McpClient client, string uri) @safe
{
	auto result = client.readResource(uri);
	foreach (content; result.contents)
		if (content.text.length)
			return content.text;
	return null;
}

/// Read a skill's `SKILL.md` by skill path — `readSkillUri` against
/// `skill://<path>/SKILL.md`.
string readSkill(McpClient client, string path) @safe
{
	return readSkillUri(client, skillUri(path));
}

/// One direct child reported by `resources/directory/read`: either a file (read
/// it with `resources/read`) or a subdirectory (`isDirectory`, descend with a
/// further `readDirectory`).
struct SkillDirEntry
{
	string uri; /// the child's resource URI
	string name; /// the child's directory-relative name (basename)
	string mimeType; /// the child's MIME type (`inode/directory` for a subdirectory)

	/// Whether this child is a subdirectory rather than a file.
	bool isDirectory() const @safe
	{
		return mimeType == skillDirectoryMimeType;
	}
}

/// List the direct children of a directory resource via the SEP-2640
/// `resources/directory/read` method (a wrapper over `client.readDirectory`).
/// Only valid against a server that advertised `directoryRead: true`. Files come
/// back with their own MIME type; subdirectories carry `inode/directory`
/// (`SkillDirEntry.isDirectory`) and are descended with a further call.
SkillDirEntry[] readDirectory(McpClient client, string uri) @safe
{
	SkillDirEntry[] entries;
	auto result = client.readDirectory(uri);
	foreach (r; result.resources)
	{
		SkillDirEntry e;
		e.uri = r.uri;
		e.name = r.name;
		if (!r.mimeType.isNull)
			e.mimeType = r.mimeType.get;
		entries ~= e;
	}
	return entries;
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

unittest  // a prefixed skill path maps to a nested skill:// URI
{
	assert(skillUri("acme/billing/refunds") == "skill://acme/billing/refunds/SKILL.md");
	assert(skillName("acme/billing/refunds") == "refunds");
	assert(skillName("git-workflow") == "git-workflow");
	assert(skillArchiveUri("pdf-processing", ".tar.gz") == "skill://pdf-processing.tar.gz");
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

unittest  // isValidSkillPath allows multi-segment prefixes but constrains the final segment
{
	assert(isValidSkillPath("git-workflow"));
	assert(isValidSkillPath("acme/billing/refunds"));
	assert(!isValidSkillPath(""));
	assert(!isValidSkillPath("acme//refunds")); // empty middle segment
	assert(!isValidSkillPath("acme/refunds/")); // empty (invalid) final segment
	assert(!isValidSkillPath("acme/Bad_Name")); // invalid final segment
}

unittest  // skillDigest renders a lowercase sha256:<hex> of the bytes
{
	// SHA-256 of the empty input is a well-known constant.
	assert(skillDigest(
			[]) == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
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

unittest  // enableSkills advertises the extension and serves an empty {skills:[]} index
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
	// The capability advertises the optional directory-read method this SDK serves.
	assert(caps["extensions"][skillsExtensionKey]["directoryRead"].get!bool == true);

	Json rp = Json.emptyObject;
	rp["uri"] = skillIndexUri;
	auto contents = s.handle(Message(makeRequest(Json(2), "resources/read",
			rp))).get["result"]["contents"][0];
	assert(contents["mimeType"].get!string == skillIndexMimeType);
	auto doc = parseJsonString(contents["text"].get!string);
	// The discovery document carries no $schema / version marker — just `skills`.
	assert("$schema" !in doc);
	assert(doc["skills"].type == Json.Type.array && doc["skills"].length == 0);
}

unittest  // registerSkill serves SKILL.md and lists a conformant index entry
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

	// The index lists the skill with verbatim frontmatter, url, and a digest.
	Json ip = Json.emptyObject;
	ip["uri"] = skillIndexUri;
	auto idx = s.handle(Message(makeRequest(Json(2), "resources/read", ip)))
		.get["result"]["contents"][0];
	auto doc = parseJsonString(idx["text"].get!string);
	assert(doc["skills"].length == 1);
	auto e = doc["skills"][0];
	assert(e["frontmatter"]["name"].get!string == "git-workflow");
	assert(e["frontmatter"]["description"].get!string == "Follow Git conventions");
	assert(e["url"].get!string == "skill://git-workflow/SKILL.md");
	// digest MUST be present with url, and MUST match the served SKILL.md bytes.
	assert(e["digest"].get!string == skillDigest(cast(const(ubyte)[]) md));
	assert("type" !in e); // the old non-spec `type:"skill-md"` field is gone
}

unittest  // a prefixed skill path lists frontmatter.name as the final segment
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import vibe.data.json : parseJsonString;

	auto s = new McpServer("t", "1");
	registerSkill(s, "acme/billing/refunds", "Process refunds", "# Refunds\n");

	Json rp = Json.emptyObject;
	rp["uri"] = skillUri("acme/billing/refunds");
	auto sm = s.handle(Message(makeRequest(Json(1), "resources/read", rp)))
		.get["result"]["contents"][0];
	assert(sm["text"].get!string.length > 0);

	Json ip = Json.emptyObject;
	ip["uri"] = skillIndexUri;
	auto idx = s.handle(Message(makeRequest(Json(2), "resources/read", ip)))
		.get["result"]["contents"][0];
	auto doc = parseJsonString(idx["text"].get!string);
	auto e = doc["skills"][0];
	assert(e["frontmatter"]["name"].get!string == "refunds");
	assert(e["url"].get!string == "skill://acme/billing/refunds/SKILL.md");
}

unittest  // metadata round-trips into the index frontmatter as a nested object
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import vibe.data.json : parseJsonString;

	auto s = new McpServer("t", "1");
	Skill sk = {
		path: "pdf", description: "Process PDFs", instructions: "# PDF\n",
		metadata: ["version": "2.1.0"]
	};
	registerSkill(s, sk);

	Json ip = Json.emptyObject;
	ip["uri"] = skillIndexUri;
	auto idx = s.handle(Message(makeRequest(Json(1), "resources/read", ip)))
		.get["result"]["contents"][0];
	auto doc = parseJsonString(idx["text"].get!string);
	assert(doc["skills"][0]["frontmatter"]["metadata"]["version"].get!string == "2.1.0");
}

unittest  // registerSkill serves supporting files as sibling resources
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	Skill sk = {
		path: "pdf", description: "Process PDFs", instructions: "See references/FORMS.md.",
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

unittest  // an archive form is served as a blob and listed with a digest
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import vibe.data.json : parseJsonString;
	import std.base64 : Base64;

	auto s = new McpServer("t", "1");
	// A stand-in archive payload; the extension does not interpret the bytes.
	const raw = cast(const(ubyte)[]) "fake-tar-gz-bytes";
	const b64 = Base64.encode(raw).idup;
	Skill sk = {
		path: "pdf", description: "Process PDFs", instructions: "# PDF\n",
		archives: [SkillArchive(".tar.gz", "application/gzip", b64)]
	};
	registerSkill(s, sk);

	// The archive resource is served as a blob at skill://pdf.tar.gz.
	Json rp = Json.emptyObject;
	rp["uri"] = "skill://pdf.tar.gz";
	auto contents = s.handle(Message(makeRequest(Json(1), "resources/read",
			rp))).get["result"]["contents"][0];
	assert(contents["mimeType"].get!string == "application/gzip");
	assert(contents["blob"].get!string == b64);

	// The index entry lists the archive with the matching url, mime, and digest.
	Json ip = Json.emptyObject;
	ip["uri"] = skillIndexUri;
	auto idx = s.handle(Message(makeRequest(Json(2), "resources/read", ip)))
		.get["result"]["contents"][0];
	auto doc = parseJsonString(idx["text"].get!string);
	auto archive = doc["skills"][0]["archives"][0];
	assert(archive["url"].get!string == "skill://pdf.tar.gz");
	assert(archive["mimeType"].get!string == "application/gzip");
	assert(archive["digest"].get!string == skillDigest(raw));
}

unittest  // registerSkill rejects an invalid skill path
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
	assert(doc["skills"][0]["frontmatter"]["name"].get!string == "alpha");
	assert(doc["skills"][1]["frontmatter"]["name"].get!string == "beta");
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

unittest  // SkillEntry.fromJson reads frontmatter, url, digest, and archives
{
	import vibe.data.json : parseJsonString;

	auto e = SkillEntry.fromJson(parseJsonString(`{
		"frontmatter": {"name": "refunds", "description": "d"},
		"url": "skill://acme/billing/refunds/SKILL.md",
		"digest": "sha256:abc",
		"archives": [{"url": "skill://acme/billing/refunds.tar.gz",
			"mimeType": "application/gzip", "digest": "sha256:def"}]
	}`));
	assert(e.name == "refunds");
	assert(e.description == "d");
	assert(e.url == "skill://acme/billing/refunds/SKILL.md");
	assert(e.digest == "sha256:abc");
	assert(e.archives.length == 1);
	assert(e.archives[0].mimeType == "application/gzip");
	assert(e.archives[0].digest == "sha256:def");
}

version (unittest)
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	// Build a draft-version request so `resources/directory/read` (draft-gated)
	// is routed; mirrors the server's own `draftReq` test helper.
	private Message draftRequest(long id, string method, Json params) @safe
	{
		import mcp.protocol.mrtr : MetaKey;

		Json m = Json.emptyObject;
		m[MetaKey.protocolVersion] = "2026-07-28";
		m[MetaKey.clientInfo] = Json(["name": Json("c"), "version": Json("1")]);
		m[MetaKey.clientCapabilities] = Json.emptyObject;
		params["_meta"] = m;
		return Message(makeRequest(Json(id), method, params));
	}

	private McpServer pdfSkillServer() @safe
	{
		auto s = new McpServer("t", "1");
		Skill sk = {
			path: "office/pdf-forms", description: "Process PDFs", instructions: "# PDF\n", files: [
				SkillFile("references/FORMS.md", "text/markdown", "# Forms\n")
			]
		};
		registerSkill(s, sk);
		return s;
	}
}

unittest  // resources/directory/read lists a skill root's files and subdirectories
{
	auto s = pdfSkillServer();

	Json p = Json.emptyObject;
	p["uri"] = "skill://office/pdf-forms";
	auto res = s.handle(draftRequest(1, "resources/directory/read", p)).get["result"]["resources"];
	assert(res.length == 2);

	bool sawSkillMd, sawReferencesDir;
	foreach (i; 0 .. res.length)
	{
		auto child = res[i];
		if (child["uri"].get!string == "skill://office/pdf-forms/SKILL.md")
		{
			assert(child["name"].get!string == "SKILL.md");
			sawSkillMd = true;
		}
		if (child["uri"].get!string == "skill://office/pdf-forms/references")
		{
			assert(child["name"].get!string == "references");
			assert(child["mimeType"].get!string == skillDirectoryMimeType);
			sawReferencesDir = true;
		}
	}
	assert(sawSkillMd && sawReferencesDir);
}

unittest  // resources/directory/read descends into a subdirectory
{
	auto s = pdfSkillServer();

	Json p = Json.emptyObject;
	p["uri"] = "skill://office/pdf-forms/references";
	auto res = s.handle(draftRequest(1, "resources/directory/read", p)).get["result"]["resources"];
	assert(res.length == 1);
	assert(res[0]["uri"].get!string == "skill://office/pdf-forms/references/FORMS.md");
	assert(res[0]["name"].get!string == "FORMS.md");
	assert(res[0]["mimeType"].get!string == "text/markdown");
}

unittest  // resources/directory/read on a file (not a directory) is -32602
{
	import mcp.protocol.errors : ErrorCode;

	auto s = pdfSkillServer();

	Json p = Json.emptyObject;
	p["uri"] = "skill://office/pdf-forms/SKILL.md";
	auto resp = s.handle(draftRequest(1, "resources/directory/read", p)).get;
	assert(resp["error"]["code"].get!int == cast(int) ErrorCode.invalidParams);
	assert(resp["error"]["data"]["uri"].get!string == "skill://office/pdf-forms/SKILL.md");
}

unittest  // resources/directory/read is -32601 when skills (and the method) are not enabled
{
	import mcp.protocol.errors : ErrorCode;

	auto s = new McpServer("t", "1");
	Json p = Json.emptyObject;
	p["uri"] = "skill://anything";
	auto resp = s.handle(draftRequest(1, "resources/directory/read", p)).get;
	assert(resp["error"]["code"].get!int == cast(int) ErrorCode.methodNotFound);
}

unittest  // resources/directory/read does not exist on a non-draft (stable) session
{
	import mcp.protocol.errors : ErrorCode;

	auto s = pdfSkillServer(); // enables the method on the draft path

	// A stable session (no draft _meta) never sees the draft-only method.
	Json p = Json.emptyObject;
	p["uri"] = "skill://office/pdf-forms";
	auto resp = s.handle(Message(makeRequest(Json(1), "resources/directory/read", p))).get;
	assert(resp["error"]["code"].get!int == cast(int) ErrorCode.methodNotFound);
}
