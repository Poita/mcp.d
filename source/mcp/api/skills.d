module mcp.api.skills;

import std.typecons : nullable;
import vibe.data.json : Json;

import mcp.server.server : McpServer;
import mcp.server.skill_index : SkillIndex;
import mcp.protocol.types : Resource, ResourceContents;

@safe:

/// The MCP Skills extension identifier (SEP-2640) — the key under
/// `capabilities.extensions` a server declares to advertise that it serves
/// Agent Skills as resources. Declaring it commits the server to the
/// `skills/list` and `skills/get` methods; `resources/directory/read` is
/// additionally gated behind the `directoryRead` capability setting. Skill
/// content itself rides the existing Resources primitive, so a host that
/// already treats resources as a virtual filesystem consumes MCP-served skills
/// identically to local ones. Note that no URI scheme marks a resource as a
/// skill — `skill://` included: a resource is known to be a skill only through
/// a `skills/list` entry or a `skills/get` answer.
enum string skillsExtensionKey = "io.modelcontextprotocol/skills";

/// The MIME type a `SKILL.md` resource declares (Agent Skills are Markdown with
/// YAML frontmatter).
enum string skillMimeType = "text/markdown";

/// The MIME type SEP-2640 assigns to a directory resource — the `mimeType` that
/// marks a `resources/directory/read` child as a subdirectory the client can
/// descend into (rather than a file to read).
enum string skillDirectoryMimeType = "inode/directory";

/// The most `resources` entries a single skill may carry, `SKILL.md` included.
/// The Skills extension fixes this so servers know what every conforming host
/// accepts; a skill over the limit is not guaranteed to be loadable anywhere,
/// so registration rejects it.
enum size_t maxSkillResources = 512;

/// The largest total file size a single skill may carry: the sum of `size` over
/// its `resources` entries, `SKILL.md` included (16 MiB). Registration rejects
/// a skill over the limit for the same reason as `maxSkillResources`.
enum size_t maxSkillTotalBytes = 16 * 1024 * 1024;

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

/// A declarative skill: a `SKILL.md` (its `instructions` body, with frontmatter
/// synthesized from `path`'s final segment, `description`, and `metadata`) plus
/// any supporting `files`. Register it with `registerSkill`; the `@skill` UDA
/// builds one of these from an annotated method.
struct Skill
{
	/// The skill path: a `/`-separated locator whose final segment is the skill
	/// name (lowercase alphanumeric + single hyphens). May be a single segment
	/// (`git-workflow`) or carry an organizational prefix (`acme/billing/refunds`).
	string path;
	string description; /// one-line description of when to use the skill
	string instructions; /// the `SKILL.md` body (Markdown; frontmatter is synthesized)
	/// Optional extra frontmatter under `metadata:`. Keys prefixed
	/// `io.modelcontextprotocol/` are reserved for metadata defined by MCP
	/// extensions (none are currently defined).
	string[string] metadata;
	SkillFile[] files; /// optional supporting files served as sibling resources

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

/// A `sha256:<hex>` digest of `bytes`, the integrity form SEP-2640 requires for
/// entry `digest` fields (lowercase hex of the SHA-256 of the artifact's raw
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
/// requires in each skill entry — identical in content to the `SKILL.md` it
/// describes.
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

/// Advertise the SEP-2640 skills extension on `server`, committing it to the
/// `skills/list` and `skills/get` methods (served by the McpServer core from
/// whatever skills are registered). Idempotent: safe to call before every
/// `registerSkill`, and called for you by `registerSkill` and the `@skill` UDA.
/// Declare it (directly or via a `registerSkill`) before `initialize` /
/// `server/discover` so the extension appears in the negotiated capabilities.
void enableSkills(McpServer server) @safe
{
	auto index = server.ensureSkillIndex();
	if (index.enabled)
		return;
	index.enabled = true;

	// Advertise the extension with `directoryRead: true` and turn the method on:
	// this SDK serves skills as individual file resources, so `resources/directory/read`
	// can scope-list any skill subtree. Done once, on the first skill — repeated
	// `registerSkill` calls must not re-clobber the negotiated settings.
	Json settings = Json.emptyObject;
	settings["directoryRead"] = true;
	server.enableExtension(skillsExtensionKey, settings);
	server.enableDirectoryRead();
}

/// Add a fully-built skill entry (`{uri, frontmatter, resources}`) to the
/// server's skill index, where `skills/list` and `skills/get` serve it from.
/// Throws if an entry with the same `uri` is already registered.
package(mcp) void addSkillEntry(McpServer server, Json entry) @safe
{
	auto index = server.ensureSkillIndex();
	const uri = entry["uri"].get!string;
	if (uri in index.byUri)
		throw new Exception("a skill entry for '" ~ uri ~ "' is already registered");
	index.byUri[uri] = entry;
	index.order ~= uri;
}

// Build a resource reader that closes over its file/uri by PARAMETER. Capturing a
// foreach-body local directly in the lambda would share a single closure frame
// across iterations — every reader would then serve the last file registered — so
// the per-resource values must be passed as function arguments instead.
private ResourceContents delegate() @safe makeFileReader(SkillFile f, string uri) @safe
{
	return () @safe => f.isBlob ? ResourceContents.makeBlob(uri, f.mimeType,
			f.content) : ResourceContents.makeText(uri, f.mimeType, f.content);
}

/// Register `skill` on `server`: serve its `SKILL.md` (with synthesized
/// frontmatter) at `skill://<path>/SKILL.md`, serve each supporting file at
/// `skill://<path>/<file>`, advertise the skills extension, and add a conformant
/// entry — verbatim `frontmatter`, the `SKILL.md` `uri`, and the per-file
/// `resources` manifest — for `skills/list` / `skills/get` to serve. Throws if
/// `path` is not a valid skill path (see `isValidSkillPath`).
void registerSkill(McpServer server, Skill skill) @safe
{
	const name = skill.name;
	registerSkillResources(server, skill.path, skillMarkdown(name, skill.description,
			skill.instructions, skill.metadata), frontmatterJson(name,
			skill.description, skill.metadata), skill.files);
}

/// The shared registration core both `registerSkill` (which synthesizes the
/// `SKILL.md` and frontmatter from a `Skill`) and `registerSkillDir` (which
/// reads them from a local directory) funnel into: serve `skillMd` verbatim at
/// `skill://<path>/SKILL.md`, serve each supporting file resource, and add the
/// conformant skill entry — verbatim `frontmatter`, the `SKILL.md` `uri`, and
/// the complete per-file `resources` manifest of `{uri, digest, size}` entries
/// (the `SKILL.md`'s own entry first) — for `skills/list` / `skills/get` to
/// serve. Rejects a skill over the extension's fixed limits (`maxSkillResources`
/// entries, `maxSkillTotalBytes` bytes), which no conforming host is required to
/// load.
/// `frontmatter` is the entry's `frontmatter` object — for a directory skill
/// the authored YAML parsed to JSON, for a `Skill` the synthesized
/// `{name, description, metadata}`. Throws if `path` is not a valid skill path
/// (see `isValidSkillPath`) or the skill is already registered.
package(mcp) void registerSkillResources(McpServer server, string path,
		string skillMd, Json frontmatter, SkillFile[] files) @safe
{
	import std.base64 : Base64;
	import std.conv : to;

	if (!isValidSkillPath(path))
		throw new Exception("invalid skill path '" ~ path
				~ "': each '/'-separated segment must be non-empty and the final segment "
				~ "must be a valid skill name (1..64 chars of lowercase letters, digits, "
				~ "and single hyphens, no leading/trailing/consecutive hyphens)");

	const name = skillName(path);
	const uri = skillUri(path);

	if (uri in server.ensureSkillIndex().byUri)
		throw new Exception("a skill at '" ~ uri ~ "' is already registered");

	if (files.length + 1 > maxSkillResources)
		throw new Exception("skill '" ~ path ~ "' has " ~ (files.length + 1)
				.to!string ~ " resources (SKILL.md included); the Skills extension "
				~ "allows at most " ~ maxSkillResources.to!string);

	// Build the complete per-file resources manifest — SKILL.md's own {uri,
	// digest, size} first, then every supporting file, each digesting and
	// measuring the bytes it serves (a blob file's digest and size cover its
	// decoded bytes, not the base64 transport form). Doing this up front keeps
	// every throw-capable step (URI collisions, undecodable base64, the total
	// size limit) ahead of any server mutation, so a failed registration can
	// always roll back cleanly.
	bool[string] localUris;
	localUris[uri] = true;
	Json manifest = Json.emptyArray;
	manifest ~= resourceRef(uri, skillDigest(cast(const(ubyte)[]) skillMd), skillMd.length);
	size_t total = skillMd.length;
	foreach (file; files)
	{
		const fu = skillFileUri(path, file.path);
		if (fu in localUris)
			throw new Exception("duplicate skill resource uri '" ~ fu
					~ "' (a supporting file path collides with another file or with SKILL.md)");
		localUris[fu] = true;
		const(ubyte)[] bytes = file.isBlob
			? Base64.decode(file.content) : cast(const(ubyte)[]) file.content;
		total += bytes.length;
		if (total > maxSkillTotalBytes)
			throw new Exception(
					"skill '" ~ path ~ "' totals more than " ~ maxSkillTotalBytes.to!string
					~ " bytes across its files; the Skills "
					~ "extension allows at most 16 MiB per skill");
		manifest ~= resourceRef(fu, skillDigest(bytes), bytes.length);
	}

	enableSkills(server);

	// Roll back any resources registered for THIS skill if a later registration
	// throws (e.g. a URI already taken by another skill), so a failed registration
	// never leaves orphaned resources behind. The entry is added last, after every
	// resource is in place, so a throw can never leave a listed-but-unserved skill.
	string[] registered;
	scope (failure)
		foreach (u; registered)
			server.removeResource(u);

	Resource descriptor;
	descriptor.uri = uri;
	descriptor.name = name;
	if (frontmatter.type == Json.Type.object && "description" in frontmatter
			&& frontmatter["description"].type == Json.Type.string)
		descriptor.description = nullable(frontmatter["description"].get!string);
	descriptor.mimeType = nullable(skillMimeType);
	server.registerResource(descriptor, () @safe {
		return ResourceContents.makeText(uri, skillMimeType, skillMd);
	});
	registered ~= uri;

	foreach (file; files)
	{
		const fileUri = skillFileUri(path, file.path);
		Resource fileDescriptor;
		fileDescriptor.uri = fileUri;
		fileDescriptor.name = file.path;
		if (file.mimeType.length)
			fileDescriptor.mimeType = nullable(file.mimeType);
		// The reader is built by a factory so it captures THIS file by parameter
		// (see makeFileReader): a lambda over the loop-body local would alias.
		server.registerResource(fileDescriptor, makeFileReader(file, fileUri));
		registered ~= fileUri;
	}

	Json entry = Json.emptyObject;
	entry["uri"] = uri;
	entry["frontmatter"] = frontmatter;
	entry["resources"] = manifest;
	addSkillEntry(server, entry);
}

/// One `{uri, digest, size}` element of a skill entry's `resources` manifest:
/// the file's URI, the `sha256:` digest of its raw bytes, and the byte length
/// those same bytes have.
package(mcp) Json resourceRef(string uri, string digest, size_t size) @safe
{
	Json r = Json.emptyObject;
	r["uri"] = uri;
	r["digest"] = digest;
	r["size"] = cast(long) size;
	return r;
}

/// Convenience overload registering a skill from its parts (no supporting files
/// or metadata). Equivalent to `registerSkill(server, Skill(path, description,
/// instructions))`.
void registerSkill(McpServer server, string path, string description, string instructions) @safe
{
	registerSkill(server, Skill(path, description, instructions));
}

/// A skill whose `SKILL.md` body is generated on each read, so no stable digest
/// can be published for it: its entry carries `resources: "dynamic"` instead of
/// a manifest. The frontmatter is fixed — synthesized from `path`'s final
/// segment, `description`, and `metadata` exactly as for a `Skill` — so the
/// entry's `frontmatter` stays identical to what every read returns; only the
/// body varies. Register it with `registerDynamicSkill`.
///
/// A dynamic skill offers hosts no content integrity and cannot be
/// content-bound to an approval, so some hosts decline to load one; prefer a
/// static `Skill` whenever the content can be fixed at registration. Supporting
/// files, if any, are registered separately with `McpServer.registerResource`
/// under `skill://<path>/…`; hosts discover them via `resources/directory/read`.
struct DynamicSkill
{
	/// The skill path; final segment is the skill name (see `Skill.path`).
	string path;
	string description; /// one-line description of when to use the skill
	/// Produces the `SKILL.md` body (Markdown, without frontmatter) for one read.
	string delegate() @safe instructions;
	/// Optional extra frontmatter under `metadata:` (see `Skill.metadata`).
	string[string] metadata;

	/// The skill name: the final segment of `path`.
	string name() const @safe pure
	{
		return skillName(path);
	}
}

/// Register `skill` on `server`: serve a `SKILL.md` at `skill://<path>/SKILL.md`
/// whose body `skill.instructions` regenerates on every read beneath fixed,
/// synthesized frontmatter, advertise the skills extension, and add an entry
/// with `resources: "dynamic"` for `skills/list` / `skills/get` to serve. Throws
/// if `path` is not a valid skill path, `instructions` is null, or a skill is
/// already registered at that URI.
void registerDynamicSkill(McpServer server, DynamicSkill skill) @safe
{
	if (!isValidSkillPath(skill.path))
		throw new Exception("invalid skill path '" ~ skill.path
				~ "': each '/'-separated segment must be non-empty and the final segment "
				~ "must be a valid skill name (1..64 chars of lowercase letters, digits, "
				~ "and single hyphens, no leading/trailing/consecutive hyphens)");
	if (skill.instructions is null)
		throw new Exception("registerDynamicSkill: '" ~ skill.path
				~ "' has no instructions delegate");

	const name = skill.name;
	const uri = skillUri(skill.path);
	if (uri in server.ensureSkillIndex().byUri)
		throw new Exception("a skill at '" ~ uri ~ "' is already registered");

	enableSkills(server);

	Resource descriptor;
	descriptor.uri = uri;
	descriptor.name = name;
	descriptor.description = nullable(skill.description);
	descriptor.mimeType = nullable(skillMimeType);
	// Copied into locals so the reader closure captures values, not the struct.
	string description = skill.description;
	string[string] metadata = skill.metadata;
	auto body_ = skill.instructions;
	server.registerResource(descriptor, () @safe {
		return ResourceContents.makeText(uri, skillMimeType,
			skillMarkdown(name, description, body_(), metadata));
	});
	// The entry is added last, after the resource is in place, so a throw here
	// leaves no listed-but-unserved skill; the resource is rolled back to match.
	scope (failure)
		server.removeResource(uri);

	Json entry = Json.emptyObject;
	entry["uri"] = uri;
	entry["frontmatter"] = frontmatterJson(name, description, metadata);
	entry["resources"] = "dynamic";
	addSkillEntry(server, entry);
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

/// One `{uri, digest, size}` entry from a skill entry's `resources` manifest: a
/// file the skill serves, the sha256 of the bytes it serves, and how many bytes
/// those are.
struct SkillResourceRef
{
	string uri; /// resource URI of the file
	string digest; /// `sha256:<hex>` digest of the file's raw bytes
	long size; /// byte length of the file's raw content (the bytes `digest` covers)

	static SkillResourceRef fromJson(Json j) @safe
	{
		SkillResourceRef r;
		if ("uri" in j && j["uri"].type == Json.Type.string)
			r.uri = j["uri"].get!string;
		if ("digest" in j && j["digest"].type == Json.Type.string)
			r.digest = j["digest"].get!string;
		if ("size" in j && j["size"].type == Json.Type.int_)
			r.size = j["size"].get!long;
		return r;
	}
}

/// One skill entry, as carried by `skills/list` and `skills/get`. `name` and
/// `description` are read from the verbatim `frontmatter` object (always present
/// per the Agent Skills spec); `uri` addresses the `SKILL.md` directly, and
/// `resources` is the complete per-file manifest a host verifies reads against.
/// A dynamically generated skill publishes the string `"dynamic"` in place of a
/// manifest: `isDynamic` is set and `resources` is empty, and the skill offers
/// no content integrity. An entry with neither (`!isValid`) is malformed and
/// must not be loaded. Within the frontmatter's `metadata` object, keys prefixed
/// `io.modelcontextprotocol/` are reserved for MCP extensions; ignore
/// unrecognized keys under that prefix.
struct SkillEntry
{
	string uri; /// resource URI of the `SKILL.md`
	Json frontmatter; /// verbatim `SKILL.md` frontmatter as JSON
	SkillResourceRef[] resources; /// complete `{uri, digest, size}` manifest of the skill's files
	bool isDynamic; /// `resources` was the string `"dynamic"`: generated content, no digests

	/// Whether `resources` took one of the two shapes the extension allows: a
	/// manifest array (never legitimately empty, as it always lists `SKILL.md`)
	/// or the string `"dynamic"`. A host must not load an entry that is not valid.
	bool isValid() const @safe pure nothrow
	{
		return isDynamic || resources.length > 0;
	}

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
		if ("uri" in j && j["uri"].type == Json.Type.string)
			e.uri = j["uri"].get!string;
		if ("frontmatter" in j)
			e.frontmatter = j["frontmatter"];
		if ("resources" in j && j["resources"].type == Json.Type.array)
			foreach (i; 0 .. j["resources"].length)
				e.resources ~= SkillResourceRef.fromJson(j["resources"][i]);
		else if ("resources" in j && j["resources"].type == Json.Type.string
						&& j["resources"].get!string == "dynamic")
					e.isDynamic = true;
		return e;
	}
}

/// The skills the server publishes, via `skills/list` (paginating to
/// completion). May be empty — which, per the spec, does NOT prove the server
/// has no skills: large or generated catalogs may list nothing, and a skill
/// known only by URI is still readable and retrievable via `getSkill`.
SkillEntry[] listSkills(McpClient client) @safe
{
	SkillEntry[] entries;
	auto result = client.skillsList();
	foreach (s; result.skills)
		entries ~= SkillEntry.fromJson(s);
	return entries;
}

/// The entry for the single skill whose `SKILL.md` URI is `uri`, via
/// `skills/get` — the same `{uri, frontmatter, resources}` a listing would
/// carry, available even for skills no listing mentioned. Throws `McpException`
/// (-32602) if the server does not serve `uri` as a skill.
SkillEntry getSkill(McpClient client, string uri) @safe
{
	return SkillEntry.fromJson(client.skillsGet(uri).skill);
}

/// Verify `bytes`, read from `uri`, against `entry`'s `resources` manifest, as
/// the Skills extension requires of hosts: the file must be listed in the
/// manifest, its byte length must equal the entry's `size`, and its digest must
/// match the bytes. Returns `null` on success, or a reason string on failure —
/// an unlisted file or a length mismatch is a verification failure equivalent
/// to a digest mismatch, and a skill without `resources` offers no integrity at
/// all. Whatever the cause, failed content must not be used; refresh the entry
/// via `getSkill` and re-read.
string verifyResourceDigest(const SkillEntry entry, string uri, scope const(ubyte)[] bytes) @safe
{
	import std.conv : to;

	if (entry.isDynamic)
		return "the skill is dynamic (its entry publishes no digests), so its content cannot be verified";
	if (entry.resources.length == 0)
		return "the skill entry carries no resources manifest, so its content cannot be verified";
	foreach (r; entry.resources)
	{
		if (r.uri != uri)
			continue;
		if (r.size != bytes.length)
			return "size mismatch for " ~ uri ~ ": manifest lists " ~ r.size.to!string
				~ " bytes but the content is " ~ bytes.length.to!string ~ " bytes";
		const actual = skillDigest(bytes);
		if (actual != r.digest)
			return "digest mismatch for " ~ uri ~ ": manifest lists " ~ r.digest
				~ " but the content hashes to " ~ actual;
		return null;
	}
	return uri ~ " is not listed in the skill's resources manifest";
}

/// Check `entry` against the extension's fixed per-skill limits, which its
/// complete `resources` manifest makes decidable before any file is fetched: at
/// most `maxSkillResources` entries and at most `maxSkillTotalBytes` bytes in
/// total. Returns `null` when the skill is within both limits (or has no
/// manifest to count), else a reason a host can show the user for declining it.
string checkSkillLimits(const SkillEntry entry) @safe
{
	import std.conv : to;

	if (entry.resources.length > maxSkillResources)
		return "the skill lists " ~ entry.resources.length.to!string
			~ " resources; the Skills extension allows at most " ~ maxSkillResources.to!string;
	long total;
	foreach (r; entry.resources)
		total += r.size;
	if (total > maxSkillTotalBytes)
		return "the skill's files total " ~ total.to!string
			~ " bytes; the Skills extension allows at most 16 MiB ("
			~ maxSkillTotalBytes.to!string ~ " bytes)";
	return null;
}

/// Read a skill's `SKILL.md` by its resource URI — a wrapper over
/// `resources/read`. Works whether or not the skill appears in any listing (a
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
	assert(skillUri("git-workflow") == "skill://git-workflow/SKILL.md");
	assert(skillFileUri("pdf", "references/FORMS.md") == "skill://pdf/references/FORMS.md");
}

unittest  // the Skills extension negotiates from 2025-11-25
{
	import mcp.protocol.capabilities : extensionMinVersion;
	import mcp.protocol.versions : ProtocolVersion;

	assert(extensionMinVersion(skillsExtensionKey) == ProtocolVersion.v2025_11_25);
}

unittest  // a prefixed skill path maps to a nested skill:// URI
{
	assert(skillUri("acme/billing/refunds") == "skill://acme/billing/refunds/SKILL.md");
	assert(skillName("acme/billing/refunds") == "refunds");
	assert(skillName("git-workflow") == "git-workflow");
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

unittest  // enableSkills advertises the extension (with directoryRead) and nothing else
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.mrtr : MetaKey;

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
}

unittest  // there is no skill://index.json — the old discovery resource is gone
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = pdfSkillServer();
	Json rp = Json.emptyObject;
	rp["uri"] = "skill://index.json";
	auto resp = s.handle(Message(makeRequest(Json(1), "resources/read", rp))).get;
	assert("error" in resp, "skill://index.json must not be served as a resource");
}

unittest  // registerSkill serves SKILL.md and skills/list carries a conformant entry
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

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

	// skills/list carries the entry: verbatim frontmatter, the SKILL.md uri, and
	// a complete per-file resources manifest.
	auto result = s.handle(Message(makeRequest(Json(2), "skills/list",
			Json.emptyObject))).get["result"];
	assert(result["skills"].length == 1);
	auto e = result["skills"][0];
	assert(e["frontmatter"]["name"].get!string == "git-workflow");
	assert(e["frontmatter"]["description"].get!string == "Follow Git conventions");
	assert(e["uri"].get!string == "skill://git-workflow/SKILL.md");
	assert("url" !in e); // the pre-method field name is gone
	assert("digest" !in e); // the single SKILL.md digest is gone
	// The manifest includes an entry matching the skill's own uri, carrying the
	// digest of the served SKILL.md bytes.
	assert(e["resources"].length == 1);
	assert(e["resources"][0]["uri"].get!string == e["uri"].get!string);
	assert(e["resources"][0]["digest"].get!string == skillDigest(cast(const(ubyte)[]) md));
}

unittest  // a skill's resources manifest lists every file exactly once with its digest
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import std.base64 : Base64;

	auto s = new McpServer("t", "1");
	const raw = cast(const(ubyte)[]) "\x00binary\xff";
	Skill sk = {
		path: "pdf", description: "Process PDFs", instructions: "# PDF\n",
		files: [
				SkillFile("references/FORMS.md", "text/markdown", "# Forms\n"),
				SkillFile("assets/logo.bin", "application/octet-stream",
						Base64.encode(raw).idup, true)
		]
	};
	registerSkill(s, sk);

	auto e = s.handle(Message(makeRequest(Json(1), "skills/list",
			Json.emptyObject))).get["result"]["skills"][0];
	auto res = e["resources"];
	assert(res.length == 3); // SKILL.md + two supporting files, each exactly once

	string digestFor(string uri) @safe
	{
		foreach (i; 0 .. res.length)
			if (res[i]["uri"].get!string == uri)
				return res[i]["digest"].get!string;
		assert(false, "manifest is missing " ~ uri);
	}

	// A text file's digest covers its UTF-8 bytes; a blob file's digest covers
	// the decoded bytes it serves, not the base64 transport encoding.
	assert(digestFor("skill://pdf/references/FORMS.md") == skillDigest(
			cast(const(ubyte)[]) "# Forms\n"));
	assert(digestFor("skill://pdf/assets/logo.bin") == skillDigest(raw));
}

unittest  // every manifest entry carries the byte length of the content its digest covers
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import std.base64 : Base64;

	auto s = new McpServer("t", "1");
	const raw = cast(const(ubyte)[]) "\x00binary\xff";
	Skill sk = {
		path: "pdf", description: "Process PDFs", instructions: "# PDF\n",
		files: [
				SkillFile("references/FORMS.md", "text/markdown", "# Forms\n"),
				SkillFile("assets/logo.bin", "application/octet-stream",
						Base64.encode(raw).idup, true)
		]
	};
	registerSkill(s, sk);

	auto e = s.handle(Message(makeRequest(Json(1), "skills/list",
			Json.emptyObject))).get["result"]["skills"][0];
	auto res = e["resources"];

	long sizeFor(string uri) @safe
	{
		foreach (i; 0 .. res.length)
			if (res[i]["uri"].get!string == uri)
				return res[i]["size"].get!long;
		assert(false, "manifest is missing " ~ uri);
	}

	// SKILL.md's size is the length of the rendered markdown it serves.
	Json rp = Json.emptyObject;
	rp["uri"] = "skill://pdf/SKILL.md";
	const md = s.handle(Message(makeRequest(Json(2), "resources/read", rp)))
		.get["result"]["contents"][0]["text"].get!string;
	assert(sizeFor("skill://pdf/SKILL.md") == md.length);
	assert(sizeFor("skill://pdf/references/FORMS.md") == "# Forms\n".length);
	// A blob's size counts the decoded bytes, not the base64 transport form.
	assert(sizeFor("skill://pdf/assets/logo.bin") == raw.length);
}

unittest  // a skill with more than 512 resources (SKILL.md included) is rejected
{
	import std.exception : assertThrown, assertNotThrown;

	assert(maxSkillResources == 512);

	SkillFile[] files;
	foreach (i; 0 .. maxSkillResources - 1) // + SKILL.md = exactly the limit
	{
		import std.conv : to;

		files ~= SkillFile("f" ~ i.to!string ~ ".txt", "text/plain", "x");
	}
	Skill atLimit = {
		path: "at-limit", description: "d", instructions: "# A\n", files: files
	};
	assertNotThrown!Exception(registerSkill(new McpServer("t", "1"), atLimit));

	files ~= SkillFile("one-too-many.txt", "text/plain", "x");
	Skill over = {
		path: "over", description: "d", instructions: "# O\n", files: files
	};
	assertThrown!Exception(registerSkill(new McpServer("t", "1"), over));
}

unittest  // a skill whose files total more than 16 MiB is rejected
{
	import std.exception : assertThrown;

	assert(maxSkillTotalBytes == 16_777_216);

	// SKILL.md plus one file of exactly the limit exceeds it by the SKILL.md bytes.
	import std.array : replicate;

	Skill sk = {
		path: "huge", description: "d", instructions: "# H\n", files: [
			SkillFile("big.txt", "text/plain", "a".replicate(maxSkillTotalBytes))
		]
	};
	assertThrown!Exception(registerSkill(new McpServer("t", "1"), sk));
}

unittest  // skills/list paginates whole entries with cursor/nextCursor
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	s.setPageSize(1);
	registerSkill(s, "alpha", "First", "a");
	registerSkill(s, "beta", "Second", "b");

	auto page1 = s.handle(Message(makeRequest(Json(1), "skills/list",
			Json.emptyObject))).get["result"];
	assert(page1["skills"].length == 1);
	assert(page1["skills"][0]["frontmatter"]["name"].get!string == "alpha");
	assert(page1["nextCursor"].type == Json.Type.string);

	Json p2 = Json.emptyObject;
	p2["cursor"] = page1["nextCursor"];
	auto page2 = s.handle(Message(makeRequest(Json(2), "skills/list", p2))).get["result"];
	assert(page2["skills"].length == 1);
	assert(page2["skills"][0]["frontmatter"]["name"].get!string == "beta");
	assert("nextCursor" !in page2);
}

unittest  // skills/list on a server with the extension but no skills is empty
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	enableSkills(s);
	auto result = s.handle(Message(makeRequest(Json(1), "skills/list",
			Json.emptyObject))).get["result"];
	assert(result["skills"].type == Json.Type.array);
	assert(result["skills"].length == 0);
}

unittest  // skills/get returns the same entry skills/list carries
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = pdfSkillServer();

	auto listed = s.handle(Message(makeRequest(Json(1), "skills/list",
			Json.emptyObject))).get["result"]["skills"][0];
	Json p = Json.emptyObject;
	p["uri"] = "skill://office/pdf-forms/SKILL.md";
	auto got = s.handle(Message(makeRequest(Json(2), "skills/get", p))).get["result"]["skill"];
	assert(got == listed);
}

unittest  // skills/get for a URI that is not a served skill is a flat -32602
{
	import mcp.protocol.errors : ErrorCode;
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = pdfSkillServer();

	// A supporting file of a skill is not itself a skill; nor is an unknown URI.
	foreach (uri; [
		"skill://office/pdf-forms/references/FORMS.md", "skill://nope/SKILL.md"
	])
	{
		Json p = Json.emptyObject;
		p["uri"] = uri;
		auto resp = s.handle(Message(makeRequest(Json(1), "skills/get", p))).get;
		assert(resp["error"]["code"].get!int == cast(int) ErrorCode.invalidParams);
		assert(resp["error"]["data"]["uri"].get!string == uri);
	}
}

unittest  // skills/get without a string uri is -32602
{
	import mcp.protocol.errors : ErrorCode;
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = pdfSkillServer();
	auto resp = s.handle(Message(makeRequest(Json(1), "skills/get", Json.emptyObject))).get;
	assert(resp["error"]["code"].get!int == cast(int) ErrorCode.invalidParams);
}

unittest  // skills/list and skills/get are -32601 when skills are not enabled
{
	import mcp.protocol.errors : ErrorCode;
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	foreach (method; ["skills/list", "skills/get"])
	{
		auto resp = s.handle(Message(makeRequest(Json(1), method, Json.emptyObject))).get;
		assert(resp["error"]["code"].get!int == cast(int) ErrorCode.methodNotFound);
	}
}

unittest  // skills/list and skills/get do not exist below 2025-11-25
{
	import mcp.protocol.errors : ErrorCode;
	import mcp.protocol.versions : ProtocolVersion;
	import mcp.server.connection : ConnectionState;
	import vibe.data.json : parseJsonString;

	auto s = pdfSkillServer();

	auto conn = new ConnectionState;
	conn.negotiated = ProtocolVersion.v2025_06_18;
	foreach (method; ["skills/list", "skills/get"])
	{
		auto outText = s.handleRaw(`{"jsonrpc":"2.0","id":1,"method":"` ~ method
				~ `","params":{"uri":"skill://office/pdf-forms/SKILL.md"}}`, conn);
		auto resp = parseJsonString(outText);
		assert(resp["error"]["code"].get!int == cast(int) ErrorCode.methodNotFound);
	}
}

unittest  // a modern-session skills/list result carries the required ttlMs/cacheScope
{
	auto s = pdfSkillServer();

	auto result = s.handle(draftRequest(1, "skills/list", Json.emptyObject)).get["result"];
	assert(result["skills"].length == 1);
	// ListSkillsResult extends CacheableResult: both fields are REQUIRED, with the
	// conservative do-not-cache default when the application configured no hint.
	assert(result["ttlMs"].get!long == 0);
	assert(result["cacheScope"].get!string == "public");
	assert(result["resultType"].get!string == "complete");
}

unittest  // a modern-session skills/get result carries the required ttlMs/cacheScope
{
	auto s = pdfSkillServer();

	Json p = Json.emptyObject;
	p["uri"] = "skill://office/pdf-forms/SKILL.md";
	auto result = s.handle(draftRequest(1, "skills/get", p)).get["result"];
	assert(result["skill"]["uri"].get!string == "skill://office/pdf-forms/SKILL.md");
	assert(result["ttlMs"].get!long == 0);
	assert(result["cacheScope"].get!string == "public");
	assert(result["resultType"].get!string == "complete");
	assert("nextCursor" !in result);
}

unittest  // setListCacheHint configures the skills/list and skills/get freshness hints
{
	import core.time : minutes;
	import mcp.protocol.modern : CacheHint, CacheScope;

	auto s = pdfSkillServer();
	s.setListCacheHint("skills/list", CacheHint(5.minutes));
	s.setListCacheHint("skills/get", CacheHint(1.minutes, CacheScope.private_));

	auto listed = s.handle(draftRequest(1, "skills/list", Json.emptyObject)).get["result"];
	assert(listed["ttlMs"].get!long == 300_000);
	assert(listed["cacheScope"].get!string == "public");

	Json p = Json.emptyObject;
	p["uri"] = "skill://office/pdf-forms/SKILL.md";
	auto got = s.handle(draftRequest(2, "skills/get", p)).get["result"];
	assert(got["ttlMs"].get!long == 60_000);
	assert(got["cacheScope"].get!string == "private");
}

unittest  // a 2025-11-25 session's skills results carry no caching attributes
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	// The base protocol at 2025-11-25 has no CacheableResult, so the fields the
	// extension inherits from it at 2026-07-28 and later are not written there.
	auto s = pdfSkillServer();
	auto listed = s.handle(Message(makeRequest(Json(1), "skills/list",
			Json.emptyObject))).get["result"];
	assert("ttlMs" !in listed && "cacheScope" !in listed && "resultType" !in listed);

	Json p = Json.emptyObject;
	p["uri"] = "skill://office/pdf-forms/SKILL.md";
	auto got = s.handle(Message(makeRequest(Json(2), "skills/get", p))).get["result"];
	assert("ttlMs" !in got && "cacheScope" !in got && "resultType" !in got);
}

unittest  // a modern-session resources/directory/read result carries resultType:"complete"
{
	auto s = pdfSkillServer();
	Json p = Json.emptyObject;
	p["uri"] = "skill://office/pdf-forms";
	auto result = s.handle(draftRequest(1, "resources/directory/read", p)).get["result"];
	assert(result["resultType"].get!string == "complete");
}

unittest  // declaring the skills extension also declares the resources capability
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.mrtr : MetaKey;

	// Skill files are served through resources/read, and the base Resources spec
	// requires a server that supports resources to declare the capability — even
	// before the first skill (and so the first resource) is registered.
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
	assert("resources" in caps);

	// The same holds on the 2025-11-25 initialize handshake.
	Json init = Json.emptyObject;
	init["protocolVersion"] = "2025-11-25";
	init["capabilities"] = Json.emptyObject;
	init["clientInfo"] = Json(["name": Json("c"), "version": Json("1")]);
	auto legacyCaps = s.handle(Message(makeRequest(Json(2), "initialize",
			init))).get["result"]["capabilities"];
	assert("resources" in legacyCaps);
}

unittest  // the skills error messages name the offending uri the way the spec's examples do
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = pdfSkillServer();

	Json p = Json.emptyObject;
	p["uri"] = "skill://acme/billing/chargebacks/SKILL.md";
	auto missing = s.handle(Message(makeRequest(Json(1), "skills/get", p))).get["error"];
	assert(missing["message"].get!string
			== "No skill is served at skill://acme/billing/chargebacks/SKILL.md");

	Json d = Json.emptyObject;
	d["uri"] = "skill://office/pdf-forms/SKILL.md";
	auto notDir = s.handle(draftRequest(2, "resources/directory/read", d)).get["error"];
	assert(notDir["message"].get!string
			== "skill://office/pdf-forms/SKILL.md is not a directory resource");
}

unittest  // registerDynamicSkill publishes an entry whose resources is the string "dynamic"
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	DynamicSkill sk = {
		path: "reports/daily", description: "Assemble today's operational report",
		instructions: () @safe => "# Daily\n"
	};
	registerDynamicSkill(s, sk);

	auto e = s.handle(Message(makeRequest(Json(1), "skills/list",
			Json.emptyObject))).get["result"]["skills"][0];
	assert(e["uri"].get!string == "skill://reports/daily/SKILL.md");
	assert(e["frontmatter"]["name"].get!string == "daily");
	assert(e["frontmatter"]["description"].get!string == "Assemble today's operational report");
	assert(e["resources"].type == Json.Type.string);
	assert(e["resources"].get!string == "dynamic");

	// skills/get carries the identical entry.
	Json p = Json.emptyObject;
	p["uri"] = "skill://reports/daily/SKILL.md";
	auto got = s.handle(Message(makeRequest(Json(2), "skills/get", p))).get["result"]["skill"];
	assert(got == e);
}

unittest  // a dynamic skill's SKILL.md is generated on each read, under fixed frontmatter
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import std.algorithm : canFind;
	import std.conv : to;

	auto s = new McpServer("t", "1");
	int reads;
	DynamicSkill sk = {
		path: "counter", description: "Counts reads", metadata: ["version": "1"],
		instructions: () @safe {
			reads++;
			return "# Read " ~ reads.to!string ~ "\n";
		}
	};
	registerDynamicSkill(s, sk);

	string read() @safe
	{
		Json rp = Json.emptyObject;
		rp["uri"] = "skill://counter/SKILL.md";
		auto c = s.handle(Message(makeRequest(Json(1), "resources/read", rp)))
			.get["result"]["contents"][0];
		assert(c["mimeType"].get!string == skillMimeType);
		return c["text"].get!string;
	}

	const first = read();
	const second = read();
	assert(first.canFind("# Read 1") && second.canFind("# Read 2"));
	// The frontmatter is fixed and identical to the entry's, however the body varies.
	assert(first.canFind("name: counter") && second.canFind("name: counter"));
	assert(first.canFind(`"version": "1"`));
	auto e = s.handle(Message(makeRequest(Json(3), "skills/list",
			Json.emptyObject))).get["result"]["skills"][0];
	assert(e["frontmatter"]["metadata"]["version"].get!string == "1");
}

unittest  // registerDynamicSkill rejects an invalid path and a duplicate uri
{
	import std.exception : assertThrown;

	auto s = new McpServer("t", "1");
	DynamicSkill bad = {
		path: "Bad Name", description: "d", instructions: () @safe => "x"
	};
	assertThrown!Exception(registerDynamicSkill(s, bad));

	registerSkill(s, "taken", "First", "a");
	DynamicSkill dup = {
		path: "taken", description: "d", instructions: () @safe => "x"
	};
	assertThrown!Exception(registerDynamicSkill(s, dup));
}

unittest  // a prefixed skill path lists frontmatter.name as the final segment
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerSkill(s, "acme/billing/refunds", "Process refunds", "# Refunds\n");

	Json rp = Json.emptyObject;
	rp["uri"] = skillUri("acme/billing/refunds");
	auto sm = s.handle(Message(makeRequest(Json(1), "resources/read", rp)))
		.get["result"]["contents"][0];
	assert(sm["text"].get!string.length > 0);

	auto e = s.handle(Message(makeRequest(Json(2), "skills/list",
			Json.emptyObject))).get["result"]["skills"][0];
	assert(e["frontmatter"]["name"].get!string == "refunds");
	assert(e["uri"].get!string == "skill://acme/billing/refunds/SKILL.md");
}

unittest  // metadata round-trips into the entry frontmatter as a nested object
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	Skill sk = {
		path: "pdf", description: "Process PDFs", instructions: "# PDF\n",
		metadata: ["version": "2.1.0"]
	};
	registerSkill(s, sk);

	auto e = s.handle(Message(makeRequest(Json(1), "skills/list",
			Json.emptyObject))).get["result"]["skills"][0];
	assert(e["frontmatter"]["metadata"]["version"].get!string == "2.1.0");
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

unittest  // each of several supporting files serves its OWN content (no reader aliasing)
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	Skill sk = {
		path: "multi", description: "Many files", instructions: "# Multi\n",
		files: [
				SkillFile("a.txt", "text/plain", "AAA"),
				SkillFile("b.md", "text/markdown", "BBB"),
				SkillFile("c.json", "application/json", "\"CCC\"")
		]
	};
	registerSkill(s, sk);

	string readBody(string uri) @safe
	{
		Json p = Json.emptyObject;
		p["uri"] = uri;
		return s.handle(Message(makeRequest(Json(1), "resources/read", p)))
			.get["result"]["contents"][0]["text"].get!string;
	}

	// A reader-aliasing bug would make every file serve the last one's content.
	assert(readBody("skill://multi/a.txt") == "AAA");
	assert(readBody("skill://multi/b.md") == "BBB");
	assert(readBody("skill://multi/c.json") == "\"CCC\"");
}

unittest  // registerSkill rejects an invalid skill path
{
	import std.exception : assertThrown;

	auto s = new McpServer("t", "1");
	assertThrown!Exception(registerSkill(s, "Bad Name", "d", "body"));
}

unittest  // a duplicate supporting-file path is rejected and rolls back cleanly
{
	import std.exception : assertThrown, assertNotThrown;
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import vibe.data.json : parseJsonString;

	auto s = new McpServer("t", "1");
	Skill bad = {
		path: "dup", description: "d", instructions: "# D\n", files: [
			SkillFile("a.txt", "text/plain", "one"),
			SkillFile("a.txt", "text/plain", "two")
		]
	};
	assertThrown!Exception(registerSkill(s, bad));

	// Rollback: the half-registered SKILL.md was removed, so the path is free and a
	// corrected skill registers cleanly as the only listed entry.
	Skill good = {
		path: "dup", description: "d", instructions: "# D\n", files: [
			SkillFile("a.txt", "text/plain", "one")
		]
	};
	assertNotThrown!Exception(registerSkill(s, good));

	auto result = s.handle(Message(makeRequest(Json(1), "skills/list",
			Json.emptyObject))).get["result"];
	assert(result["skills"].length == 1);
	assert(result["skills"][0]["frontmatter"]["name"].get!string == "dup");
}

unittest  // registering the same skill path twice is rejected, leaving one entry
{
	import std.exception : assertThrown;
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerSkill(s, "twice", "First", "a");
	assertThrown!Exception(registerSkill(s, "twice", "Second", "b"));

	// The first registration is intact: still listed once, still served.
	auto result = s.handle(Message(makeRequest(Json(1), "skills/list",
			Json.emptyObject))).get["result"];
	assert(result["skills"].length == 1);
	assert(result["skills"][0]["frontmatter"]["description"].get!string == "First");
}

unittest  // a supporting file named SKILL.md collides with the skill markdown and is rejected
{
	import std.exception : assertThrown;

	auto s = new McpServer("t", "1");
	Skill bad = {
		path: "x", description: "d", instructions: "# X\n", files: [
			SkillFile("SKILL.md", "text/markdown", "oops")
		]
	};
	assertThrown!Exception(registerSkill(s, bad));
}

unittest  // multiple skills accumulate in the listing in registration order
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerSkill(s, "alpha", "First", "a");
	registerSkill(s, "beta", "Second", "b");

	auto result = s.handle(Message(makeRequest(Json(1), "skills/list",
			Json.emptyObject))).get["result"];
	assert(result["skills"].length == 2);
	assert(result["skills"][0]["frontmatter"]["name"].get!string == "alpha");
	assert(result["skills"][1]["frontmatter"]["name"].get!string == "beta");
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

unittest  // SkillEntry.fromJson reads uri, frontmatter, and the resources manifest
{
	import vibe.data.json : parseJsonString;

	auto e = SkillEntry.fromJson(parseJsonString(`{
		"uri": "skill://acme/billing/refunds/SKILL.md",
		"frontmatter": {"name": "refunds", "description": "d"},
		"resources": [
			{"uri": "skill://acme/billing/refunds/SKILL.md", "digest": "sha256:abc"},
			{"uri": "skill://acme/billing/refunds/examples/email.md", "digest": "sha256:def"}
		]
	}`));
	assert(e.name == "refunds");
	assert(e.description == "d");
	assert(e.uri == "skill://acme/billing/refunds/SKILL.md");
	assert(e.resources.length == 2);
	assert(e.resources[0].uri == e.uri);
	assert(e.resources[0].digest == "sha256:abc");
	assert(e.resources[1].digest == "sha256:def");
}

unittest  // SkillEntry.fromJson reads each manifest entry's size
{
	import vibe.data.json : parseJsonString;

	auto e = SkillEntry.fromJson(parseJsonString(`{
		"uri": "skill://x/SKILL.md",
		"frontmatter": {"name": "x", "description": "d"},
		"resources": [
			{"uri": "skill://x/SKILL.md", "digest": "sha256:abc", "size": 2314},
			{"uri": "skill://x/a.md", "digest": "sha256:def", "size": 962}
		]
	}`));
	assert(e.resources[0].size == 2314);
	assert(e.resources[1].size == 962);
}

unittest  // verifyResourceDigest treats a byte-length mismatch as a verification failure
{
	const bytes = cast(const(ubyte)[]) "# Forms\n";
	SkillEntry e;
	e.uri = "skill://pdf/SKILL.md";
	// The digest is right but the advertised size is not: still a failure, per the
	// spec's rule that a read whose length differs from `size` fails verification.
	e.resources = [
		SkillResourceRef("skill://pdf/references/FORMS.md", skillDigest(bytes), 999)
	];
	const reason = verifyResourceDigest(e, "skill://pdf/references/FORMS.md", bytes);
	assert(reason !is null);
	import std.algorithm : canFind;

	assert(reason.canFind("size"));
}

unittest  // verifyResourceDigest accepts bytes whose length and digest both match
{
	const bytes = cast(const(ubyte)[]) "# Forms\n";
	SkillEntry e;
	e.uri = "skill://pdf/SKILL.md";
	e.resources = [
		SkillResourceRef("skill://pdf/references/FORMS.md", skillDigest(bytes), bytes.length)
	];
	assert(verifyResourceDigest(e, "skill://pdf/references/FORMS.md", bytes) is null);
}

unittest  // checkSkillLimits passes an entry within both per-skill limits
{
	SkillEntry e;
	e.uri = "skill://x/SKILL.md";
	e.resources = [SkillResourceRef("skill://x/SKILL.md", "sha256:abc", 5120)];
	assert(checkSkillLimits(e) is null);
}

unittest  // checkSkillLimits rejects more than 512 resources
{
	import std.conv : to;

	SkillEntry e;
	e.uri = "skill://x/SKILL.md";
	foreach (i; 0 .. maxSkillResources + 1)
		e.resources ~= SkillResourceRef("skill://x/f" ~ i.to!string, "sha256:abc", 1);
	const reason = checkSkillLimits(e);
	assert(reason !is null);
	import std.algorithm : canFind;

	assert(reason.canFind("512"));
}

unittest  // checkSkillLimits rejects a total size over 16 MiB, summing `size` alone
{
	SkillEntry e;
	e.uri = "skill://x/SKILL.md";
	e.resources = [
		SkillResourceRef("skill://x/SKILL.md", "sha256:abc", 100),
		SkillResourceRef("skill://x/big.bin", "sha256:def", maxSkillTotalBytes)
	];
	const reason = checkSkillLimits(e);
	assert(reason !is null);
	import std.algorithm : canFind;

	assert(reason.canFind("16"));
}

unittest  // SkillEntry.fromJson marks a "dynamic" resources value as valid but unverifiable
{
	import vibe.data.json : parseJsonString;

	auto e = SkillEntry.fromJson(parseJsonString(`{
		"uri": "skill://reports/daily/SKILL.md",
		"frontmatter": {"name": "daily", "description": "d"},
		"resources": "dynamic"
	}`));
	assert(e.isDynamic);
	assert(e.resources.length == 0);
	assert(e.isValid);
}

unittest  // SkillEntry with an array manifest is valid and not dynamic
{
	import vibe.data.json : parseJsonString;

	auto e = SkillEntry.fromJson(parseJsonString(`{
		"uri": "skill://x/SKILL.md",
		"frontmatter": {"name": "x", "description": "d"},
		"resources": [{"uri": "skill://x/SKILL.md", "digest": "sha256:abc", "size": 1}]
	}`));
	assert(!e.isDynamic);
	assert(e.isValid);
}

unittest  // an entry with no resources, or a non-array non-"dynamic" value, is invalid
{
	import vibe.data.json : parseJsonString;

	auto missing = SkillEntry.fromJson(parseJsonString(`{
		"uri": "skill://x/SKILL.md", "frontmatter": {"name": "x", "description": "d"}
	}`));
	assert(!missing.isValid && !missing.isDynamic);

	auto wrongType = SkillEntry.fromJson(parseJsonString(`{
		"uri": "skill://x/SKILL.md", "frontmatter": {"name": "x", "description": "d"},
		"resources": 42
	}`));
	assert(!wrongType.isValid && !wrongType.isDynamic);

	auto otherString = SkillEntry.fromJson(parseJsonString(`{
		"uri": "skill://x/SKILL.md", "frontmatter": {"name": "x", "description": "d"},
		"resources": "static"
	}`));
	assert(!otherString.isValid && !otherString.isDynamic);
}

unittest  // verifyResourceDigest reports a dynamic skill as offering no integrity
{
	SkillEntry e;
	e.uri = "skill://reports/daily/SKILL.md";
	e.isDynamic = true;
	const reason = verifyResourceDigest(e, e.uri, cast(const(ubyte)[]) "x");
	assert(reason !is null);
	import std.algorithm : canFind;

	assert(reason.canFind("dynamic"));
}

unittest  // checkSkillLimits has nothing to count for a dynamic skill
{
	SkillEntry e;
	e.uri = "skill://reports/daily/SKILL.md";
	e.isDynamic = true;
	assert(checkSkillLimits(e) is null);
}

unittest  // verifyResourceDigest accepts bytes matching the listed digest
{
	const bytes = cast(const(ubyte)[]) "# Forms\n";
	SkillEntry e;
	e.uri = "skill://pdf/SKILL.md";
	e.resources = [
		SkillResourceRef("skill://pdf/SKILL.md", "sha256:unused", 0),
		SkillResourceRef("skill://pdf/references/FORMS.md", skillDigest(bytes), bytes.length)
	];
	assert(verifyResourceDigest(e, "skill://pdf/references/FORMS.md", bytes) is null);
}

unittest  // verifyResourceDigest reports a digest mismatch
{
	SkillEntry e;
	e.uri = "skill://pdf/SKILL.md";
	// Same length as the tampered bytes, so only the digest can catch the change.
	e.resources = [
		SkillResourceRef("skill://pdf/references/FORMS.md",
				skillDigest(cast(const(ubyte)[]) "original"), "original".length)
	];
	const reason = verifyResourceDigest(e, "skill://pdf/references/FORMS.md",
			cast(const(ubyte)[]) "tampered");
	assert(reason !is null);
	import std.algorithm : canFind;

	assert(reason.canFind("digest mismatch"));
}

unittest  // verifyResourceDigest treats an unlisted uri as a verification failure
{
	SkillEntry e;
	e.uri = "skill://pdf/SKILL.md";
	e.resources = [SkillResourceRef("skill://pdf/SKILL.md", "sha256:abc")];
	const reason = verifyResourceDigest(e, "skill://pdf/references/EXTRA.md",
			cast(const(ubyte)[]) "x");
	assert(reason !is null);
	import std.algorithm : canFind;

	assert(reason.canFind("not listed"));
}

unittest  // verifyResourceDigest fails everything for an entry without a manifest
{
	SkillEntry e;
	e.uri = "skill://dynamic/SKILL.md";
	assert(verifyResourceDigest(e, "skill://dynamic/SKILL.md", cast(const(ubyte)[]) "x") !is null);
}

version (unittest)
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.client.transport : ClientTransport, SubscriptionStream, ClientProtocol;

	// A client transport that hands each request straight to an in-process
	// McpServer, so the typed client helpers can be exercised end-to-end
	// (client wrapper -> wire Json -> server handler -> wire Json -> parse)
	// without a socket.
	private final class ServerBackedTransport : ClientTransport
	{
		private McpServer server_;

		this(McpServer server) @safe
		{
			server_ = server;
		}

		Json deliver(Json requestMessage, long) @safe
		{
			import mcp.protocol.errors : McpException, ErrorCode;

			auto resp = server_.handle(Message(requestMessage)).get;
			if ("error" in resp)
				throw new McpException(cast(ErrorCode) resp["error"]["code"].get!int,
						resp["error"]["message"].get!string, "data" in resp["error"]
						? resp["error"]["data"] : Json.undefined);
			return resp["result"];
		}

		void sendOneway(Json message) @safe
		{
			server_.handle(Message(message));
		}

		bool repliesSynchronously() @safe
		{
			return true;
		}

		void startServerStream() @safe
		{
		}

		SubscriptionStream openListen(Json) @safe
		{
			return null;
		}

		void setInboundHandler(void delegate(Message) @safe) @safe
		{
		}

		void setProtocol(ClientProtocol) @safe
		{
		}

		void startLegacyFallback() @safe
		{
		}

		void setBearerToken(string) @safe
		{
		}

		void setDraftProtocol(bool) @safe
		{
		}

		bool cancelsByStreamClose() @safe
		{
			return false;
		}

		void close() @safe
		{
		}
	}

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

unittest  // listSkills returns typed entries from a live in-process server
{
	auto s = pdfSkillServer();
	auto client = new McpClient(new ServerBackedTransport(s));

	auto skills = listSkills(client);
	assert(skills.length == 1);
	assert(skills[0].uri == "skill://office/pdf-forms/SKILL.md");
	assert(skills[0].name == "pdf-forms");
	assert(skills[0].description == "Process PDFs");
	assert(skills[0].resources.length == 2);
	assert(skills[0].resources[0].uri == skills[0].uri);
}

unittest  // listSkills drains a paginated listing to completion
{
	auto s = new McpServer("t", "1");
	s.setPageSize(1);
	registerSkill(s, "alpha", "First", "a");
	registerSkill(s, "beta", "Second", "b");
	auto client = new McpClient(new ServerBackedTransport(s));

	auto skills = listSkills(client);
	assert(skills.length == 2);
	assert(skills[0].name == "alpha");
	assert(skills[1].name == "beta");
}

unittest  // getSkill returns the same typed entry the listing carries
{
	auto s = pdfSkillServer();
	auto client = new McpClient(new ServerBackedTransport(s));

	auto entry = getSkill(client, "skill://office/pdf-forms/SKILL.md");
	assert(entry.uri == "skill://office/pdf-forms/SKILL.md");
	assert(entry.name == "pdf-forms");
	assert(entry.resources.length == 2);

	// The fetched SKILL.md verifies against the entry it was retrieved under.
	const md = readSkillUri(client, entry.uri);
	assert(verifyResourceDigest(entry, entry.uri, cast(const(ubyte)[]) md) is null);
}

unittest  // listSkills surfaces a dynamic entry as isDynamic with an empty manifest
{
	auto s = new McpServer("t", "1");
	registerSkill(s, "static-one", "Static", "# S\n");
	DynamicSkill dyn = {
		path: "dynamic-one", description: "Dynamic", instructions: () @safe => "# D\n"
	};
	registerDynamicSkill(s, dyn);
	auto client = new McpClient(new ServerBackedTransport(s));

	auto skills = listSkills(client);
	assert(skills.length == 2);
	assert(!skills[0].isDynamic && skills[0].resources.length == 1);
	assert(skills[1].isDynamic && skills[1].resources.length == 0 && skills[1].isValid);
}

unittest  // getSkill surfaces the server's -32602 for a non-skill uri
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto s = pdfSkillServer();
	auto client = new McpClient(new ServerBackedTransport(s));
	assertThrown!McpException(getSkill(client, "skill://nope/SKILL.md"));
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

unittest  // resources/directory/read is served on a 2025-11-25 (stable) session
{
	auto s = pdfSkillServer(); // enables the method

	// The default negotiated version is the latest stable (2025-11-25), the floor
	// at which the Skills extension — and so its directory-read method — applies.
	Json p = Json.emptyObject;
	p["uri"] = "skill://office/pdf-forms";
	auto resp = s.handle(Message(makeRequest(Json(1), "resources/directory/read", p))).get;
	assert("result" in resp);
	assert(resp["result"]["resources"].length == 2);
}

unittest  // resources/directory/read does not exist below 2025-11-25
{
	import mcp.protocol.errors : ErrorCode;
	import mcp.protocol.versions : ProtocolVersion;
	import mcp.server.connection : ConnectionState;
	import vibe.data.json : parseJsonString;

	auto s = pdfSkillServer(); // enables the method

	// A session that negotiated a version below the Skills floor never sees it.
	auto conn = new ConnectionState;
	conn.negotiated = ProtocolVersion.v2025_06_18;
	auto outText = s.handleRaw(`{"jsonrpc":"2.0","id":1,"method":"resources/directory/read",`
			~ `"params":{"uri":"skill://office/pdf-forms"}}`, conn);
	auto resp = parseJsonString(outText);
	assert(resp["error"]["code"].get!int == cast(int) ErrorCode.methodNotFound);
}
