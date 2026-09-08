/**
 * Register an Agent Skill straight from a local directory (SEP-2640).
 *
 * `registerSkillDir(server, dir)` reads a skill directory — a `SKILL.md` plus
 * any supporting files and subdirectories — and exposes it over MCP: the
 * `SKILL.md` is served verbatim with its authored frontmatter parsed into the
 * skill's entry, and every file becomes a `skill://<path>/<file>` resource (so
 * subdirectories are walkable via `resources/directory/read`).
 *
 * This module owns the filesystem and YAML (`dyaml`) dependencies;
 * `mcp.api.skills` itself stays free of them.
 */
module mcp.api.skill_dir;

import vibe.data.json : Json;

import mcp.server.server : McpServer;
import mcp.api.skills : SkillFile, SkillEntry, registerSkillResources,
	addSkillEntry, skillName, skillFileUri, isValidSkillPath,
	isValidSkillName, skillDigest,
	verifyResourceDigest, resourceRef, maxSkillResources, maxSkillTotalBytes;

@safe:

/// Options controlling how `registerSkillDir` exposes a skill directory. Bundles
/// the per-call configuration so the common case stays a two-argument call.
struct SkillDirOptions
{
	/// The skill path to serve under. Empty derives it from the `SKILL.md`
	/// frontmatter `name`; otherwise the final segment MUST equal that name.
	string path;
	/// Publish each nested skill (a `SKILL.md` in a descendant directory) as its
	/// own flat entry alongside the enclosing skill's, per SEP-2640's
	/// flat-publication rule. Off, a nested `SKILL.md` is served as an ordinary
	/// supporting file only — readable, but nothing marks it as a skill.
	bool publishNested = true;
	/// Optional filter: return `false` to exclude a file by its skill-relative
	/// path (e.g. drop `.git/…` or `*.pyc`). `null` includes everything. Note a
	/// filtered-out nested `SKILL.md` is neither served nor published as a
	/// nested skill.
	bool delegate(string relPath) @safe include;
	/// Reject the directory if the skill would carry more than this many
	/// resources, `SKILL.md` included. Defaults to the extension's fixed per-skill
	/// limit, which registration enforces regardless; lower it to reject a large
	/// tree before its files are read into memory.
	size_t maxFiles = maxSkillResources;
	/// Reject the directory if its files, `SKILL.md` included, total more than
	/// this many bytes. Defaults to the extension's fixed per-skill limit, which
	/// registration enforces regardless; lower it to stop reading sooner.
	size_t maxTotalBytes = maxSkillTotalBytes;
}

/// Register the skill directory `dir` on `server`. Reads `dir/SKILL.md` (served
/// verbatim, its frontmatter parsed for the skill's entry) and walks the tree to
/// expose each file as a sibling resource. A `SKILL.md` in a descendant
/// directory is a nested skill: its files are ordinary supporting content of the
/// enclosing skill (listed in the enclosing `resources` manifest like any file),
/// and with `publishNested` (the default) the nested skill is additionally
/// published as its own flat entry whose `resources` cover exactly its subtree.
///
/// Throws if `dir` is not a directory, has no `SKILL.md`, the frontmatter lacks
/// a string `name`, the resolved skill path is invalid or its final segment does
/// not match the frontmatter `name`, a symlink is encountered, the file count /
/// total size exceeds the configured caps, or (`publishNested`) a nested
/// `SKILL.md` fails the same frontmatter/naming validation as a top-level one.
/// Validation runs before registration, so a throw leaves the server unchanged.
void registerSkillDir(McpServer server, string dir, SkillDirOptions options = SkillDirOptions.init) @safe
{
	import std.base64 : Base64;

	if (!pathIsDir(dir))
		throw new Exception("registerSkillDir: not a directory: " ~ dir);
	const skillMdPath = joinPath(dir, "SKILL.md");
	if (!pathExists(skillMdPath))
		throw new Exception("registerSkillDir: missing SKILL.md in " ~ dir);

	const skillMd = readTextFile(skillMdPath);
	Json frontmatter = parseSkillFrontmatter(skillMd);
	if (!(frontmatter.type == Json.Type.object && "name" in frontmatter
			&& frontmatter["name"].type == Json.Type.string))
		throw new Exception("registerSkillDir: SKILL.md frontmatter must define a string 'name'");
	// The Agent Skills spec requires both name and description.
	if (!("description" in frontmatter && frontmatter["description"].type == Json.Type.string))
		throw new Exception(
				"registerSkillDir: SKILL.md frontmatter must define a string 'description'");
	const fmName = frontmatter["name"].get!string;

	const path = options.path.length ? options.path : fmName;
	if (!isValidSkillPath(path))
		throw new Exception("registerSkillDir: invalid skill path '" ~ path ~ "'");
	if (skillName(path) != fmName)
		throw new Exception("registerSkillDir: the final skill-path segment '" ~ skillName(
				path) ~ "' must equal the SKILL.md frontmatter name '" ~ fmName ~ "'");

	RawFile[] raws = collectFiles(dir, skillMd.length, options.include,
			options.maxFiles, options.maxTotalBytes);

	SkillFile[] files;
	foreach (r; raws)
	{
		SkillFile f;
		f.path = r.path;
		f.mimeType = r.mimeType;
		if (r.isText)
			f.content = cast(string) r.bytes;
		else
		{
			f.content = Base64.encode(r.bytes).idup;
			f.isBlob = true;
		}
		files ~= f;
	}

	// Build (and fully validate) the nested skills' entries before anything is
	// registered, so a malformed nested skill rejects the whole directory
	// without side effects; the appends after registration cannot throw.
	Json[] nestedEntries;
	if (options.publishNested)
		nestedEntries = buildNestedEntries(server, path, raws);

	registerSkillResources(server, path, skillMd, frontmatter, files);
	foreach (entry; nestedEntries)
		addSkillEntry(server, entry);
}

/// One flat entry per nested skill found in `raws` (any `SKILL.md` below the
/// root): `uri` is the nested `SKILL.md`'s file resource URI under the enclosing
/// skill's `path`, `frontmatter` is the nested file's own authored frontmatter,
/// and `resources` covers exactly the nested skill's subtree — itself first,
/// then every deeper file, including any further-nested skills' files. Throws on
/// the same validation failures as a top-level skill (frontmatter shape, naming,
/// name/directory match, already-registered URI); the files themselves are
/// registered once, by the enclosing skill's registration.
private Json[] buildNestedEntries(McpServer server, string path, RawFile[] raws) @safe
{
	import std.algorithm : endsWith, startsWith;

	Json[] entries;
	foreach (r; raws)
	{
		if (!r.path.endsWith("/SKILL.md"))
			continue;
		const dirRel = r.path[0 .. $ - "/SKILL.md".length];
		const basename = skillName(dirRel);
		if (!r.isText)
			throw new Exception(
					"registerSkillDir: nested SKILL.md is not valid UTF-8 text: " ~ r.path);
		Json fm = parseSkillFrontmatter(cast(string) r.bytes);
		if (!(fm.type == Json.Type.object && "name" in fm && fm["name"].type == Json.Type.string))
			throw new Exception("registerSkillDir: nested SKILL.md frontmatter must "
					~ "define a string 'name': " ~ r.path);
		if (!("description" in fm && fm["description"].type == Json.Type.string))
			throw new Exception("registerSkillDir: nested SKILL.md frontmatter must "
					~ "define a string 'description': " ~ r.path);
		if (!isValidSkillName(basename))
			throw new Exception("registerSkillDir: nested skill directory name '"
					~ basename ~ "' is not a valid skill name (" ~ r.path ~ ")");
		if (fm["name"].get!string != basename)
			throw new Exception("registerSkillDir: nested skill directory '" ~ dirRel
					~ "' must equal its SKILL.md frontmatter name '" ~ fm["name"].get!string ~ "'");

		const uri = skillFileUri(path, r.path);
		if (uri in server.ensureSkillIndex().byUri)
			throw new Exception("a skill at '" ~ uri ~ "' is already registered");

		Json manifest = Json.emptyArray;
		manifest ~= resourceRef(uri, skillDigest(r.bytes), r.bytes.length);
		foreach (rr; raws)
		{
			if (rr.path == r.path || !rr.path.startsWith(dirRel ~ "/"))
				continue;
			manifest ~= resourceRef(skillFileUri(path, rr.path),
					skillDigest(rr.bytes), rr.bytes.length);
		}

		Json entry = Json.emptyObject;
		entry["uri"] = uri;
		entry["frontmatter"] = fm;
		entry["resources"] = manifest;
		entries ~= entry;
	}
	return entries;
}

// --- Frontmatter -----------------------------------------------------------

/// Parse the leading `---`-delimited YAML frontmatter of a `SKILL.md` into a
/// JSON object (the verbatim `frontmatter` SEP-2640 puts in a skill entry). The
/// fence is matched a line at a time: the file must open with a line that is
/// exactly `---`, and the frontmatter ends at the next line that is exactly
/// `---` or `...` — so a `---` appearing inside a value does not close it early,
/// and CRLF line endings work. Hosts use this to compare a fetched `SKILL.md`'s
/// frontmatter against its entry (see `verifySkillMarkdown`).
Json parseSkillFrontmatter(string md) @safe
{
	import std.array : split, join, replace;
	import std.string : stripRight;

	// Normalize CRLF, then split on \n only — NOT std.string.splitLines, which
	// also breaks on U+2028 / U+2029 / vertical tab and would corrupt a value
	// containing one. Normalizing first means the reconstructed YAML carries no
	// stray \r either.
	auto lines = md.replace("\r\n", "\n").split('\n');
	if (lines.length == 0 || lines[0] != "---")
		throw new Exception("SKILL.md must begin with a '---' frontmatter line");
	size_t end = size_t.max;
	foreach (i; 1 .. lines.length)
	{
		const t = lines[i].stripRight;
		if (t == "---" || t == "...")
		{
			end = i;
			break;
		}
	}
	if (end == size_t.max)
		throw new Exception("SKILL.md frontmatter is not closed by a '---' line");
	return yamlToJson(lines[1 .. end].join("\n"));
}

/// Convert a YAML document (dyaml) to a vibe `Json` value, preserving scalar
/// types so the index frontmatter mirrors the authored YAML.
private Json yamlToJson(string yaml) @safe
{
	import dyaml : Loader;

	try
	{
		auto root = Loader.fromString(yaml).load();
		return nodeToJson(root);
	}
	catch (Exception e)
		throw new Exception("registerSkillDir: invalid SKILL.md frontmatter YAML: " ~ e.msg);
}

// Templated on dyaml's Node so the converter need not name the type; recursion
// re-deduces it. Scalars keep their YAML-inferred type (bool/int/float/null/string).
private Json nodeToJson(N)(N node) @safe
{
	import dyaml : NodeID, NodeType;

	final switch (node.nodeID)
	{
	case NodeID.mapping:
		Json o = Json.emptyObject;
		foreach (string key, N value; node)
			o[key] = nodeToJson(value);
		return o;
	case NodeID.sequence:
		Json a = Json.emptyArray;
		foreach (N value; node)
			a ~= nodeToJson(value);
		return a;
	case NodeID.scalar:
		switch (node.type)
		{
		case NodeType.boolean:
			return Json(node.as!bool);
		case NodeType.integer:
			return Json(node.as!long);
		case NodeType.decimal:
			return Json(node.as!double);
		case NodeType.null_:
			return Json(null);
		case NodeType.timestamp:
			// Render a YAML-implicit timestamp as an ISO-8601 string rather than
			// dyaml's SysTime.toString, which is not round-trippable.
			import std.datetime.systime : SysTime;

			return Json(node.as!SysTime.toISOExtString);
		case NodeType.binary:
			import std.base64 : Base64;

			return Json(Base64.encode(node.as!(ubyte[])).idup);
		case NodeType.merge:
			// A bare merge key has no value of its own.
			return Json(null);
		default:
			return Json(node.as!string);
		}
	case NodeID.invalid:
		return Json(null);
	}
}

/// Verify a fetched `SKILL.md` against its skill entry, covering both host-side
/// checks SEP-2640 requires: the bytes must match the digest the entry's
/// `resources` manifest lists for the skill's own `uri`, and the parsed YAML
/// frontmatter must be identical in content to the entry's `frontmatter` — so
/// what a user approved from the listing is what the model actually receives.
/// Returns `null` on success, or a reason string on failure; a failing skill
/// must not be loaded.
string verifySkillMarkdown(const SkillEntry entry, string skillMd) @safe
{
	const digestReason = verifyResourceDigest(entry, entry.uri, cast(const(ubyte)[]) skillMd);
	if (digestReason !is null)
		return digestReason;

	Json parsed;
	try
		parsed = parseSkillFrontmatter(skillMd);
	catch (Exception e)
		return "the fetched SKILL.md has no parseable frontmatter: " ~ e.msg;
	// vibe Json equality is deep, so one comparison covers every field the
	// author wrote, in both directions (a missing field and an added field are
	// both discrepancies).
	if (parsed != entry.frontmatter)
		return "the fetched SKILL.md frontmatter does not match the entry's frontmatter";
	return null;
}

// --- Filesystem walk -------------------------------------------------------

/// A file read from a skill directory, ready to become a resource and a
/// `resources`-manifest entry.
private struct RawFile
{
	string path; /// skill-relative posix path, e.g. "references/FORMS.md"
	immutable(ubyte)[] bytes; /// raw file contents
	string mimeType; /// inferred MIME type
	bool isText; /// served as text (vs base64 blob)
}

/// Every file under `dir` except the root `SKILL.md`, whose byte length is
/// `skillMdBytes`: the caps count the `SKILL.md` as one resource and its bytes
/// toward the total, so they line up with the extension's per-skill limits.
private RawFile[] collectFiles(string dir, size_t skillMdBytes,
		scope bool delegate(string) @safe include, size_t maxFiles, size_t maxTotalBytes) @safe
{
	import std.algorithm : sort;

	RawFile[] files;
	size_t total = skillMdBytes;
	if (total > maxTotalBytes)
		throw new Exception("registerSkillDir: skill directory exceeds maxTotalBytes");
	walkInto(dir, "", files, total, include, maxFiles, maxTotalBytes);
	// Sort by path so the served order and the manifest order are deterministic.
	sort!((a, b) => a.path < b.path)(files);
	return files;
}

private void walkInto(string base, string rel, ref RawFile[] files, ref size_t total,
		scope bool delegate(string) @safe include, size_t maxFiles, size_t maxTotalBytes) @safe
{
	const here = rel.length ? joinPath(base, rel) : base;
	foreach (entry; listDir(here))
	{
		const childRel = rel.length ? rel ~ "/" ~ entry.name : entry.name;
		if (entry.isSymlink)
			throw new Exception(
					"registerSkillDir: symlinks are not allowed in a skill "
					~ "directory: " ~ childRel);
		if (entry.isDir)
		{
			walkInto(base, childRel, files, total, include, maxFiles, maxTotalBytes);
			continue;
		}
		if (!entry.isFile)
			continue;
		// The root SKILL.md is served as the skill markdown, not as a generic
		// file. A SKILL.md anywhere deeper is a nested skill: from this skill's
		// perspective it is ordinary supporting content, collected like any
		// other file (and possibly published as its own entry — see
		// `buildNestedEntries`).
		if (entry.name == "SKILL.md" && rel.length == 0)
			continue;
		if (include !is null && !include(childRel))
			continue;

		// `files` excludes the root SKILL.md, which counts as a resource too.
		if (files.length + 2 > maxFiles)
			throw new Exception("registerSkillDir: skill directory exceeds maxFiles");
		const fullPath = joinPath(base, childRel);
		// Check the size against the cap BEFORE reading, so a single oversized
		// file cannot be slurped into memory just to be rejected afterward.
		if (total + fileSize(fullPath) > maxTotalBytes)
			throw new Exception("registerSkillDir: skill directory exceeds maxTotalBytes");
		const bytes = readBytes(fullPath);
		total += bytes.length;

		RawFile r;
		r.path = childRel;
		r.bytes = bytes;
		inferMime(childRel, bytes, r.mimeType, r.isText);
		files ~= r;
	}
}

/// Decide a file's MIME type and whether it is served as text. Text is gated on
/// both a known textual extension and the bytes actually being valid UTF-8.
private void inferMime(string relPath, scope const(ubyte)[] bytes, out string mime, out bool isText) @safe
{
	import std.path : extension;
	import std.uni : toLower;

	const ext = relPath.extension.toLower;
	string textMime;
	switch (ext)
	{
	case ".md", ".markdown":
		textMime = "text/markdown";
		break;
	case ".txt", ".text":
		textMime = "text/plain";
		break;
	case ".json":
		textMime = "application/json";
		break;
	case ".yaml", ".yml":
		textMime = "application/yaml";
		break;
	case ".html", ".htm":
		textMime = "text/html";
		break;
	case ".css":
		textMime = "text/css";
		break;
	case ".csv":
		textMime = "text/csv";
		break;
	case ".xml":
		textMime = "application/xml";
		break;
	case ".svg":
		textMime = "image/svg+xml";
		break;
	case ".toml":
		textMime = "application/toml";
		break;
	case ".py", ".js", ".ts", ".sh", ".rb", ".go", ".rs", ".c", ".h", ".cpp",
			".hpp", ".d", ".java", ".sql":
			textMime = "text/plain";
		break;
	case ".png":
		mime = "image/png";
		isText = false;
		return;
	case ".jpg", ".jpeg":
		mime = "image/jpeg";
		isText = false;
		return;
	case ".gif":
		mime = "image/gif";
		isText = false;
		return;
	case ".pdf":
		mime = "application/pdf";
		isText = false;
		return;
	default:
		// Unknown or extension-less (LICENSE, Makefile, .gitignore): serve as
		// text when the bytes are valid UTF-8, otherwise as an opaque blob.
		if (isValidUtf8(bytes))
		{
			mime = "text/plain";
			isText = true;
		}
		else
		{
			mime = "application/octet-stream";
			isText = false;
		}
		return;
	}

	// A textual extension still serves as a blob if the bytes are not valid UTF-8.
	if (isValidUtf8(bytes))
	{
		mime = textMime;
		isText = true;
	}
	else
	{
		mime = "application/octet-stream";
		isText = false;
	}
}

private bool isValidUtf8(scope const(ubyte)[] bytes) @safe
{
	import std.utf : validate, UTFException;

	try
		validate(cast(const(char)[]) bytes);
	catch (UTFException)
		return false;
	return true;
}

// --- @trusted filesystem primitives ----------------------------------------

private struct DirEntryInfo
{
	string name;
	bool isDir;
	bool isFile;
	bool isSymlink;
}

private string joinPath(string a, string b) @safe pure
{
	return a.length && a[$ - 1] == '/' ? a ~ b : a ~ "/" ~ b;
}

private bool pathExists(string p) @trusted
{
	import std.file : exists;

	return exists(p);
}

private bool pathIsDir(string p) @trusted
{
	import std.file : exists, isDir;

	return exists(p) && isDir(p);
}

private string readTextFile(string p) @trusted
{
	import std.file : readText;

	return readText(p);
}

private immutable(ubyte)[] readBytes(string p) @trusted
{
	import std.file : read;

	return cast(immutable(ubyte)[]) read(p);
}

private ulong fileSize(string p) @trusted
{
	import std.file : getSize;

	return getSize(p);
}

private DirEntryInfo[] listDir(string dir) @trusted
{
	import std.file : dirEntries, SpanMode, DirEntry;
	import std.path : baseName;

	DirEntryInfo[] out_;
	foreach (DirEntry e; dirEntries(dir, SpanMode.shallow))
	{
		DirEntryInfo info;
		info.name = baseName(e.name);
		info.isSymlink = e.isSymlink;
		info.isDir = e.isDir;
		info.isFile = e.isFile;
		out_ ~= info;
	}
	return out_;
}

// --- Tests ------------------------------------------------------------------

version (unittest)
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	// A throwaway skill directory: SKILL.md with authored frontmatter (mixed
	// scalar types) plus one supporting file in a subdirectory.
	private void writeSkillFixture(string root) @trusted
	{
		import std.file : mkdirRecurse, write, rmdirRecurse, exists;

		if (exists(root))
			rmdirRecurse(root);
		mkdirRecurse(root ~ "/references");
		write(root ~ "/SKILL.md",
				"---\nname: pdf-forms\ndescription: Process PDFs\nlicense: Apache-2.0\n"
				~ "metadata:\n  version: \"2.1.0\"\n  experimental: true\n---\n\n# PDF Forms\n");
		write(root ~ "/references/FORMS.md", "# Form Fields\n- applicant_name\n");
	}

	private void writeFile(string path, string content) @trusted
	{
		import std.file : write;

		write(path, content);
	}

	private void writeNestedDir(string path) @trusted
	{
		import std.file : mkdirRecurse;

		mkdirRecurse(path);
	}

	// A skill directory with a single, caller-supplied SKILL.md and no other files.
	private void writeRawSkill(string root, string skillMd) @trusted
	{
		import std.file : mkdirRecurse, write, rmdirRecurse, exists;

		if (exists(root))
			rmdirRecurse(root);
		mkdirRecurse(root);
		write(root ~ "/SKILL.md", skillMd);
	}

	private void removeTree(string root) @trusted
	{
		import std.file : rmdirRecurse, exists;

		if (exists(root))
			rmdirRecurse(root);
	}

	private string tmpRoot(string suffix) @trusted
	{
		import std.path : buildPath;
		import std.file : tempDir;

		return buildPath(tempDir, "mcp_d_skilldir_" ~ suffix);
	}

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

	private Json readResource(McpServer s, long id, string uri) @safe
	{
		Json p = Json.emptyObject;
		p["uri"] = uri;
		return s.handle(Message(makeRequest(Json(id), "resources/read", p)))
			.get["result"]["contents"][0];
	}

	// The `index`-th entry of the server's skills/list result.
	private Json listedSkill(McpServer s, long id, size_t index) @safe
	{
		return s.handle(Message(makeRequest(Json(id), "skills/list",
				Json.emptyObject))).get["result"]["skills"][index];
	}
}

unittest  // registerSkillDir serves SKILL.md verbatim with authored, type-preserved frontmatter
{
	import std.algorithm : canFind;

	const root = tmpRoot("verbatim");
	writeSkillFixture(root);
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	registerSkillDir(s, root);

	// The authored SKILL.md is served byte-for-byte (frontmatter is NOT synthesized).
	const md = readResource(s, 1, "skill://pdf-forms/SKILL.md")["text"].get!string;
	assert(md.canFind("license: Apache-2.0"));
	assert(md.canFind("# PDF Forms"));

	// The entry frontmatter is the parsed YAML — every field, with types kept —
	// and the resources manifest covers SKILL.md plus the supporting file.
	auto e = listedSkill(s, 2, 0);
	assert(e["frontmatter"]["name"].get!string == "pdf-forms");
	assert(e["frontmatter"]["license"].get!string == "Apache-2.0");
	assert(e["frontmatter"]["metadata"]["version"].get!string == "2.1.0");
	assert(e["frontmatter"]["metadata"]["experimental"].get!bool == true);
	assert(e["uri"].get!string == "skill://pdf-forms/SKILL.md");
	assert(e["resources"].length == 2);
	assert(e["resources"][0]["uri"].get!string == "skill://pdf-forms/SKILL.md");
	assert(e["resources"][0]["digest"].get!string == skillDigestOf(md));
}

unittest  // a directory skill's manifest carries each file's byte length
{
	const root = tmpRoot("sizes");
	writeSkillFixture(root);
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	registerSkillDir(s, root);

	const md = readResource(s, 1, "skill://pdf-forms/SKILL.md")["text"].get!string;
	auto res = listedSkill(s, 2, 0)["resources"];
	assert(res[0]["uri"].get!string == "skill://pdf-forms/SKILL.md");
	assert(res[0]["size"].get!long == md.length);
	assert(res[1]["uri"].get!string == "skill://pdf-forms/references/FORMS.md");
	assert(res[1]["size"].get!long == "# Form Fields\n- applicant_name\n".length);
}

unittest  // SkillDirOptions caps default to the extension's fixed per-skill limits
{
	import mcp.api.skills : maxSkillResources, maxSkillTotalBytes;

	SkillDirOptions opts;
	assert(opts.maxFiles == maxSkillResources);
	assert(opts.maxTotalBytes == maxSkillTotalBytes);
}

unittest  // maxFiles counts SKILL.md itself as one of the skill's resources
{
	import std.exception : assertThrown, assertNotThrown;

	const root = tmpRoot("maxfiles");
	writeSkillFixture(root); // SKILL.md + references/FORMS.md = 2 resources
	scope (exit)
		removeTree(root);

	SkillDirOptions tight;
	tight.maxFiles = 1;
	assertThrown!Exception(registerSkillDir(new McpServer("t", "1"), root, tight));

	SkillDirOptions exact;
	exact.maxFiles = 2;
	assertNotThrown!Exception(registerSkillDir(new McpServer("t", "1"), root, exact));
}

unittest  // registerSkillDir exposes supporting files as sibling resources
{
	const root = tmpRoot("files");
	writeSkillFixture(root);
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	registerSkillDir(s, root);

	import std.algorithm : canFind;

	const ff = readResource(s, 1, "skill://pdf-forms/references/FORMS.md")["text"].get!string;
	assert(ff.canFind("applicant_name"));
}

unittest  // registerSkillDir auto-exposes subdirectories via resources/directory/read
{
	const root = tmpRoot("dirread");
	writeSkillFixture(root);
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	registerSkillDir(s, root);

	Json p = Json.emptyObject;
	p["uri"] = "skill://pdf-forms";
	auto res = s.handle(draftRequest(1, "resources/directory/read", p)).get["result"]["resources"];

	bool sawSkillMd, sawReferencesDir;
	foreach (i; 0 .. res.length)
	{
		const uri = res[i]["uri"].get!string;
		if (uri == "skill://pdf-forms/SKILL.md")
			sawSkillMd = true;
		if (uri == "skill://pdf-forms/references")
			sawReferencesDir = true;
	}
	assert(sawSkillMd && sawReferencesDir);
}

version (unittest)
{
	// A skill directory containing a nested skill two levels down, plus an
	// ordinary supporting file at each level.
	private void writeNestedFixture(string root) @trusted
	{
		import std.file : mkdirRecurse, write, rmdirRecurse, exists;

		if (exists(root))
			rmdirRecurse(root);
		mkdirRecurse(root ~ "/references/sub-skill");
		write(root ~ "/SKILL.md", "---\nname: outer\ndescription: Outer skill\n---\n\n# Outer\n");
		write(root ~ "/references/GUIDE.md", "# Guide\n");
		write(root ~ "/references/sub-skill/SKILL.md",
				"---\nname: sub-skill\ndescription: Nested skill\n---\n\n# Sub\n");
		write(root ~ "/references/sub-skill/notes.md", "# Notes\n");
	}
}

unittest  // nested files are supporting content: the enclosing manifest lists them all
{
	const root = tmpRoot("nest-encl");
	writeNestedFixture(root);
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	registerSkillDir(s, root);

	auto e = listedSkill(s, 1, 0);
	assert(e["uri"].get!string == "skill://outer/SKILL.md");
	// Its own SKILL.md + GUIDE.md + the nested skill's SKILL.md + notes.md:
	// the nested skill's files are ordinary files of the enclosing skill too.
	auto res = e["resources"];
	assert(res.length == 4);
	bool sawNestedMd;
	foreach (i; 0 .. res.length)
		if (res[i]["uri"].get!string == "skill://outer/references/sub-skill/SKILL.md")
			sawNestedMd = true;
	assert(sawNestedMd);
}

unittest  // a nested skill is additionally published as its own flat entry
{
	const root = tmpRoot("nest-flat");
	writeNestedFixture(root);
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	registerSkillDir(s, root);

	// Two flat entries: the enclosing skill first, then the nested one, whose
	// uri shares the enclosing path prefix and whose frontmatter is the nested
	// file's own authored frontmatter.
	auto result = s.handle(Message(makeRequest(Json(1), "skills/list",
			Json.emptyObject))).get["result"];
	assert(result["skills"].length == 2);
	auto nested = result["skills"][1];
	assert(nested["uri"].get!string == "skill://outer/references/sub-skill/SKILL.md");
	assert(nested["frontmatter"]["name"].get!string == "sub-skill");
	assert(nested["frontmatter"]["description"].get!string == "Nested skill");

	// The nested entry's manifest covers exactly its subtree — itself first.
	auto res = nested["resources"];
	assert(res.length == 2);
	assert(res[0]["uri"].get!string == nested["uri"].get!string);
	assert(res[1]["uri"].get!string == "skill://outer/references/sub-skill/notes.md");
	assert(res[1]["digest"].get!string == skillDigestOf("# Notes\n"));
	assert(res[1]["size"].get!long == "# Notes\n".length);
}

unittest  // skills/get answers for a nested skill's uri
{
	const root = tmpRoot("nest-get");
	writeNestedFixture(root);
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	registerSkillDir(s, root);

	Json p = Json.emptyObject;
	p["uri"] = "skill://outer/references/sub-skill/SKILL.md";
	auto got = s.handle(Message(makeRequest(Json(1), "skills/get", p))).get["result"]["skill"];
	assert(got["frontmatter"]["name"].get!string == "sub-skill");
}

unittest  // a nested directory whose name mismatches its frontmatter rejects the whole dir
{
	import std.exception : assertThrown;

	const root = tmpRoot("nest-bad");
	writeNestedFixture(root);
	scope (exit)
		removeTree(root);
	writeFile(root ~ "/references/sub-skill/SKILL.md",
			"---\nname: other-name\ndescription: d\n---\n\n# Sub\n");

	auto s = new McpServer("t", "1");
	assertThrown!Exception(registerSkillDir(s, root));

	// Validation precedes registration: the server is untouched, so the skills
	// methods were never even enabled.
	auto resp = s.handle(Message(makeRequest(Json(1), "skills/list", Json.emptyObject))).get;
	assert("error" in resp);
}

unittest  // publishNested=false serves the nested SKILL.md as a plain file only
{
	import std.algorithm : canFind;

	const root = tmpRoot("nest-off");
	writeNestedFixture(root);
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	SkillDirOptions opts;
	opts.publishNested = false;
	registerSkillDir(s, root, opts);

	auto result = s.handle(Message(makeRequest(Json(1), "skills/list",
			Json.emptyObject))).get["result"];
	assert(result["skills"].length == 1);
	// Still readable — it is ordinary supporting content of the enclosing skill.
	const md = readResource(s, 2, "skill://outer/references/sub-skill/SKILL.md")["text"]
		.get!string;
	assert(md.canFind("# Sub"));
}

unittest  // nested files are registered once and serve their authored bytes
{
	import std.algorithm : canFind;

	const root = tmpRoot("nest-once");
	writeNestedFixture(root);
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	registerSkillDir(s, root);

	const md = readResource(s, 1, "skill://outer/references/sub-skill/SKILL.md")["text"]
		.get!string;
	assert(md.canFind("name: sub-skill") && md.canFind("# Sub"));

	// Exactly one resource registration for the nested SKILL.md.
	auto listed = s.handle(Message(makeRequest(Json(2), "resources/list",
			Json.emptyObject))).get["result"]["resources"];
	size_t count;
	foreach (i; 0 .. listed.length)
		if (listed[i]["uri"].get!string == "skill://outer/references/sub-skill/SKILL.md")
			count++;
	assert(count == 1);
}

unittest  // a doubly-nested skill publishes three flat entries with subtree manifests
{
	const root = tmpRoot("nest-deep");
	writeNestedFixture(root);
	scope (exit)
		removeTree(root);
	// A further skill nested inside the nested one.
	writeNestedDir(root ~ "/references/sub-skill/deep-skill");
	writeFile(root ~ "/references/sub-skill/deep-skill/SKILL.md",
			"---\nname: deep-skill\ndescription: Doubly nested\n---\n\n# Deep\n");

	auto s = new McpServer("t", "1");
	registerSkillDir(s, root);

	auto result = s.handle(Message(makeRequest(Json(1), "skills/list",
			Json.emptyObject))).get["result"];
	assert(result["skills"].length == 3);

	// The middle skill's manifest includes the deep skill's file (nested content
	// is supporting content, at every level); the deep skill's covers itself only.
	Json subEntry, deepEntry;
	foreach (i; 0 .. result["skills"].length)
	{
		const n = result["skills"][i]["frontmatter"]["name"].get!string;
		if (n == "sub-skill")
			subEntry = result["skills"][i];
		if (n == "deep-skill")
			deepEntry = result["skills"][i];
	}
	assert(subEntry["resources"].length == 3); // its SKILL.md, notes.md, deep SKILL.md
	assert(deepEntry["resources"].length == 1);
	assert(deepEntry["resources"][0]["uri"].get!string
			== "skill://outer/references/sub-skill/deep-skill/SKILL.md");
}

unittest  // registerSkillDir honours an explicit prefixed path matching the frontmatter name
{
	const root = tmpRoot("prefix");
	writeSkillFixture(root);
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	SkillDirOptions opts;
	opts.path = "office/pdf-forms"; // final segment matches frontmatter name
	registerSkillDir(s, root, opts);

	assert(listedSkill(s, 1, 0)["uri"].get!string == "skill://office/pdf-forms/SKILL.md");
}

unittest  // registerSkillDir rejects a path whose final segment != frontmatter name
{
	import std.exception : assertThrown;

	const root = tmpRoot("mismatch");
	writeSkillFixture(root);
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	SkillDirOptions opts;
	opts.path = "office/wrong-name";
	assertThrown!Exception(registerSkillDir(s, root, opts));
}

unittest  // a '---' inside a frontmatter value does not close the frontmatter early
{
	const root = tmpRoot("fence");
	// `notes` is a block scalar that itself contains a `---` line; `trailing`
	// comes after it and must survive into the parsed frontmatter.
	writeRawSkill(root,
			"---\nname: fence-skill\ndescription: d\nnotes: |\n  sep:\n  ---\n  more\n"
			~ "trailing: kept\n---\n\n# Body\n");
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	registerSkillDir(s, root);

	auto fm = listedSkill(s, 1, 0)["frontmatter"];
	assert(fm["trailing"].get!string == "kept");
}

unittest  // a CRLF SKILL.md parses (fence and values carry trailing \r)
{
	const root = tmpRoot("crlf");
	writeRawSkill(root, "---\r\nname: crlf-skill\r\ndescription: a value\r\n---\r\n\r\n# Body\r\n");
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	registerSkillDir(s, root);

	auto fm = listedSkill(s, 1, 0)["frontmatter"];
	assert(fm["name"].get!string == "crlf-skill");
	assert(fm["description"].get!string == "a value");
}

unittest  // registerSkillDir requires a string description in the frontmatter
{
	import std.exception : assertThrown;

	const root = tmpRoot("nodesc");
	writeRawSkill(root, "---\nname: x\n---\n\n# Body\n");
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	assertThrown!Exception(registerSkillDir(s, root));
}

unittest  // an extension-less text file is served as text/plain, not an opaque blob
{
	import std.algorithm : canFind;

	const root = tmpRoot("license");
	writeSkillFixture(root);
	writeFile(root ~ "/LICENSE", "MIT License\n\nPermission is hereby granted...\n");
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	registerSkillDir(s, root);

	auto c = readResource(s, 1, "skill://pdf-forms/LICENSE");
	assert(c["mimeType"].get!string == "text/plain");
	assert(c["text"].get!string.canFind("MIT License"));
}

unittest  // a YAML timestamp in frontmatter is rendered as an ISO-8601 string
{
	import std.algorithm : canFind;

	const root = tmpRoot("timestamp");
	writeRawSkill(root, "---\nname: ts-skill\ndescription: d\ncreated: 2021-01-02\n---\n\n# Body\n");
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	registerSkillDir(s, root);

	auto fm = listedSkill(s, 1, 0)["frontmatter"];
	assert(fm["created"].type == Json.Type.string);
	assert(fm["created"].get!string.canFind("2021-01-02"));
}

unittest  // registerSkillDir rejects a directory whose files exceed maxTotalBytes
{
	import std.exception : assertThrown;

	const root = tmpRoot("toobig");
	writeSkillFixture(root);
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	SkillDirOptions opts;
	opts.maxTotalBytes = 4; // smaller than the fixture's FORMS.md
	assertThrown!Exception(registerSkillDir(s, root, opts));
}

version (unittest) private string skillDigestOf(string s) @safe
{
	return skillDigest(cast(const(ubyte)[]) s);
}

unittest  // parseSkillFrontmatter is public: hosts parse fetched SKILL.md frontmatter
{
	auto fm = parseSkillFrontmatter("---\nname: x\ndescription: d\n---\n\n# Body\n");
	assert(fm["name"].get!string == "x");
	assert(fm["description"].get!string == "d");
}

version (unittest)
{
	import mcp.api.skills : SkillResourceRef;

	// A well-formed SKILL.md and the entry a server would publish for it.
	private enum verifyMd = "---\nname: x\ndescription: d\n---\n\n# Body\n";

	private SkillEntry verifyEntry() @safe
	{
		SkillEntry e;
		e.uri = "skill://x/SKILL.md";
		e.frontmatter = parseSkillFrontmatter(verifyMd);
		e.resources = [
			SkillResourceRef("skill://x/SKILL.md", skillDigestOf(verifyMd), verifyMd.length)
		];
		return e;
	}
}

unittest  // verifySkillMarkdown passes for matching bytes and frontmatter
{
	assert(verifySkillMarkdown(verifyEntry(), verifyMd) is null);
}

unittest  // verifySkillMarkdown reports a same-length body mutation as a digest failure
{
	const mutated = "---\nname: x\ndescription: d\n---\n\n# Bodx\n";
	const reason = verifySkillMarkdown(verifyEntry(), mutated);
	assert(reason !is null);
	import std.algorithm : canFind;

	assert(reason.canFind("digest mismatch"));
}

unittest  // verifySkillMarkdown reports a length-changing mutation as a size failure
{
	const mutated = "---\nname: x\ndescription: d\n---\n\n# Tampered\n";
	const reason = verifySkillMarkdown(verifyEntry(), mutated);
	assert(reason !is null);
	import std.algorithm : canFind;

	assert(reason.canFind("size mismatch"));
}

unittest  // verifySkillMarkdown reports entry frontmatter that diverges from the file
{
	// The digest matches the fetched bytes, but the entry claims different
	// frontmatter than the file carries — the identity discrepancy the host-side
	// field comparison exists to catch.
	auto e = verifyEntry();
	e.frontmatter["description"] = "something else";
	const reason = verifySkillMarkdown(e, verifyMd);
	assert(reason !is null);
	import std.algorithm : canFind;

	assert(reason.canFind("frontmatter"));
}
