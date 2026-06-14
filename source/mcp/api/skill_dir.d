/**
 * Register an Agent Skill straight from a local directory (SEP-2640).
 *
 * `registerSkillDir(server, dir)` reads a skill directory — a `SKILL.md` plus
 * any supporting files and subdirectories — and exposes it over MCP: the
 * `SKILL.md` is served verbatim with its authored frontmatter parsed into the
 * `skill://index.json` entry, every file becomes a `skill://<path>/<file>`
 * resource (so subdirectories are walkable via `resources/directory/read`), and
 * each requested `ArchiveFormat` is packed into a downloadable whole-skill
 * archive listed alongside the per-file form.
 *
 * This module owns the filesystem, YAML (`dyaml`), and archive (`archive`)
 * dependencies; `mcp.api.skills` itself stays free of them.
 */
module mcp.api.skill_dir;

import vibe.data.json : Json;

import mcp.server.server : McpServer;
import mcp.api.attributes : ArchiveFormat;
import mcp.api.skills : SkillFile, SkillArchive, registerSkillResources,
	skillName, isValidSkillPath;

@safe:

/// Options controlling how `registerSkillDir` exposes a skill directory. Bundles
/// the per-call configuration so the common case stays a two-argument call.
struct SkillDirOptions
{
	/// The skill path to serve under. Empty derives it from the `SKILL.md`
	/// frontmatter `name`; otherwise the final segment MUST equal that name.
	string path;
	/// Expose each file in the directory as its own `skill://<path>/<file>`
	/// resource. Turn off for archive-only distribution.
	bool serveFiles = true;
	/// Archive formats to also build and serve as whole-skill downloads. Empty
	/// (the default) serves no archive.
	ArchiveFormat[] archives;
	/// Optional filter: return `false` to exclude a file by its skill-relative
	/// path (e.g. drop `.git/…` or `*.pyc`). `null` includes everything.
	bool delegate(string relPath) @safe include;
	/// Reject the directory if it holds more than this many files (a guard
	/// against accidentally serving an enormous tree).
	size_t maxFiles = 10_000;
	/// Reject the directory if its files total more than this many bytes.
	size_t maxTotalBytes = 64 * 1024 * 1024;
}

/// Register the skill directory `dir` on `server`. Reads `dir/SKILL.md` (served
/// verbatim, its frontmatter parsed for the index), walks the tree to expose
/// each file as a sibling resource, and builds any requested archive forms.
///
/// Throws if `dir` is not a directory, has no `SKILL.md`, the frontmatter lacks
/// a string `name`, the resolved skill path is invalid or its final segment does
/// not match the frontmatter `name`, a nested `SKILL.md` is found (skills do not
/// nest), a symlink is encountered, or the file count / total size exceeds the
/// configured caps.
void registerSkillDir(McpServer server, string dir, SkillDirOptions options = SkillDirOptions.init) @safe
{
	import std.base64 : Base64;

	if (!pathIsDir(dir))
		throw new Exception("registerSkillDir: not a directory: " ~ dir);
	const skillMdPath = joinPath(dir, "SKILL.md");
	if (!pathExists(skillMdPath))
		throw new Exception("registerSkillDir: missing SKILL.md in " ~ dir);

	const skillMd = readTextFile(skillMdPath);
	Json frontmatter = parseFrontmatter(skillMd);
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

	// Collect the tree once if either the per-file resources or any archive needs
	// it. An archive packs the whole directory regardless of `serveFiles`.
	RawFile[] raws;
	if (options.serveFiles || options.archives.length)
		raws = collectFiles(dir, options.include, options.maxFiles, options.maxTotalBytes);

	SkillFile[] files;
	if (options.serveFiles)
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

	SkillArchive[] archives;
	foreach (fmt; options.archives)
		archives ~= buildArchive(fmt, cast(immutable(ubyte)[]) skillMd, raws);

	registerSkillResources(server, path, skillMd, frontmatter, files, archives);
}

// --- Frontmatter -----------------------------------------------------------

/// Parse the leading `---`-delimited YAML frontmatter of a `SKILL.md` into a
/// JSON object (the verbatim `frontmatter` SEP-2640 puts in the index). The fence
/// is matched a line at a time: the file must open with a line that is exactly
/// `---`, and the frontmatter ends at the next line that is exactly `---` or
/// `...` — so a `---` appearing inside a value does not close it early, and CRLF
/// line endings work.
private Json parseFrontmatter(string md) @safe
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

// --- Filesystem walk -------------------------------------------------------

/// A file read from a skill directory, ready to become a resource and/or an
/// archive entry.
private struct RawFile
{
	string path; /// skill-relative posix path, e.g. "references/FORMS.md"
	immutable(ubyte)[] bytes; /// raw file contents
	string mimeType; /// inferred MIME type
	bool isText; /// served as text (vs base64 blob)
}

private RawFile[] collectFiles(string dir,
		scope bool delegate(string) @safe include, size_t maxFiles, size_t maxTotalBytes) @safe
{
	import std.algorithm : sort;

	RawFile[] files;
	size_t total;
	walkInto(dir, "", files, total, include, maxFiles, maxTotalBytes);
	// Sort by path so both the served order and the archive bytes are deterministic.
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
		// file; a SKILL.md anywhere deeper would mean a nested skill, which the
		// spec forbids.
		if (entry.name == "SKILL.md")
		{
			if (rel.length == 0)
				continue;
			throw new Exception(
					"registerSkillDir: a nested SKILL.md is not allowed (skills do not nest): "
					~ childRel);
		}
		if (include !is null && !include(childRel))
			continue;

		if (files.length + 1 > maxFiles)
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

// --- Archive building ------------------------------------------------------

/// Pack `skillMd` (as `SKILL.md`) plus every file into one archive of `fmt`,
/// base64-encoded into a `SkillArchive`. Entries are sorted and carry no
/// timestamps, so the archive bytes — and thus the index digest — are stable
/// across runs.
private SkillArchive buildArchive(ArchiveFormat fmt, immutable(ubyte)[] skillMd, RawFile[] files) @safe
{
	import std.base64 : Base64;

	ArchiveEntry[] entries;
	entries ~= ArchiveEntry("SKILL.md", skillMd);
	foreach (f; files)
		entries ~= ArchiveEntry(f.path, f.bytes);

	immutable(ubyte)[] data;
	string suffix, mime;
	final switch (fmt)
	{
	case ArchiveFormat.zip:
		data = buildZip(entries);
		suffix = ".zip";
		mime = "application/zip";
		break;
	case ArchiveFormat.tarGz:
		data = buildTarGz(entries);
		suffix = ".tar.gz";
		mime = "application/gzip";
		break;
	}
	return SkillArchive(suffix, mime, Base64.encode(data).idup);
}

private struct ArchiveEntry
{
	string name;
	immutable(ubyte)[] bytes;
}

private immutable(ubyte)[] buildZip(ArchiveEntry[] entries) @trusted
{
	import archive.zip : ZipArchive;

	import std.datetime.systime : DosFileTime;

	auto zip = new ZipArchive();
	foreach (e; entries)
	{
		auto f = new ZipArchive.File(e.name);
		f.data = e.bytes;
		f.modificationTime = cast(DosFileTime) 0; // fixed, for deterministic output
		zip.addFile(f);
	}
	return (cast(ubyte[]) zip.serialize()).idup;
}

private immutable(ubyte)[] buildTarGz(ArchiveEntry[] entries) @trusted
{
	import archive.targz : TarGzArchive;

	auto tar = new TarGzArchive();
	foreach (e; entries)
	{
		auto f = new TarGzArchive.File(e.name);
		f.data = e.bytes;
		f.modificationTime = 0;
		f.permissions = 420; // 0644, fixed for deterministic output
		tar.addFile(f);
	}
	return (cast(ubyte[]) tar.serialize()).idup;
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
}

unittest  // registerSkillDir serves SKILL.md verbatim with authored, type-preserved frontmatter
{
	import mcp.api.skills : skillIndexUri;
	import vibe.data.json : parseJsonString;
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

	// The index frontmatter is the parsed YAML — every field, with types kept.
	const idx = readResource(s, 2, skillIndexUri)["text"].get!string;
	auto e = parseJsonString(idx)["skills"][0];
	assert(e["frontmatter"]["name"].get!string == "pdf-forms");
	assert(e["frontmatter"]["license"].get!string == "Apache-2.0");
	assert(e["frontmatter"]["metadata"]["version"].get!string == "2.1.0");
	assert(e["frontmatter"]["metadata"]["experimental"].get!bool == true);
	assert(e["url"].get!string == "skill://pdf-forms/SKILL.md");
	assert(e["digest"].get!string == skillDigestOf(md));
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

unittest  // registerSkillDir builds and lists a requested archive form
{
	import mcp.api.skills : skillIndexUri;
	import vibe.data.json : parseJsonString;

	const root = tmpRoot("archive");
	writeSkillFixture(root);
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	SkillDirOptions opts;
	opts.archives = [ArchiveFormat.zip, ArchiveFormat.tarGz];
	registerSkillDir(s, root, opts);

	const idx = readResource(s, 1, skillIndexUri)["text"].get!string;
	auto archives = parseJsonString(idx)["skills"][0]["archives"];
	assert(archives.length == 2);
	assert(archives[0]["url"].get!string == "skill://pdf-forms.zip");
	assert(archives[0]["mimeType"].get!string == "application/zip");
	assert(archives[1]["url"].get!string == "skill://pdf-forms.tar.gz");
	assert(archives[1]["mimeType"].get!string == "application/gzip");

	// Each archive resource is readable as a blob.
	assert(readResource(s, 2, "skill://pdf-forms.zip")["blob"].get!string.length > 0);
	assert(readResource(s, 3, "skill://pdf-forms.tar.gz")["blob"].get!string.length > 0);
}

unittest  // archive bytes are deterministic — same input, same digest across runs
{
	import mcp.api.skills : skillIndexUri;
	import vibe.data.json : parseJsonString;

	string digestFor(string suffix) @safe
	{
		const root = tmpRoot("determinism-" ~ suffix);
		writeSkillFixture(root);
		scope (exit)
			removeTree(root);
		auto s = new McpServer("t", "1");
		SkillDirOptions opts;
		opts.archives = [ArchiveFormat.zip];
		registerSkillDir(s, root, opts);
		const idx = readResource(s, 1, skillIndexUri)["text"].get!string;
		return parseJsonString(idx)["skills"][0]["archives"][0]["digest"].get!string;
	}

	assert(digestFor("a") == digestFor("b"));
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

unittest  // registerSkillDir rejects a nested SKILL.md (skills do not nest)
{
	import std.exception : assertThrown;

	const root = tmpRoot("nested");
	writeSkillFixture(root);
	scope (exit)
		removeTree(root);
	writeFile(root ~ "/references/SKILL.md", "---\nname: x\ndescription: y\n---\n");

	auto s = new McpServer("t", "1");
	assertThrown!Exception(registerSkillDir(s, root));
}

unittest  // registerSkillDir honours an explicit prefixed path matching the frontmatter name
{
	import mcp.api.skills : skillIndexUri;
	import vibe.data.json : parseJsonString;

	const root = tmpRoot("prefix");
	writeSkillFixture(root);
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	SkillDirOptions opts;
	opts.path = "office/pdf-forms"; // final segment matches frontmatter name
	registerSkillDir(s, root, opts);

	const idx = readResource(s, 1, skillIndexUri)["text"].get!string;
	assert(parseJsonString(
			idx)["skills"][0]["url"].get!string == "skill://office/pdf-forms/SKILL.md");
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
	import mcp.api.skills : skillIndexUri;
	import vibe.data.json : parseJsonString;

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

	const idx = readResource(s, 1, skillIndexUri)["text"].get!string;
	auto fm = parseJsonString(idx)["skills"][0]["frontmatter"];
	assert(fm["trailing"].get!string == "kept");
}

unittest  // a CRLF SKILL.md parses (fence and values carry trailing \r)
{
	import mcp.api.skills : skillIndexUri;
	import vibe.data.json : parseJsonString;

	const root = tmpRoot("crlf");
	writeRawSkill(root, "---\r\nname: crlf-skill\r\ndescription: a value\r\n---\r\n\r\n# Body\r\n");
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	registerSkillDir(s, root);

	const idx = readResource(s, 1, skillIndexUri)["text"].get!string;
	auto fm = parseJsonString(idx)["skills"][0]["frontmatter"];
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
	import mcp.api.skills : skillIndexUri;
	import vibe.data.json : parseJsonString;
	import std.algorithm : canFind;

	const root = tmpRoot("timestamp");
	writeRawSkill(root, "---\nname: ts-skill\ndescription: d\ncreated: 2021-01-02\n---\n\n# Body\n");
	scope (exit)
		removeTree(root);

	auto s = new McpServer("t", "1");
	registerSkillDir(s, root);

	const idx = readResource(s, 1, skillIndexUri)["text"].get!string;
	auto fm = parseJsonString(idx)["skills"][0]["frontmatter"];
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
	import mcp.api.skills : skillDigest;

	return skillDigest(cast(const(ubyte)[]) s);
}
