module mcp.api.attributes;

import vibe.data.json : Json;
import core.time : Duration;

@safe:

/// UDA marking a method as an MCP tool. Apply to a member function; the input
/// schema is derived from the parameter types, and the return value is wrapped
/// into a tool result.
///
/// Example:
/// ---
/// class Calc
/// {
///     @tool("add", "Add two integers")
///     int add(int a, int b) { return a + b; }
/// }
/// ---
///
/// An optional human-readable `title` may be supplied for display purposes; it
/// is independent of the programmatic `name`. To declare behavioral hints
/// (readOnlyHint, destructiveHint, ...), attach the marker UDAs `@readOnly`,
/// `@destructive`, `@idempotent`, `@openWorld` (and `@hintTitle(...)` for the
/// annotation-level title) to the same method.
struct tool
{
	string name;
	string description;
	string title; /// optional human-readable display name (empty = unset)
}

/// UDA marking a method as an asynchronous MCP task tool (SEP-2663). Like `@tool`,
/// the input schema is derived from the parameter types; but the `tools/call`
/// returns a task handle immediately and the method body runs asynchronously via
/// the server's task dispatcher, its return value becoming the task's final
/// result. The method may take an injected `TaskContext` parameter (omitted from
/// the input schema) to report progress, observe cancellation, or suspend for
/// mid-execution input via `requireInput`. Requires `enableTasks()` on the server.
///
/// Behavioral-hint marker UDAs (`@readOnly`, `@destructive`, ...) and
/// `@hintTitle` apply exactly as for `@tool`.
///
/// Example:
/// ---
/// @task("word_count", "Count words asynchronously")
/// @readOnly
/// WordCount count(string text, TaskContext tc) @safe { ... }
/// ---
struct task
{
	string name;
	string description;
	string title; /// optional human-readable display name (empty = unset)
}

/// Per-task time-to-live UDA, attached alongside `@task`: how long the task lives
/// from creation. Intrinsic to the work the task does (a long-running job vs a
/// quick computation), so it belongs on the task, not the server. Omit it to
/// inherit `TaskOptions.defaultTtl`.
///
/// Example:
/// ---
/// import core.time : hours;
/// @task("build", "Run the build")
/// @taskTtl(1.hours)
/// BuildResult build(string target, TaskContext tc) @safe { ... }
/// ---
struct taskTtl
{
	import core.time : Duration;

	Duration value; /// task TTL (serialized to integer ms on the wire)
}

/// Per-task poll-cadence UDA, attached alongside `@task`: the interval the client
/// SHOULD wait between `tasks/get` polls. Like `@taskTtl`, it is intrinsic to the
/// task. Omit it to inherit `TaskOptions.defaultPollInterval`.
///
/// Example:
/// ---
/// import core.time : seconds;
/// @task("build", "Run the build")
/// @taskTtl(1.hours) @taskPollInterval(5.seconds)
/// BuildResult build(string target, TaskContext tc) @safe { ... }
/// ---
struct taskPollInterval
{
	import core.time : Duration;

	Duration value; /// suggested poll cadence (serialized to integer ms on the wire)
}

/// Marker UDA declaring the `readOnlyHint` behavioral hint (the MCP spec's
/// `ToolAnnotations.readOnlyHint`). Attach alongside `@tool`; presence sets the
/// hint to `true`, absence leaves it unset (omitted from the wire form).
///
/// Example:
/// ---
/// @tool("search", "Search records")
/// @readOnly
/// string[] search(string q) { ... }
/// ---
enum readOnly;

/// Marker UDA declaring the `destructiveHint` behavioral hint
/// (`ToolAnnotations.destructiveHint`). Presence = `true`; absence = unset.
enum destructive;

/// Marker UDA declaring the `idempotentHint` behavioral hint
/// (`ToolAnnotations.idempotentHint`). Presence = `true`; absence = unset.
enum idempotent;

/// Marker UDA declaring the `openWorldHint` behavioral hint
/// (`ToolAnnotations.openWorldHint`). Presence = `true`; absence = unset.
enum openWorld;

/// Positional value UDA setting the annotation-level display title
/// (`ToolAnnotations.title`), distinct from `@tool`'s 3rd argument
/// (`Tool.title`). Attach alongside `@tool`.
///
/// Example:
/// ---
/// @tool("erase", "Erase a record")
/// @destructive @idempotent @hintTitle("Erase Record")
/// void erase(string id) { ... }
/// ---
struct hintTitle
{
	string value; /// the annotation-level display title (ToolAnnotations.title)
}

/// UDA marking a method as an MCP prompt. The method returns the prompt's
/// messages (a `PromptMessage[]`, a `GetPromptResult`, or a `string`).
///
/// An optional human-readable `title` may be supplied for display purposes; it
/// is independent of the programmatic `name`.
struct prompt
{
	string name;
	string description;
	string title; /// optional human-readable display name (empty = unset)
}

/// UDA marking a method as a static MCP resource. The method takes no arguments
/// and returns the resource contents (`string`, or a `ResourceContents`).
///
/// An optional human-readable `title` may be supplied for display purposes; it
/// is independent of the programmatic `name`.
struct resource
{
	string uri;
	string name;
	string mimeType;
	string description;
	string title; /// optional human-readable display name (empty = unset)
}

/// UDA marking a method as an MCP skill (SEP-2640, the
/// `io.modelcontextprotocol/skills` extension). The method takes no arguments
/// and returns the `SKILL.md` instructions body as a `string`; the reflection
/// layer synthesizes the YAML frontmatter from the skill `path`'s final segment
/// and `description`, serves it as a `skill://<path>/SKILL.md` markdown resource,
/// advertises the skills extension, and lists a conformant entry (verbatim
/// frontmatter, url, sha256 digest) in the `skill://index.json` discovery
/// resource. `path` is a `/`-separated locator whose final segment is the skill
/// name; that segment must be lowercase alphanumeric with single hyphens
/// (1..64 chars), per the Agent Skills spec. Preceding segments are an optional
/// organizational prefix (e.g. `acme/billing/refunds`).
///
/// The directory is read eagerly at `registerHandlers` time (a skill is a static
/// value — its frontmatter and content digest must be stable), so a missing
/// directory, absent `SKILL.md`, symlink, or oversized tree throws from
/// registration rather than per request.
///
/// Example:
/// ---
/// @skill("git-workflow", "Follow this team's Git conventions")
/// string gitWorkflow() @safe { return "# Git Workflow\n\n1. Branch from main.\n"; }
/// ---
struct skill
{
	string path;
	string description;
}

/// An archive format a skill directory can be packed into and served as an
/// alternative whole-skill download (SEP-2640 "archives"). `zip` needs no extra
/// dependency; `tarGz` produces a gzip-compressed tar. Used by `@skillDir` and
/// `SkillDirOptions` (`mcp.api.skill_dir`).
enum ArchiveFormat
{
	zip, /// a ZIP archive (`application/zip`, served at `skill://<path>.zip`)
	tarGz /// a gzip-compressed tar (`application/gzip`, served at `skill://<path>.tar.gz`)
}

/// UDA marking a method as an MCP skill served from a local directory (SEP-2640).
/// The method takes no arguments and returns the path to a local skill directory
/// (one containing a `SKILL.md`); the reflection layer reads `SKILL.md` verbatim,
/// parses its authored frontmatter for the index, exposes every file in the
/// directory tree as a `skill://<path>/<file>` resource (so subdirectories are
/// walkable via `resources/directory/read`), and — for each `ArchiveFormat`
/// passed — packs the whole directory into a downloadable archive listed in the
/// index. `path` is the skill path (its final segment must equal the directory's
/// `SKILL.md` frontmatter `name`); leave it empty to derive the path from that
/// name. For finer control (read filters, size caps) use the imperative
/// `registerSkillDir` with `SkillDirOptions`.
///
/// Example:
/// ---
/// @skillDir("office/pdf-forms", ArchiveFormat.zip)
/// string pdfForms() @safe { return "skills/pdf-forms"; }
/// ---
struct skillDir
{
	string path;
	ArchiveFormat[] archives;

	/// Construct from a skill path and zero or more archive formats to also
	/// expose (`@skillDir("x")`, `@skillDir("x", ArchiveFormat.zip)`,
	/// `@skillDir("x", ArchiveFormat.zip, ArchiveFormat.tarGz)`).
	this(string path, ArchiveFormat[] archives...) @safe
	{
		this.path = path;
		this.archives = archives.dup;
	}
}

/// UDA marking a method as a resource template (URI contains `{var}`
/// placeholders). The method receives the captured parameters as its arguments.
///
/// An optional human-readable `title` may be supplied for display purposes; it
/// is independent of the programmatic `name`.
struct resourceTemplate
{
	string uriTemplate;
	string name;
	string mimeType;
	string description;
	string title; /// optional human-readable display name (empty = unset)
}

/// Positional value UDA declaring the intended `audience` for a `@resource`- or
/// `@resourceTemplate`-annotated method (the MCP `Annotations.audience` field).
/// Pass one or more roles, e.g. `@audience("user")` or
/// `@audience("user", "assistant")`. Absence leaves the audience unset.
///
/// Example:
/// ---
/// @resource("file:///readme", "Readme", "text/markdown")
/// @priority(0.9) @audience("user")
/// string readme() { return "..."; }
/// ---
struct audience
{
	string[] roles; /// intended audience, e.g. ["user", "assistant"]

	this(string[] roles...) @safe pure nothrow
	{
		this.roles = roles.dup;
	}
}

/// Positional value UDA declaring the importance `priority` (0.0..1.0) for a
/// `@resource`- or `@resourceTemplate`-annotated method (the MCP
/// `Annotations.priority` field). Absence leaves the priority unset.
struct priority
{
	double value; /// importance 0.0 (least) .. 1.0 (most)

	this(double value) @safe pure nothrow
	in (value >= 0.0 && value <= 1.0, "@priority value must be in [0.0, 1.0]")
	{
		this.value = value;
	}
}

/// Positional value UDA declaring the ISO 8601 `lastModified` timestamp for a
/// `@resource`- or `@resourceTemplate`-annotated method (the MCP
/// `Annotations.lastModified` field). Absence leaves it unset.
struct lastModified
{
	string value; /// ISO 8601 last-modified timestamp
}

/// Method-level UDA documenting a named parameter of a `@tool`, `@task`, or
/// `@prompt` method. Attach it to the method declaration (never inline to a
/// parameter); `parameter` names the argument it documents and `description`
/// is the human-readable text folded into that property's JSON Schema
/// `description` (or, for prompts, into `PromptArgument.description`).
///
/// Repeatable: attach one `@describeParam` per documented parameter. Naming a
/// parameter that the method does not declare — or an injected context
/// parameter (a trailing `RequestContext` / `TaskContext`, which has no schema
/// property) — is a compile-time error.
///
/// Example:
/// ---
/// @tool("annotate", "Annotate a document")
/// @describeParam("id", "the document id")
/// @describeParam("count", "how many copies")
/// string annotate(string id, int count) { ... }
/// ---
struct describeParam
{
	string parameter;
	string description;
}

/// Method-level UDA mirroring a named `@tool` parameter into an HTTP request
/// header. Attach it to the method declaration (never inline to a parameter):
/// `parameter` names the tool argument and `name` is the header suffix, so the
/// argument is mirrored into the `Mcp-Param-<name>` request header.
///
/// Per the MCP draft (`server/tools` #x-mcp-header), a server MAY designate tool
/// parameters to be mirrored into headers via an `x-mcp-header` extension
/// property in the parameter's `inputSchema`. The reflection layer emits the
/// corresponding `x-mcp-header` property (carrying `name`) onto the named
/// parameter's schema, so the streamable-HTTP transport can validate the
/// `Mcp-Param-<name>` header against the argument value.
///
/// Naming a parameter the method does not declare is a compile-time error, as is
/// applying it to a non-primitive parameter (only integer/string/boolean — or a
/// `Nullable` thereof — are permitted x-mcp-header value types).
///
/// Example:
/// ---
/// @tool("query", "Query a region")
/// @mcpHeader("region", "Region")
/// string query(string region) { ... }
/// ---
struct mcpHeader
{
	string parameter; /// the tool parameter mirrored into the header
	string name; /// the header suffix, e.g. "Region" -> `Mcp-Param-Region`
}

/// UDA declaring a display icon for a `@tool`, `@resource`, or
/// `@resourceTemplate`-annotated method (the MCP `Icons` mixin: `Tool.icons`,
/// `Resource.icons`). Attach one or more `@icon` UDAs to the same method; each
/// becomes an entry in the descriptor's `icons` array. `src` is required;
/// `mimeType`, `sizes`, and `theme` are optional.
///
/// Example:
/// ---
/// @tool("draw", "Draw something")
/// @icon("https://example.com/draw.png", "image/png", ["48x48"], "dark")
/// string draw(string spec) { ... }
/// ---
struct icon
{
	string src; /// URI or data: URL of the icon (required)
	string mimeType; /// optional MIME type, e.g. "image/png" (empty = unset)
	string[] sizes; /// optional size strings, e.g. ["48x48", "96x96"]
	string theme; /// optional theme preference: "light" or "dark" (empty = unset)
}

/// UDA linking a `@tool`-annotated method to an MCP Apps UI resource (the MCP
/// Apps `_meta.ui` field on `Tool`). `resourceUri` points at the `ui://`
/// resource a host renders for this tool; the optional trailing `visibility`
/// roles name who may invoke the tool ("model" and/or "app"). The reflection
/// layer folds this into the tool's `_meta.ui`, merging with any `@meta` object.
///
/// Example:
/// ---
/// @tool("get_weather", "Show the weather dashboard")
/// @ui("ui://weather/dashboard", "model", "app")
/// WeatherData getWeather(string city) { ... }
/// ---
struct ui
{
	string resourceUri; /// the `ui://` resource the tool renders
	string[] visibility; /// optional roles permitted to call the tool

	this(string resourceUri, string[] visibility...) @safe pure nothrow
	{
		this.resourceUri = resourceUri;
		this.visibility = visibility.dup;
	}
}

/// UDA attaching a descriptor-level `_meta` object to a `@tool`, `@resource`,
/// or `@resourceTemplate`-annotated method (the MCP `_meta` field on `Tool`,
/// `Resource`, `ResourceTemplate`). The supplied JSON must be an object; it is
/// emitted verbatim as the descriptor's `_meta`.
///
/// Example:
/// ---
/// import vibe.data.json : parseJsonString;
/// @tool("x", "X")
/// @meta(parseJsonString(`{"category":"math"}`))
/// int x() { ... }
/// ---
struct meta
{
	Json value; /// the `_meta` object (must be a JSON object to be emitted)
}

/// The JSON Schema constraint UDAs (`@fieldDescription`, `@minimum`, `@maximum`,
/// `@title`, `@format`, `@minLength`, `@maxLength`, `@pattern`, `@minItems`,
/// `@maxItems`, `@schemaDefault`/`SchemaDefault`) are owned by the `jsonschema`
/// package, which also owns the schema generation (`jsonSchemaOf`) and facet
/// application (`applyUdaFacets`) that consume them. They are re-exported here so
/// MCP users get them from `mcp.api.attributes` alongside the MCP-specific UDAs,
/// and so the type identity matches what `jsonschema` matches against.
public import jsonschema : fieldDescription, minimum, maximum, title, format,
	minLength, maxLength, pattern, minItems, maxItems, SchemaDefault, schemaDefault;

/// UDA declaring a per-resource / per-template draft `CacheableResult` freshness
/// hint for a `@resource`- or `@resourceTemplate`-annotated method. The reflection
/// layer plumbs it through to the matching low-level registration so a draft
/// `resources/read` carries `ttlMs` / `cacheScope`. Has no effect on pre-draft
/// protocol versions (the server only emits cache fields when negotiated to draft).
///
/// `scope_` is `"public"` (the default) or `"private"`.
///
/// Example:
/// ---
/// @resource("file:///data", "Data", "application/json")
/// @cache(5.seconds, "private")
/// string data() { ... }
/// ---
struct cache
{
	Duration ttl; /// how long the result may be cached
	string scope_ = "public"; /// "public" (default) | "private"
}

unittest  // @priority accepts in-range values
{
	auto p = priority(0.5);
	assert(p.value == 0.5);
}

unittest  // @priority accepts the boundary values 0.0 and 1.0
{
	assert(priority(0.0).value == 0.0);
	assert(priority(1.0).value == 1.0);
}

unittest  // @priority rejects out-of-range values via its contract
{
	import core.exception : AssertError;

	static bool rejects(double v) @trusted
	{
		try
			cast(void) priority(v);
		catch (AssertError)
			return true;
		return false;
	}

	assert(rejects(5.0));
	assert(rejects(-1.0));
}
