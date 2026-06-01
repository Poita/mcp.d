module mcp.api.attributes;

import vibe.data.json : Json;

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

/// UDA declaring a `@tool`-annotated method's per-tool task-augmented execution
/// support (the MCP 2025-11-25 `Tool.execution` descriptor). Attach alongside
/// `@tool`; `taskSupport` must be one of `"forbidden"` (the default when this
/// UDA is absent), `"optional"`, or `"required"`.
///
/// Example:
/// ---
/// @tool("render", "Render a long report")
/// @toolExecution("optional")
/// string render(string spec) { ... }
/// ---
struct toolExecution
{
	string taskSupport; /// "forbidden" | "optional" | "required"
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
struct resource
{
	string uri;
	string name;
	string mimeType;
}

/// UDA marking a method as a resource template (URI contains `{var}`
/// placeholders). The method receives the captured parameters as its arguments.
struct resourceTemplate
{
	string uriTemplate;
	string name;
	string mimeType;
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
}

/// Positional value UDA declaring the ISO 8601 `lastModified` timestamp for a
/// `@resource`- or `@resourceTemplate`-annotated method (the MCP
/// `Annotations.lastModified` field). Absence leaves it unset.
struct lastModified
{
	string value; /// ISO 8601 last-modified timestamp
}

/// Optional per-parameter description, attached to a function parameter or used
/// alongside `@tool` to document a named argument.
struct describe
{
	string parameter;
	string description;
}

/// UDA marking a `@tool` parameter as mirrored into an HTTP request header.
///
/// Per the MCP draft (`server/tools` #x-mcp-header), a server MAY designate tool
/// parameters to be mirrored into headers via an `x-mcp-header` extension
/// property in the parameter's `inputSchema`. Apply this UDA directly to the
/// parameter; the reflection layer emits the corresponding `x-mcp-header`
/// property (carrying `name`) into the generated input schema, so that the
/// streamable-HTTP transport can validate the `Mcp-Param-<name>` header against
/// the argument value.
///
/// Example:
/// ---
/// @tool("query", "Query a region")
/// string query(@mcpHeader("Region") string region) { ... }
/// ---
struct mcpHeader
{
	string name; /// the header suffix, e.g. "Region" -> `Mcp-Param-Region`
}

/// UDA declaring a display icon for a `@tool`, `@resource`, or
/// `@resourceTemplate`-annotated method (the MCP `Icons` mixin: `Tool.icons`,
/// `Resource.icons`). Attach one or more `@icon` UDAs to the same method; each
/// becomes an entry in the descriptor's `icons` array. `src` is required;
/// `mimeType` and `sizes` are optional.
///
/// Example:
/// ---
/// @tool("draw", "Draw something")
/// @icon("https://example.com/draw.png", "image/png", ["48x48"])
/// string draw(string spec) { ... }
/// ---
struct icon
{
	string src; /// URI or data: URL of the icon (required)
	string mimeType; /// optional MIME type, e.g. "image/png" (empty = unset)
	string[] sizes; /// optional size strings, e.g. ["48x48", "96x96"]
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

/// Field-level UDA declaring a numeric lower bound (the JSON Schema `minimum`
/// keyword) for a struct field. When `jsonSchemaOf!T` reflects over a struct,
/// a field annotated with `@minimum(v)` emits `"minimum": v` on its property
/// schema. Intended for numeric / integer fields (e.g. tool input or
/// elicitation form schemas); applying it to a non-numeric field has no
/// defined meaning but the bound is still emitted verbatim.
///
/// Example:
/// ---
/// struct Form
/// {
///     @minimum(1) @maximum(100) int count;
/// }
/// ---
struct minimum
{
	double value; /// the inclusive lower bound emitted as JSON Schema `minimum`
}

/// Field-level UDA declaring a numeric upper bound (the JSON Schema `maximum`
/// keyword) for a struct field. See `@minimum` for usage; a field annotated
/// with `@maximum(v)` emits `"maximum": v` on its property schema.
struct maximum
{
	double value; /// the inclusive upper bound emitted as JSON Schema `maximum`
}

/// Field-level UDA declaring a human-readable display `title` (the JSON Schema
/// `title` keyword) for a struct field. When `jsonSchemaOf!T` reflects over a
/// struct, a field annotated with `@title("…")` emits `"title": "…"` on its
/// property schema.
///
/// Example:
/// ---
/// struct Form
/// {
///     @title("Item count") int count;
/// }
/// ---
struct title
{
	string value; /// the display title emitted as JSON Schema `title`
}

/// Field-level UDA declaring a default value (the JSON Schema `default`
/// keyword) for a struct field. Named `@schemaDefault` to avoid clashing with
/// D's `default` keyword. When `jsonSchemaOf!T` reflects over a struct, a field
/// annotated with `@schemaDefault(v)` emits `"default": v` on its property
/// schema, serializing the value (an `enum` value is emitted as its wire string,
/// a `bool` as a JSON boolean, etc.).
///
/// Example:
/// ---
/// struct Form
/// {
///     @schemaDefault(false) bool verbose;
///     @schemaDefault(10) int limit;
/// }
/// ---
/// The payload struct carrying a `@schemaDefault` value. Construct it via the
/// `schemaDefault(value)` factory below rather than naming it directly; the
/// reflection layer detects it with `isInstanceOf!(SchemaDefault, UDA)`.
struct SchemaDefault(T)
{
	T value; /// the default value emitted (serialized) as JSON Schema `default`
}

/// Factory producing the `@schemaDefault` UDA so the element type is inferred
/// from the supplied value (`@schemaDefault(false)` rather than
/// `@schemaDefault!bool(false)`).
SchemaDefault!T schemaDefault(T)(T value) @safe pure nothrow
{
	return SchemaDefault!T(value);
}

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
/// @cache(5000, "private")
/// string data() { ... }
/// ---
struct cache
{
	long ttlMs; /// how long the result may be cached, in milliseconds
	string scope_ = "public"; /// "public" (default) | "private"
}
