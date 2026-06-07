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

/// Field-level UDA declaring the JSON Schema string `format` keyword (e.g.
/// `"email"`, `"uri"`, `"date-time"`) for a struct/elicitation field. Emitted
/// verbatim onto the property schema by `jsonSchemaOf`.
struct format
{
	string value; /// the JSON Schema `format` token
}

/// Field-level UDA declaring the JSON Schema `minLength` keyword (minimum string
/// length) for a struct/elicitation string field.
struct minLength
{
	size_t value; /// inclusive minimum string length
}

/// Field-level UDA declaring the JSON Schema `maxLength` keyword (maximum string
/// length) for a struct/elicitation string field.
struct maxLength
{
	size_t value; /// inclusive maximum string length
}

/// Field-level UDA declaring the JSON Schema `pattern` keyword (an ECMA-262
/// regular expression a string must match) for a struct/elicitation field.
struct pattern
{
	string value; /// the regular-expression pattern
}

/// Field-level UDA declaring the JSON Schema `minItems` keyword (minimum array
/// length) for a struct/elicitation array field.
struct minItems
{
	size_t value; /// inclusive minimum array length
}

/// Field-level UDA declaring the JSON Schema `maxItems` keyword (maximum array
/// length) for a struct/elicitation array field.
struct maxItems
{
	size_t value; /// inclusive maximum array length
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
