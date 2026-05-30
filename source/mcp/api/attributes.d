module mcp.api.attributes;

import std.typecons : Nullable;

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
/// (readOnlyHint, destructiveHint, ...), attach a `@toolAnnotations` UDA to the
/// same method.
struct tool
{
    string name;
    string description;
    string title; /// optional human-readable display name (empty = unset)
}

/// UDA declaring optional behavioral hints (the MCP spec's `ToolAnnotations`)
/// for a `@tool`-annotated method. Attach alongside `@tool`; each hint defaults
/// to "unset" and is omitted from the wire form unless assigned.
///
/// Example:
/// ---
/// import std.typecons : nullable;
/// @tool("erase", "Erase a record")
/// @toolAnnotations(destructiveHint: true.nullable, idempotentHint: true.nullable)
/// void erase(string id) { ... }
/// ---
struct toolAnnotations
{
    Nullable!bool readOnlyHint;
    Nullable!bool destructiveHint;
    Nullable!bool idempotentHint;
    Nullable!bool openWorldHint;
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

/// UDA declaring optional MCP `Annotations` (audience / priority /
/// lastModified) for a `@resource`- or `@resourceTemplate`-annotated method.
/// Attach alongside the resource UDA; each field defaults to "unset" and is
/// omitted from the wire form unless assigned.
///
/// Example:
/// ---
/// import std.typecons : nullable;
/// @resource("file:///readme", "Readme", "text/markdown")
/// @resourceAnnotations(audience: ["user"], priority: 0.9.nullable)
/// string readme() { return "..."; }
/// ---
struct resourceAnnotations
{
    string[] audience; /// intended audience, e.g. ["user", "assistant"]
    Nullable!double priority; /// importance 0.0..1.0
    Nullable!string lastModified; /// ISO 8601 last-modified timestamp
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
