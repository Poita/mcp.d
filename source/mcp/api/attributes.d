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
struct prompt
{
    string name;
    string description;
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

/// Optional per-parameter description, attached to a function parameter or used
/// alongside `@tool` to document a named argument.
struct describe
{
    string parameter;
    string description;
}
