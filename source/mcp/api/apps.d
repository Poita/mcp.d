module mcp.api.apps;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

@safe:

/// The MCP Apps extension identifier (the key under `capabilities.extensions`
/// and the namespace these helpers serialize under). A host advertises support
/// for interactive UI by declaring this extension during initialization.
enum string mcpAppsExtensionKey = "io.modelcontextprotocol/ui";

/// The MIME type a UI resource declares for HTML app content.
enum string mcpAppMimeType = "text/html;profile=mcp-app";

/// A tool's link to a UI resource, serialized under the tool's `_meta.ui`.
/// `resourceUri` points at the `ui://` resource the host renders; `visibility`
/// names who may invoke the tool ("model" and/or "app"). An empty `visibility`
/// is omitted from the wire form, leaving the spec default (`["model","app"]`).
struct UiToolMeta
{
	string resourceUri; /// the `ui://` resource the tool renders
	string[] visibility; /// who may call the tool: "model" and/or "app"

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["resourceUri"] = resourceUri;
		if (visibility.length)
		{
			Json arr = Json.emptyArray;
			foreach (v; visibility)
				arr ~= Json(v);
			j["visibility"] = arr;
		}
		return j;
	}

	static UiToolMeta fromJson(Json j) @safe
	{
		UiToolMeta m;
		if ("resourceUri" in j && j["resourceUri"].type == Json.Type.string)
			m.resourceUri = j["resourceUri"].get!string;
		if ("visibility" in j && j["visibility"].type == Json.Type.array)
			foreach (i; 0 .. j["visibility"].length)
				m.visibility ~= j["visibility"][i].get!string;
		return m;
	}
}

unittest  // UiToolMeta serializes to the spec's _meta.ui shape
{
	UiToolMeta ui = {
		resourceUri: "ui://weather/dashboard", visibility: ["model", "app"]
	};
	auto j = ui.toJson();
	assert(j["resourceUri"].get!string == "ui://weather/dashboard");
	assert(j["visibility"].length == 2);
	assert(j["visibility"][0].get!string == "model");
	assert(j["visibility"][1].get!string == "app");
}

unittest  // UiToolMeta omits visibility when empty (spec default is ["model","app"])
{
	UiToolMeta ui = {resourceUri: "ui://x/y"};
	auto j = ui.toJson();
	assert(j["resourceUri"].get!string == "ui://x/y");
	assert("visibility" !in j);
}

unittest  // UiToolMeta round-trips through fromJson
{
	UiToolMeta ui = {resourceUri: "ui://x/y", visibility: ["app"]};
	auto back = UiToolMeta.fromJson(ui.toJson());
	assert(back.resourceUri == "ui://x/y");
	assert(back.visibility == ["app"]);
}

unittest  // mcp-app constants carry the spec's literal strings
{
	assert(mcpAppsExtensionKey == "io.modelcontextprotocol/ui");
	assert(mcpAppMimeType == "text/html;profile=mcp-app");
}
