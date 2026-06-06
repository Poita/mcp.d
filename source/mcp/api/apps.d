module mcp.api.apps;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

import mcp.server.server : McpServer;
import mcp.protocol.types : Tool, Resource, ResourceContents;

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

/// A UI resource's Content Security Policy hints, serialized under
/// `_meta.ui.csp`. Each list names the external origins the rendered app may
/// reach for a given purpose; empty lists are omitted from the wire form.
struct UiResourceCsp
{
	string[] connectDomains; /// origins the app may `fetch`/connect to
	string[] resourceDomains; /// origins the app may load scripts/styles/images from
	string[] frameDomains; /// origins the app may embed in frames
	string[] baseUriDomains; /// origins permitted in a `<base>` element

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		static void put(ref Json o, string key, const string[] domains) @safe
		{
			if (!domains.length)
				return;
			Json arr = Json.emptyArray;
			foreach (d; domains)
				arr ~= Json(d);
			o[key] = arr;
		}

		put(j, "connectDomains", connectDomains);
		put(j, "resourceDomains", resourceDomains);
		put(j, "frameDomains", frameDomains);
		put(j, "baseUriDomains", baseUriDomains);
		return j;
	}

	static UiResourceCsp fromJson(Json j) @safe
	{
		UiResourceCsp c;
		static string[] read(Json o, string key) @safe
		{
			string[] result;
			if (key in o && o[key].type == Json.Type.array)
				foreach (i; 0 .. o[key].length)
					result ~= o[key][i].get!string;
			return result;
		}

		c.connectDomains = read(j, "connectDomains");
		c.resourceDomains = read(j, "resourceDomains");
		c.frameDomains = read(j, "frameDomains");
		c.baseUriDomains = read(j, "baseUriDomains");
		return c;
	}

	/// Whether no domain list carries an entry (the wire form is `{}`).
	bool empty() const @safe nothrow @nogc
	{
		return connectDomains.length == 0 && resourceDomains.length == 0
			&& frameDomains.length == 0 && baseUriDomains.length == 0;
	}
}

/// The browser capabilities a UI resource requests, serialized under
/// `_meta.ui.permissions`. Each granted permission is emitted as an empty
/// object (`"camera": {}`); an ungranted one is omitted.
struct UiResourcePermissions
{
	bool camera; /// request camera access
	bool microphone; /// request microphone access
	bool geolocation; /// request geolocation access
	bool clipboardWrite; /// request clipboard-write access

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		if (camera)
			j["camera"] = Json.emptyObject;
		if (microphone)
			j["microphone"] = Json.emptyObject;
		if (geolocation)
			j["geolocation"] = Json.emptyObject;
		if (clipboardWrite)
			j["clipboardWrite"] = Json.emptyObject;
		return j;
	}

	static UiResourcePermissions fromJson(Json j) @safe
	{
		UiResourcePermissions p;
		p.camera = ("camera" in j) !is null;
		p.microphone = ("microphone" in j) !is null;
		p.geolocation = ("geolocation" in j) !is null;
		p.clipboardWrite = ("clipboardWrite" in j) !is null;
		return p;
	}

	/// Whether no permission is requested (the wire form is `{}`).
	bool empty() const @safe nothrow @nogc
	{
		return !camera && !microphone && !geolocation && !clipboardWrite;
	}
}

/// A UI resource's app-rendering metadata, serialized under the resource's
/// `_meta.ui`. `csp` and `permissions` are omitted when empty; `domain` (the
/// dedicated sandbox origin) and `prefersBorder` (a visual-boundary hint) are
/// omitted when unset.
struct UiResourceMeta
{
	UiResourceCsp csp; /// content-security-policy domain hints
	UiResourcePermissions permissions; /// requested browser capabilities
	Nullable!string domain; /// dedicated sandbox origin for the app
	Nullable!bool prefersBorder; /// whether the host should draw a visual boundary

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		if (!csp.empty)
			j["csp"] = csp.toJson();
		if (!permissions.empty)
			j["permissions"] = permissions.toJson();
		if (!domain.isNull)
			j["domain"] = domain.get;
		if (!prefersBorder.isNull)
			j["prefersBorder"] = prefersBorder.get;
		return j;
	}

	static UiResourceMeta fromJson(Json j) @safe
	{
		UiResourceMeta m;
		if ("csp" in j && j["csp"].type == Json.Type.object)
			m.csp = UiResourceCsp.fromJson(j["csp"]);
		if ("permissions" in j && j["permissions"].type == Json.Type.object)
			m.permissions = UiResourcePermissions.fromJson(j["permissions"]);
		if ("domain" in j && j["domain"].type == Json.Type.string)
			m.domain = nullable(j["domain"].get!string);
		if ("prefersBorder" in j && j["prefersBorder"].type == Json.Type.bool_)
			m.prefersBorder = nullable(j["prefersBorder"].get!bool);
		return m;
	}
}

/// Attach a UI link to a tool's `_meta` under the `ui` key, preserving any
/// other `_meta` entries already present. Use this on a `Tool` descriptor built
/// for `McpServer.registerDynamicTool`; the `@ui` UDA does the same for the
/// FastMCP-style `@tool` API.
void setUiToolMeta(ref Tool tool, UiToolMeta ui) @safe
{
	Json m = (tool.meta.type == Json.Type.object) ? tool.meta : Json.emptyObject;
	m["ui"] = ui.toJson();
	tool.meta = m;
}

/// Advertise MCP Apps support in the server's extension capabilities. The
/// extension is carried in the `extensions` negotiation map (emitted to draft
/// clients), declaring the content types this server's UI resources use.
/// `mimeTypes` defaults to `[mcpAppMimeType]`.
void advertiseMcpApps(McpServer server, string[] mimeTypes = null) @safe
{
	Json arr = Json.emptyArray;
	if (mimeTypes.length == 0)
		arr ~= Json(mcpAppMimeType);
	else
		foreach (m; mimeTypes)
			arr ~= Json(m);
	Json settings = Json.emptyObject;
	settings["mimeTypes"] = arr;
	server.advertiseExtension(mcpAppsExtensionKey, settings);
}

/// Whether the connected client advertised the MCP Apps extension at
/// initialization (valid after `initialize` / `server/discover`). A tool handler
/// can branch on this to decide whether to return a UI-linked result.
bool clientSupportsMcpApps(McpServer server) @safe
{
	auto ext = server.clientExtensions();
	return ext.type == Json.Type.object && (mcpAppsExtensionKey in ext) !is null;
}

/// Register a `ui://` HTML resource an MCP App tool can render. The resource is
/// served with the `text/html;profile=mcp-app` MIME type and, when `meta`
/// carries any field, a `_meta.ui` object on both the listing and the read
/// contents. Throws if `uri` is not in the `ui://` scheme.
void registerUiResource(McpServer server, string uri, string name, string html,
		UiResourceMeta meta = UiResourceMeta.init, string description = null) @safe
{
	import std.algorithm.searching : startsWith;

	if (!uri.startsWith("ui://"))
		throw new Exception("a UI resource uri must start with \"ui://\", got: " ~ uri);

	const uiMeta = meta.toJson();
	Json wrapped = Json.undefined;
	if (uiMeta.length)
	{
		wrapped = Json.emptyObject;
		wrapped["ui"] = uiMeta;
	}

	Resource descriptor;
	descriptor.uri = uri;
	descriptor.name = name;
	descriptor.mimeType = nullable(mcpAppMimeType);
	if (description.length)
		descriptor.description = nullable(description);
	if (wrapped.type == Json.Type.object)
		descriptor.meta = wrapped;

	server.registerResource(descriptor, () @safe {
		auto c = ResourceContents.makeText(uri, mcpAppMimeType, html);
		if (wrapped.type == Json.Type.object)
			c.meta = wrapped;
		return c;
	});
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

unittest  // UiResourceCsp emits only the non-empty domain lists
{
	UiResourceCsp csp;
	csp.connectDomains = ["https://api.example.com"];
	csp.resourceDomains = ["https://cdn.example.com"];
	auto j = csp.toJson();
	assert(j["connectDomains"][0].get!string == "https://api.example.com");
	assert(j["resourceDomains"][0].get!string == "https://cdn.example.com");
	assert("frameDomains" !in j);
	assert("baseUriDomains" !in j);
}

unittest  // UiResourceCsp with no domains is an empty object
{
	UiResourceCsp csp;
	assert(csp.toJson().length == 0);
}

unittest  // UiResourcePermissions emits each granted permission as {}
{
	UiResourcePermissions perms;
	perms.camera = true;
	perms.microphone = true;
	auto j = perms.toJson();
	assert(j["camera"].type == Json.Type.object && j["camera"].length == 0);
	assert(j["microphone"].type == Json.Type.object);
	assert("geolocation" !in j);
	assert("clipboardWrite" !in j);
}

unittest  // UiResourceMeta serializes the full spec _meta.ui resource shape
{
	UiResourceMeta meta;
	meta.csp.connectDomains = ["https://api.example.com"];
	meta.permissions.camera = true;
	meta.domain = nullable("a904.example-content.com");
	meta.prefersBorder = nullable(true);
	auto j = meta.toJson();
	assert(j["csp"]["connectDomains"][0].get!string == "https://api.example.com");
	assert(j["permissions"]["camera"].type == Json.Type.object);
	assert(j["domain"].get!string == "a904.example-content.com");
	assert(j["prefersBorder"].get!bool == true);
}

unittest  // UiResourceMeta omits empty csp/permissions and unset domain/border
{
	UiResourceMeta meta;
	auto j = meta.toJson();
	assert("csp" !in j);
	assert("permissions" !in j);
	assert("domain" !in j);
	assert("prefersBorder" !in j);
}

unittest  // UiResourceMeta round-trips through fromJson
{
	UiResourceMeta meta;
	meta.csp.resourceDomains = ["https://cdn.example.com"];
	meta.permissions.microphone = true;
	meta.domain = nullable("x.example.com");
	meta.prefersBorder = nullable(false);
	auto back = UiResourceMeta.fromJson(meta.toJson());
	assert(back.csp.resourceDomains == ["https://cdn.example.com"]);
	assert(back.permissions.microphone);
	assert(back.domain.get == "x.example.com");
	assert(back.prefersBorder.get == false);
}

unittest  // advertiseMcpApps surfaces the extension with its mimeTypes (draft)
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.modern : MetaKey;

	auto s = new McpServer("t", "1");
	advertiseMcpApps(s);

	Json params = Json.emptyObject;
	Json meta = Json.emptyObject;
	meta[MetaKey.protocolVersion] = "2026-07-28";
	meta[MetaKey.clientInfo] = Json(["name": Json("c"), "version": Json("1")]);
	meta[MetaKey.clientCapabilities] = Json.emptyObject;
	params["_meta"] = meta;
	auto caps = s.handle(Message(makeRequest(Json(1), "server/discover",
			params))).get["result"]["capabilities"];

	assert(mcpAppsExtensionKey in caps["extensions"]);
	auto settings = caps["extensions"][mcpAppsExtensionKey];
	assert(settings["mimeTypes"][0].get!string == mcpAppMimeType);
}

unittest  // clientSupportsMcpApps reflects what the client advertised at initialize
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	Json caps = Json.emptyObject;
	Json ext = Json.emptyObject;
	ext[mcpAppsExtensionKey] = Json(["mimeTypes": Json([Json(mcpAppMimeType)])]);
	caps["extensions"] = ext;
	Json params = Json.emptyObject;
	params["protocolVersion"] = "2025-06-18";
	params["capabilities"] = caps;
	s.handle(Message(makeRequest(Json(1), "initialize", params)));

	assert(clientSupportsMcpApps(s));
}

unittest  // clientSupportsMcpApps is false for a client that did not advertise it
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	Json params = Json.emptyObject;
	params["protocolVersion"] = "2025-06-18";
	params["capabilities"] = Json.emptyObject;
	s.handle(Message(makeRequest(Json(1), "initialize", params)));

	assert(!clientSupportsMcpApps(s));
}

unittest  // registerUiResource serves HTML with the app mime type and _meta.ui
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	UiResourceMeta meta;
	meta.csp.connectDomains = ["https://api.example.com"];
	registerUiResource(s, "ui://demo/widget", "widget", "<h1>hi</h1>", meta);

	Json rp = Json.emptyObject;
	rp["uri"] = "ui://demo/widget";
	auto contents = s.handle(Message(makeRequest(Json(1), "resources/read",
			rp))).get["result"]["contents"][0];
	assert(contents["mimeType"].get!string == mcpAppMimeType);
	assert(contents["text"].get!string == "<h1>hi</h1>");
	assert(
			contents["_meta"]["ui"]["csp"]["connectDomains"][0].get!string
			== "https://api.example.com");
}

unittest  // registerUiResource lists the resource with mime type and _meta.ui
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	UiResourceMeta meta;
	meta.prefersBorder = nullable(true);
	registerUiResource(s, "ui://demo/widget", "widget", "<h1>hi</h1>", meta);

	auto res = s.handle(Message(makeRequest(Json(1), "resources/list",
			Json.emptyObject))).get["result"]["resources"][0];
	assert(res["uri"].get!string == "ui://demo/widget");
	assert(res["mimeType"].get!string == mcpAppMimeType);
	assert(res["_meta"]["ui"]["prefersBorder"].get!bool == true);
}

unittest  // registerUiResource with no metadata emits a clean resource (no _meta)
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerUiResource(s, "ui://demo/plain", "plain", "<p>x</p>");

	Json rp = Json.emptyObject;
	rp["uri"] = "ui://demo/plain";
	auto contents = s.handle(Message(makeRequest(Json(1), "resources/read",
			rp))).get["result"]["contents"][0];
	assert(contents["mimeType"].get!string == mcpAppMimeType);
	assert("_meta" !in contents);
}

unittest  // registerUiResource rejects a uri that is not in the ui:// scheme
{
	import std.exception : assertThrown;

	auto s = new McpServer("t", "1");
	assertThrown!Exception(registerUiResource(s, "https://demo/widget", "w", "<x/>"));
}

unittest  // setUiToolMeta attaches the ui link under a tool's _meta.ui
{
	Tool t;
	t.name = "render";
	UiToolMeta ui = {resourceUri: "ui://demo/widget", visibility: ["model"]};
	setUiToolMeta(t, ui);
	auto j = t.toJson();
	assert(j["_meta"]["ui"]["resourceUri"].get!string == "ui://demo/widget");
	assert(j["_meta"]["ui"]["visibility"][0].get!string == "model");
}

unittest  // setUiToolMeta preserves other _meta keys already on the tool
{
	Tool t;
	t.name = "render";
	t.meta = Json(["category": Json("demo")]);
	setUiToolMeta(t, UiToolMeta("ui://demo/widget"));
	auto j = t.toJson();
	assert(j["_meta"]["category"].get!string == "demo");
	assert(j["_meta"]["ui"]["resourceUri"].get!string == "ui://demo/widget");
}

version (unittest) private final class UiToolApi
{
	import mcp.api.attributes : tool, ui;

	@tool("render", "Render a widget")
	@ui("ui://demo/widget", "model", "app")
	string render(string spec) @safe
	{
		return spec;
	}

	@tool("plain", "A tool with no UI link")
	string plain() @safe
	{
		return "x";
	}
}

unittest  // @ui UDA attaches _meta.ui to a reflected @tool
{
	import mcp.api.reflection : registerHandlers;
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new UiToolApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json renderTool, plainTool;
	foreach (i; 0 .. tools.length)
	{
		const n = tools[i]["name"].get!string;
		if (n == "render")
			renderTool = tools[i];
		else if (n == "plain")
			plainTool = tools[i];
	}
	assert(renderTool["_meta"]["ui"]["resourceUri"].get!string == "ui://demo/widget");
	assert(renderTool["_meta"]["ui"]["visibility"][0].get!string == "model");
	assert(renderTool["_meta"]["ui"]["visibility"][1].get!string == "app");
	// A tool without @ui carries no _meta.
	assert("_meta" !in plainTool);
}
