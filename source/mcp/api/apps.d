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
