/// MCP Apps example client + self-verifying e2e test — dual-transport.
///
/// Drives the `apps-example` server over EITHER transport (stdio by default, or
/// `--http <url>`) with the SAME assertions, verifying the MCP Apps server
/// surface:
///   - `tools/list`: `get_weather` carries `_meta.ui` linking it to the
///     `ui://weather/dashboard` resource with the declared visibility roles;
///   - `resources/list` + `resources/read`: the `ui://` resource is served with
///     the `text/html;profile=mcp-app` MIME type, its HTML body, and a `_meta.ui`
///     carrying the CSP / border hints;
///   - calling `get_weather` returns the expected structured content.
///
/// Prints "OK: ..." and exits 0 on success; any mismatch throws via the
/// scaffold's `check`/`checkEq`, mapped to a non-zero exit.
module apps_client;

import vibe.data.json : Json;

import examples_common : check, checkEq, connectFromArgs, runClient;

import mcp.client.client : McpClient, byName;
import mcp.protocol.types : Tool;
import mcp.api.apps : mcpAppMimeType;

/// `get_weather` arguments as a JSON object (`{ "city": city }`). The client
/// request surface is untyped — see the repo-root `DESIGN.md`.
private Json weatherArgs(string city) @safe
{
	Json j = Json.emptyObject;
	j["city"] = city;
	return j;
}

/// Typed view of `get_weather`'s structured output.
struct WeatherOutput
{
	string city;
	int tempC;
	string summary;
}

int main(string[] args) @safe
{
	return runClient(() @safe {
		auto client = connectFromArgs(args, "apps-server");
		scope (exit)
			client.close();

		auto init = client.initialize();
		checkEq(init.serverInfo.name, "apps-example", "serverInfo.name");

		// --- tools/list: the tool carries the MCP Apps _meta.ui link ---------
		auto tools = client.listTools().tools;
		auto wt = tools.byName("get_weather");
		check(!wt.isNull, "tools/list missing get_weather");
		auto meta = wt.get.meta;
		check(meta.type == Json.Type.object && ("ui" in meta) !is null,
			"get_weather should carry _meta.ui");
		checkEq(meta["ui"]["resourceUri"].get!string,
			"ui://weather/dashboard", "_meta.ui.resourceUri");
		auto vis = meta["ui"]["visibility"];
		check(vis.type == Json.Type.array && vis.length == 2,
			"_meta.ui.visibility should list two roles");
		checkEq(vis[0].get!string, "model", "_meta.ui.visibility[0]");
		checkEq(vis[1].get!string, "app", "_meta.ui.visibility[1]");

		// --- resources/list: the ui:// resource and its app MIME type --------
		auto resources = client.listResources().resources;
		bool foundUi;
		foreach (r; resources)
		{
			if (r.uri != "ui://weather/dashboard")
				continue;
			foundUi = true;
			check(!r.mimeType.isNull && r.mimeType.get == mcpAppMimeType,
				"ui:// resource should use the app MIME type");
			check(r.meta.type == Json.Type.object && ("ui" in r.meta) !is null,
				"ui:// resource should carry _meta.ui");
			check(r.meta["ui"]["prefersBorder"].get!bool, "_meta.ui.prefersBorder");
		}
		check(foundUi, "resources/list missing ui://weather/dashboard");

		// --- resources/read: the HTML body + _meta.ui ------------------------
		import std.algorithm.searching : canFind;

		auto read = client.readResource("ui://weather/dashboard");
		check(read.contents.length == 1, "ui:// read should return one content block");
		auto c = read.contents[0];
		checkEq(c.mimeType, mcpAppMimeType, "ui:// read MIME type");
		check(c.text.canFind("<h1>Weather</h1>"), "ui:// read should return the HTML body");
		check(c.meta.type == Json.Type.object
			&& c.meta["ui"]["csp"]["connectDomains"][0].get!string == "https://api.open-meteo.com",
			"ui:// read should carry the _meta.ui CSP hint");

		// --- call get_weather: structured result -----------------------------
		auto r = client.callTool("get_weather", weatherArgs("Paris"));
		check(!r.isError, "get_weather should not be an error");
		auto out_ = r.structuredContentAs!WeatherOutput;
		checkEq(out_.city, "Paris", "get_weather city");
		checkEq(out_.summary, "Partly cloudy", "get_weather summary");

		import std.stdio : writeln;

		bool http;
		foreach (arg; args)
			if (arg == "--http" || arg == "--url")
				http = true;
		writeln("OK: apps example e2e passed over ", http ? "http" : "stdio",
			" — tool _meta.ui link, ui:// resource (app MIME + _meta.ui csp/border), ",
			"HTML body, and structured tool result all verified.");
		return 0;
	});
}
