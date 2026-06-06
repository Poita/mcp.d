/// MCP Apps example server — dual-transport (stdio + Streamable HTTP).
///
/// Demonstrates the server side of the MCP Apps extension (interactive UI
/// rendered inline by a host):
///   - `@tool` + `@ui(...)` to link a tool to a `ui://` resource via the tool's
///     `_meta.ui` (resourceUri + visibility);
///   - `registerUiResource` to publish the linked `ui://` HTML resource with the
///     `text/html;profile=mcp-app` MIME type and a `_meta.ui` carrying CSP /
///     border hints;
///   - `advertiseMcpApps` to declare the extension capability (surfaced to draft
///     clients via the `extensions` negotiation map).
///
/// MCP Apps is, on the server side, metadata plus a resource convention: the
/// host fetches the `ui://` resource and renders it sandboxed, and the app talks
/// back to the host over a postMessage bridge that never reaches this server.
/// The SAME binary speaks either transport, selected by the shared scaffold.
///
/// The matching `client.d` is a self-verifying e2e asserting this surface over
/// BOTH transports.
module apps_server;

import std.typecons : nullable;

import examples_common : runServerFromArgs;

import mcp.api.attributes;
import mcp.api.reflection : registerModule;
import mcp.api.apps;
import mcp.server.server : McpServer;

/// The example's default HTTP port (kept distinct from the other examples).
enum ushort DefaultPort = 8538;

/// The tool's structured result — its fields become the tool's structured
/// output, which a host can stream into the rendered app.
struct Weather
{
	string city;
	int tempC;
	string summary;
}

/// A tool linked to an MCP Apps UI resource. `@ui` records the `ui://` resource
/// and the visibility roles in the tool's `_meta.ui`; a host preloads that
/// resource and renders it when the tool is called.
@tool("get_weather", "Get the weather and render it as an interactive dashboard")
@readOnly @ui("ui://weather/dashboard", "model", "app")
Weather getWeather(string city) @safe
{
	// A real server would query a weather API; this returns a fixed sample.
	return Weather(city, 18, "Partly cloudy");
}

/// The HTML app a host renders for `get_weather`. A real app would read the tool
/// result over the host's postMessage bridge and draw a live dashboard; this is
/// a minimal static page the host fetches from the `ui://` resource.
enum dashboardHtml = `<!doctype html>
<html>
  <body>
    <h1>Weather</h1>
    <div id="app">Loading the weather dashboard…</div>
  </body>
</html>`;

void main(string[] args) @safe
{
	auto server = new McpServer("apps-example", "1.0.0");
	// Register the @tool/@ui free function(s) in this module.
	registerModule!(apps_server)(server);

	// Declare MCP Apps support (visible to draft clients via the extensions map).
	advertiseMcpApps(server);

	// Publish the ui:// resource the tool links to, with CSP + border hints.
	UiResourceMeta ui;
	ui.csp.connectDomains = ["https://api.open-meteo.com"];
	ui.prefersBorder = nullable(true);
	registerUiResource(server, "ui://weather/dashboard", "weather_dashboard",
			dashboardHtml, ui, "Interactive weather dashboard");

	// stdio by default, or Streamable HTTP under `--http` on `--port`/`--host`.
	runServerFromArgs(server, args, DefaultPort);
}
