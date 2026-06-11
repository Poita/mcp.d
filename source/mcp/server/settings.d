/// Bundled static configuration for an MCP server.
///
/// `ServerSettings` gathers the server identity, the statefulness mode, and the
/// per-transport options into one value, so server construction and the `run*`
/// entry points stay stable as options accumulate instead of growing a positional
/// argument per knob. Build the server from the settings with `newServer`, then
/// serve it with the `ServerSettings` overloads of `runStreamableHttp` / `runStdio`
/// (which read the nested `http` / `stdio` options).
module mcp.server.settings;

import std.typecons : Nullable;

import mcp.protocol.capabilities : Implementation;
import mcp.server.server : McpServer, ServerMode;
import mcp.transport.streamable_http : StreamableHttpOptions, runStreamableHttp;
import mcp.transport.stdio : StdioOptions, runStdio;

/// Static configuration for an MCP server, and the primary documented path for
/// declaring it. `newServer` constructs an `McpServer` from the identity + mode
/// and then applies the capability/validation flags by calling the corresponding
/// `enable*`/`disable*` methods. The per-flag `enable*` methods remain on
/// `McpServer` for dynamic/runtime configuration (toggling a capability after
/// construction); for the fixed configuration a server is born with, set it here.
///
/// The nested `http` / `stdio` carry the transport options consumed by the
/// matching `run*` overloads below.
///
/// Note: `enableTasks` is deliberately NOT a settings flag — it returns a
/// `TaskRuntime` and takes a `TaskStore`, so it stays a method-only surface called
/// after `newServer()` (the runtime it returns is needed to drive task execution).
struct ServerSettings
{
	/// Server identity (name + version) advertised during initialization.
	Implementation serverInfo;

	/// Optional human-readable usage instructions surfaced in `initialize`.
	Nullable!string instructions;

	/// Statefulness model. Stateless (the default) keeps no per-connection state
	/// across HTTP calls; stateful opts into `Mcp-Session-Id` session management.
	ServerMode mode = ServerMode.stateless;

	/// Advertise the tools `listChanged` capability (calls `enableToolsListChanged`).
	/// Off by default, matching the method's default.
	bool toolsListChanged;

	/// Advertise the resources `listChanged` capability (calls
	/// `enableResourcesListChanged`). Off by default.
	bool resourcesListChanged;

	/// Advertise the prompts `listChanged` capability (calls
	/// `enablePromptsListChanged`). Off by default.
	bool promptsListChanged;

	/// Advertise the `logging` capability and accept `logging/setLevel` (calls
	/// `enableLogging`). Off by default. Valid in either statefulness mode (the
	/// draft per-request `_meta` logging path uses it on a stateless server).
	bool logging;

	/// Advertise the resources `subscribe` capability (calls
	/// `enableResourceSubscriptions`). Off by default. Setting this `true` on a
	/// `stateless` server makes `newServer()` throw the same loud error
	/// `enableResourceSubscriptions()` raises directly — construct with
	/// `mode = ServerMode.stateful` to use subscriptions.
	bool resourceSubscriptions;

	/// Enforce each tool's declared `outputSchema` before a result is sent (calls
	/// `enableOutputSchemaValidation`). Off by default, matching the method.
	bool outputSchemaValidation;

	/// Tri-state control of input-schema validation, which is **on by default** on
	/// the server. `null` (the default) leaves that default untouched; `true` calls
	/// `enableInputSchemaValidation`; `false` calls `disableInputSchemaValidation`.
	/// The tri-state lets the settings express "leave default" as well as an
	/// explicit on/off, since the underlying default is enabled.
	Nullable!bool inputSchemaValidation;

	/// Advertise the MCP Apps extension capability (calls `enableApps` from
	/// `mcp.api.apps` with its default mime types). Off by default.
	bool apps;

	/// Streamable HTTP transport options, consumed by
	/// `runStreamableHttp(server, settings)`.
	StreamableHttpOptions http;

	/// stdio transport options, consumed by `runStdio(server, settings)`.
	StdioOptions stdio;

	/// Construct a fresh `McpServer` from this settings' identity and mode, then
	/// apply the capability/validation flags via the matching `enable*`/`disable*`
	/// methods. Tools, resources, and prompts are registered on the returned server
	/// before serving. Throws when `resourceSubscriptions` is set on a `stateless`
	/// mode (the loud error from `enableResourceSubscriptions()`).
	McpServer newServer() @safe
	{
		import mcp.api.apps : enableApps;

		McpServer server;
		final switch (mode)
		{
		case ServerMode.stateless:
			server = McpServer.stateless(serverInfo, instructions);
			break;
		case ServerMode.stateful:
			server = McpServer.stateful(serverInfo, instructions);
			break;
		}

		if (toolsListChanged)
			server.enableToolsListChanged();
		if (resourcesListChanged)
			server.enableResourcesListChanged();
		if (promptsListChanged)
			server.enablePromptsListChanged();
		if (logging)
			server.enableLogging();
		if (outputSchemaValidation)
			server.enableOutputSchemaValidation();
		if (!inputSchemaValidation.isNull)
		{
			if (inputSchemaValidation.get)
				server.enableInputSchemaValidation();
			else
				server.disableInputSchemaValidation();
		}
		if (apps)
			enableApps(server);
		// Last: a stateless-mode resourceSubscriptions opt-in throws here, exactly
		// as a direct enableResourceSubscriptions() call would.
		if (resourceSubscriptions)
			server.enableResourceSubscriptions();
		return server;
	}
}

/// Serve `server` over Streamable HTTP using `settings.http`. Blocks until exit.
void runStreamableHttp(McpServer server, ServerSettings settings) @safe
{
	runStreamableHttp(server, settings.http);
}

/// Serve `server` over stdio using `settings.stdio`. Blocks until exit.
void runStdio(McpServer server, ServerSettings settings)
{
	runStdio(server, settings.stdio);
}

@safe unittest
{
	// newServer honors the stateless default.
	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	auto server = s.newServer();
	assert(server.mode == ServerMode.stateless);
}

@safe unittest
{
	// newServer honors an explicit stateful mode.
	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	s.mode = ServerMode.stateful;
	auto server = s.newServer();
	assert(server.mode == ServerMode.stateful);
}

@safe unittest
{
	// The nested transport options carry through and the run overloads are callable.
	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	s.http.port = 9100;
	s.stdio.maxLineBytes = 4096;
	assert(s.http.port == 9100);
	assert(s.stdio.maxLineBytes == 4096);
	static assert(__traits(compiles, (McpServer srv, ServerSettings cfg) {
			runStreamableHttp(srv, cfg);
			runStdio(srv, cfg);
		}));
}

version (unittest)
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import vibe.data.json : Json;

	// Local tools/call request builder (server.d's `req` is private to its own
	// unittest block, so settings.d carries its own).
	private Message callReq(long id, Json params) @safe
	{
		return Message(makeRequest(Json(id), "tools/call", params));
	}
}

@safe unittest
{
	// toolsListChanged advertises tools: { listChanged: true }.
	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	s.toolsListChanged = true;
	auto caps = s.newServer().capabilities();
	assert(!caps.tools.isNull);
	assert(caps.tools.get.listChanged);
}

@safe unittest
{
	// resourcesListChanged advertises resources: { listChanged: true }.
	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	s.resourcesListChanged = true;
	auto caps = s.newServer().capabilities();
	assert(!caps.resources.isNull);
	assert(caps.resources.get.listChanged);
}

@safe unittest
{
	// promptsListChanged advertises prompts: { listChanged: true }.
	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	s.promptsListChanged = true;
	auto caps = s.newServer().capabilities();
	assert(!caps.prompts.isNull);
	assert(caps.prompts.get.listChanged);
}

@safe unittest
{
	// logging advertises the logging capability, and is valid in stateless mode.
	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	s.logging = true;
	auto caps = s.newServer().capabilities();
	assert(caps.logging);
}

@safe unittest
{
	// resourceSubscriptions on a STATEFUL server advertises resources: { subscribe }.
	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	s.mode = ServerMode.stateful;
	s.resourceSubscriptions = true;
	auto caps = s.newServer().capabilities();
	assert(!caps.resources.isNull);
	assert(caps.resources.get.subscribe);
}

@safe unittest
{
	// resourceSubscriptions on a STATELESS server makes newServer() throw the same
	// loud error enableResourceSubscriptions() raises directly (PR 2.2 interaction).
	import std.algorithm.searching : canFind;

	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	s.resourceSubscriptions = true; // mode stays stateless (the default)
	bool threw;
	try
		s.newServer();
	catch (Exception e)
	{
		threw = true;
		assert(e.msg.canFind("McpServer.stateful()"),
				"the stateless rejection must name McpServer.stateful()");
	}
	assert(threw, "newServer() must throw for resourceSubscriptions on a stateless server");
}

@safe unittest
{
	// apps surfaces the MCP Apps extension capability.
	import mcp.api.apps : mcpAppsExtensionKey;
	import vibe.data.json : Json;

	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	s.apps = true;
	auto caps = s.newServer().capabilities();
	assert(caps.extensions.type == Json.Type.object);
	assert((mcpAppsExtensionKey in caps.extensions) !is null);
}

@safe unittest
{
	// outputSchemaValidation enforces a tool's declared outputSchema: a handler that
	// omits structuredContent for an outputSchema'd tool surfaces an internal error.
	import mcp.api.schema : jsonSchemaOf;
	import mcp.protocol.types : Tool, CallToolResult, Content;
	import std.typecons : nullable;
	import vibe.data.json : Json;

	struct Out
	{
		int sum;
	}

	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	s.outputSchemaValidation = true;
	auto server = s.newServer();
	Tool t = {
		name: "add", description: nullable("Add"), outputSchema: jsonSchemaOf!Out
	};
	// Handler returns plain text content, NO structuredContent — invalid under the
	// declared outputSchema, so validation must reject it.
	server.registerTool(t, (Json) @safe {
		CallToolResult r;
		r.content = [Content.makeText("no structured content")];
		return r;
	});
	Json params = Json.emptyObject;
	params["name"] = "add";
	params["arguments"] = Json.emptyObject;
	auto resp = server.handle(callReq(1, params)).get;
	assert("error" in resp, "outputSchemaValidation must reject a missing structuredContent");
}

@safe unittest
{
	// inputSchemaValidation defaults to null = leave the server default (ON), so a
	// call with arguments missing a required field is rejected (isError content).
	import mcp.api.schema : jsonSchemaOf;
	import mcp.protocol.types : Tool, CallToolResult, Content;
	import std.typecons : nullable;
	import vibe.data.json : Json;

	struct Args
	{
		int a;
		int b;
	}

	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	// inputSchemaValidation left null -> default (ON).
	auto server = s.newServer();
	Tool add = {
		name: "add", description: nullable("Add"), inputSchema: jsonSchemaOf!Args
	};
	server.registerTool(add, (Json) @safe {
		CallToolResult r;
		r.content = [Content.makeText("ok")];
		return r;
	});
	Json params = Json.emptyObject;
	params["name"] = "add";
	params["arguments"] = Json(["a": Json(1)]); // missing 'b'
	auto resp = server.handle(callReq(1, params)).get;
	assert(resp["result"]["isError"].get!bool,
			"default input-schema validation must flag the missing field");
}

@safe unittest
{
	// inputSchemaValidation = false disables validation: the same call now succeeds.
	import mcp.api.schema : jsonSchemaOf;
	import mcp.protocol.types : Tool, CallToolResult, Content;
	import std.typecons : nullable, Nullable;
	import vibe.data.json : Json;

	struct Args
	{
		int a;
		int b;
	}

	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	s.inputSchemaValidation = Nullable!bool(false);
	auto server = s.newServer();
	Tool add = {
		name: "add", description: nullable("Add"), inputSchema: jsonSchemaOf!Args
	};
	server.registerTool(add, (Json) @safe {
		CallToolResult r;
		r.content = [Content.makeText("ok")];
		return r;
	});
	Json params = Json.emptyObject;
	params["name"] = "add";
	params["arguments"] = Json(["a": Json(1)]); // missing 'b', but validation is off
	auto resp = server.handle(callReq(1, params)).get;
	assert("error" !in resp);
	assert(resp["result"]["content"][0]["text"].get!string == "ok");
}
