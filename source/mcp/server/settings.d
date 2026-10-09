/// Bundled static configuration for an MCP server.
///
/// `ServerSettings` gathers the server identity, the statefulness mode, and the
/// per-transport options into one value, so server construction and the `run*`
/// entry points stay stable as options accumulate instead of growing a positional
/// argument per knob. Build the server from the settings with `newServer`, then
/// serve it with the `ServerSettings` overloads of `runStreamableHttp` / `runStdio`
/// from `mcp.transport` (which read the nested `http` / `stdio` options).
module mcp.server.settings;

import std.typecons : Nullable;

import mcp.protocol.capabilities : Implementation;
import mcp.server.request_state : RequestStateSecurity;
import mcp.server.server : McpServer, ServerMode;
import mcp.transport.streamable_http : StreamableHttpOptions;
import mcp.transport.stdio : StdioOptions;

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

	/// Advertise the `logging` capability so handlers' `ctx.log` emits
	/// `notifications/message` (calls `enableLogging`). Off by default. Valid in
	/// either statefulness mode, but only a stateful server accepts
	/// `logging/setLevel`: a stateless server has no session to hold the level,
	/// so it answers that RPC with -32601 and logs at the default `info` minimum
	/// (or the modern request's `_meta` log level).
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

	/// Validate each tool call's `arguments` against the tool's `inputSchema`
	/// before its handler runs. On by default, since the spec says servers MUST
	/// validate tool inputs; `false` calls `disableInputSchemaValidation`.
	bool inputSchemaValidation = true;

	/// Reject a stateful session's requests (other than `ping`) that arrive before
	/// its `notifications/initialized` with -32600 (calls `requireInitialized`).
	/// Off by default: the lifecycle rule is a SHOULD. Setting it on a
	/// `stateless` server makes `newServer()` throw.
	bool requireInitialized;

	/// Send an unexpected handler exception's message to the client instead of a
	/// generic "Internal error" (calls `exposeInternalErrors`). Off by default,
	/// since such messages can leak internals; useful in development.
	bool exposeInternalErrors;

	/// The most items one page of a paginated list method returns (calls
	/// `setPageSize`). `0` (the default) returns every item in a single page.
	size_t pageSize;

	/// When set, protect the MRTR `requestState` with the secure codec (calls
	/// `secureRequestState`). Null (the default) passes it through as plaintext.
	/// Stateless mode only: `newServer` throws when it is set on a `stateful` mode.
	Nullable!RequestStateSecurity requestStateSecurity;

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
	/// before serving. Throws when `resourceSubscriptions` or `requireInitialized`
	/// is set on a `stateless` mode, or `requestStateSecurity` on a `stateful` one.
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
		if (!inputSchemaValidation)
			server.disableInputSchemaValidation();
		if (requireInitialized)
			server.requireInitialized();
		if (exposeInternalErrors)
			server.exposeInternalErrors();
		if (pageSize > 0)
			server.setPageSize(pageSize);
		if (!requestStateSecurity.isNull)
			server.secureRequestState(requestStateSecurity.get);
		if (apps)
			server.enableApps();
		// Last: a stateless-mode resourceSubscriptions opt-in throws here, exactly
		// as a direct enableResourceSubscriptions() call would.
		if (resourceSubscriptions)
			server.enableResourceSubscriptions();
		return server;
	}
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
	// The nested transport options carry through.
	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	s.http.port = 9100;
	s.stdio.maxLineBytes = 4096;
	assert(s.http.port == 9100);
	assert(s.stdio.maxLineBytes == 4096);
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
	// loud error enableResourceSubscriptions() raises directly.
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
	// requestStateSecurity on a STATEFUL server makes newServer() throw, exactly
	// as a direct secureRequestState() call would.
	import std.exception : assertThrown;
	import std.typecons : nullable;
	import mcp.server.request_state : RequestStateSecurity;

	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	s.mode = ServerMode.stateful;
	RequestStateSecurity sec;
	sec.key = new ubyte[32];
	s.requestStateSecurity = nullable(sec);
	assertThrown(s.newServer());
}

@safe unittest
{
	// apps surfaces the MCP Apps extension capability.
	import mcp.api.apps : appsExtensionKey;
	import vibe.data.json : Json;

	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	s.apps = true;
	auto caps = s.newServer().capabilities();
	assert(caps.extensions.type == Json.Type.object);
	assert((appsExtensionKey in caps.extensions) !is null);
}

@safe unittest
{
	// outputSchemaValidation enforces a tool's declared outputSchema: a handler that
	// omits structuredContent for an outputSchema'd tool surfaces an internal error.
	import mcp.api.binding : jsonSchemaOf, SchemaUse;
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
		name: "add", description: nullable("Add"), outputSchema: jsonSchemaOf!(Out,
				SchemaUse.output)
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
	// inputSchemaValidation defaults to on, so a call with arguments missing a
	// required field is rejected (isError content).
	import mcp.api.binding : jsonSchemaOf;
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
	import mcp.api.binding : jsonSchemaOf;
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
	s.inputSchemaValidation = false;
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

@safe unittest
{
	// inputSchemaValidation is a plain bool, on by default.
	ServerSettings s;
	assert(s.inputSchemaValidation);
}

@safe unittest
{
	// requireInitialized gates a stateful request sent before notifications/initialized.
	import vibe.data.json : Json;

	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	s.mode = ServerMode.stateful;
	s.requireInitialized = true;
	auto server = s.newServer();
	Json init = Json.emptyObject;
	init["protocolVersion"] = "2025-11-25";
	init["capabilities"] = Json.emptyObject;
	init["clientInfo"] = Json(["name": Json("c"), "version": Json("1")]);
	server.handle(Message(makeRequest(Json(1), "initialize", init)));
	auto early = server.handle(Message(makeRequest(Json(2), "tools/list", Json.emptyObject))).get;
	assert(early["error"]["code"].get!int == -32600);
}

@safe unittest
{
	// requireInitialized on a STATELESS server makes newServer() throw.
	import std.exception : assertThrown;

	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	s.requireInitialized = true;
	assertThrown(s.newServer());
}

@safe unittest
{
	// pageSize paginates the list methods.
	import mcp.protocol.types : Tool, CallToolResult;
	import vibe.data.json : Json;

	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	s.pageSize = 1;
	auto server = s.newServer();
	foreach (name; ["a", "b"])
	{
		Tool t = {name: name};
		server.registerTool(t, (Json) @safe => CallToolResult.init);
	}
	auto list = server.handle(Message(makeRequest(Json(1), "tools/list", Json.emptyObject))).get;
	assert(list["result"]["tools"].length == 1);
	assert("nextCursor" in list["result"]);
}

@safe unittest
{
	// requestStateSecurity installs the secure requestState codec.
	import std.algorithm.searching : startsWith;
	import std.typecons : nullable;
	import mcp.protocol.mrtr : InputRequest, MetaKey;
	import mcp.protocol.types : Tool;
	import mcp.server.context : RequestContext;
	import mcp.server.request_state : RequestStateSecurity;
	import mcp.server.responses : ToolResponse;
	import vibe.data.json : Json;

	ServerSettings s;
	s.serverInfo = Implementation("settings-srv", "1.0");
	RequestStateSecurity sec;
	sec.key = new ubyte[32];
	s.requestStateSecurity = nullable(sec);
	auto server = s.newServer();
	Tool t = {name: "ask"};
	server.registerTool(t, (Json, RequestContext) @safe => ToolResponse.inputRequired(
			[InputRequest.elicitation("q", "Why?")], "plain"));

	Json meta = Json.emptyObject;
	meta[MetaKey.protocolVersion] = "2026-07-28";
	meta[MetaKey.clientCapabilities] = Json(["elicitation": Json.emptyObject]);
	Json params = Json.emptyObject;
	params["name"] = "ask";
	params["arguments"] = Json.emptyObject;
	params["_meta"] = meta;
	auto resp = server.handle(callReq(1, params)).get;
	const state = resp["result"]["requestState"].get!string;
	assert(state != "plain" && state.startsWith("v1"), state);
}
