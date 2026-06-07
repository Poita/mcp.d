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

/// Static configuration for an MCP server. `newServer` constructs an `McpServer`
/// from the identity + mode; the nested `http` / `stdio` carry the transport
/// options consumed by the matching `run*` overloads below.
struct ServerSettings
{
	/// Server identity (name + version) advertised during initialization.
	Implementation serverInfo;

	/// Optional human-readable usage instructions surfaced in `initialize`.
	Nullable!string instructions;

	/// Statefulness model. Stateless (the default) keeps no per-connection state
	/// across HTTP calls; stateful opts into `Mcp-Session-Id` session management.
	ServerMode mode = ServerMode.stateless;

	/// Streamable HTTP transport options, consumed by
	/// `runStreamableHttp(server, settings)`.
	StreamableHttpOptions http;

	/// stdio transport options, consumed by `runStdio(server, settings)`.
	StdioOptions stdio;

	/// Construct a fresh `McpServer` from this settings' identity and mode. Tools,
	/// resources, and prompts are registered on the returned server before serving.
	McpServer newServer() @safe
	{
		final switch (mode)
		{
		case ServerMode.stateless:
			return McpServer.stateless(serverInfo, instructions);
		case ServerMode.stateful:
			return McpServer.stateful(serverInfo, instructions);
		}
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
