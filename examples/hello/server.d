/// Minimal standalone MCP server: one `@tool`, served over stdio by default or
/// Streamable HTTP with `--http [--port N]`. It depends only on `mcp-d`, so it
/// can be copied out of the repository as the starting point for a new server.
module hello_server;

import std.getopt : getopt;

import mcp;
import mcp.transport;

@tool("greet", "Greet someone by name")
string greet(string name) @safe
{
	return "Hello, " ~ name ~ "!";
}

void main(string[] args)
{
	bool http;
	ushort port = 8540;
	getopt(args, "http", "Serve Streamable HTTP instead of stdio.", &http,
			"port", "Streamable HTTP listen port.", &port);

	auto server = new McpServer("hello", "1.0.0");
	registerModule!hello_server(server);

	if (http)
	{
		StreamableHttpOptions opts;
		opts.port = port;
		runStreamableHttp(server, opts);
	}
	else
		runStdio(server);
}
