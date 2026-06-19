/**
 * Minimal mcp.d server used only as a CI build fixture for deploy/Dockerfile.
 *
 * It is compiled and linked (never run) to prove that the documented system
 * dependencies and toolchain actually produce a working mcp.d server binary —
 * including the Streamable HTTP transport a real deployment uses.
 */
module app;

import std.conv : to;
import std.process : environment;

import mcp;
import mcp.transport.streamable_http : runStreamableHttp, StreamableHttpOptions;

@tool("ping", "Health check")
string ping() @safe
{
	return "ok";
}

void main(string[] args) @safe
{
	auto server = new McpServer("ci-smoke", "0.0.0");
	registerModule!app(server);

	StreamableHttpOptions opts;
	opts.port = environment.get("PORT", "8080").to!ushort;
	opts.bindAddresses = ["0.0.0.0"];
	runStreamableHttp(server, opts);
}
