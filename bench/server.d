/// Throughput benchmark server — a minimal Streamable HTTP MCP server with one
/// trivial tool. The tool body does essentially no work so the measured
/// throughput reflects the transport + protocol round-trip cost, not handler
/// compute.
///
/// Run: `bench-server --port 8550 --host 127.0.0.1`
module bench_server;

import std.getopt : getopt;

import mcp.api.attributes : tool;
import mcp.api.reflection : registerModule;
import mcp.server.server : McpServer;
import mcp.transport.streamable_http : runStreamableHttp;

/// The smallest possible tool: add two integers. Keeps the handler cost near
/// zero so the benchmark isolates client+server transport throughput.
@tool("add", "Add two integers")
long add(long a, long b) @safe
{
	return a + b;
}

void main(string[] args) @safe
{
	ushort port = 8550;
	string host = "127.0.0.1";
	(() @trusted {
		getopt(args, "port|p", "Listen port.", &port, "host|h", "Bind host.", &host);
	})();

	auto server = new McpServer("bench-server", "1.0.0");
	registerModule!(bench_server)(server);
	runStreamableHttp(server, port, host);
}
