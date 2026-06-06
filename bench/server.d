/// Throughput benchmark server — a minimal Streamable HTTP MCP server with one
/// trivial tool. The tool body does essentially no work so the measured
/// throughput reflects the transport + protocol round-trip cost, not handler
/// compute.
///
/// By default the server runs as a single vibe.d event-loop thread (one core).
/// `--threads N` instead starts N independent event-loop threads, each with its
/// OWN `McpServer` + router, all binding the same port with `SO_REUSEPORT` so
/// the kernel load-balances incoming connections across them. This lets the
/// benchmark measure multi-core scaling. Each thread keeps its own server
/// object, so no mutable state is shared across threads.
///
/// Run: `bench-server --port 8550 --host 127.0.0.1 --threads 4`
module bench_server;

import std.getopt : getopt;

import vibe.core.core : runEventLoop, lowerPrivileges;
import vibe.http.router : URLRouter;
import vibe.http.server : HTTPServerSettings, HTTPServerOption, listenHTTP;

import mcp.api.attributes : tool;
import mcp.api.reflection : registerModule;
import mcp.server.server : McpServer;
import mcp.transport.streamable_http : mountMcp, runStreamableHttp;

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
	int threads = 1;
	(() @trusted {
		getopt(args, "port|p", "Listen port.", &port, "host|h", "Bind host.", &host,
			"threads|t", "Event-loop threads sharing the port via SO_REUSEPORT.", &threads);
	})();
	if (threads < 1)
		threads = 1;

	// Single-threaded path: the plain SDK entry point (one event loop, one core).
	if (threads == 1)
	{
		auto server = new McpServer("bench-server", "1.0.0");
		registerModule!(bench_server)(server);
		runStreamableHttp(server, port, host);
		return;
	}

	runMultiThreaded(port, host, threads);
}

/// Start `threads` OS threads, each running its own vibe event loop with its own
/// `McpServer`/router listening on the same `port` via `SO_REUSEPORT`. The main
/// thread also serves (so N threads => N listeners), and blocks on the worker
/// threads. The kernel distributes accepted connections across the listeners.
private void runMultiThreaded(ushort port, string host, int threads) @trusted
{
	import core.thread : Thread;

	void serve()
	{
		auto server = new McpServer("bench-server", "1.0.0");
		registerModule!(bench_server)(server);

		auto router = new URLRouter;
		mountMcp(router, server);

		auto settings = new HTTPServerSettings;
		settings.port = port;
		settings.bindAddresses = [host];
		// SO_REUSEPORT lets every thread bind the same port; the kernel balances
		// connections across the per-thread listeners.
		settings.options |= HTTPServerOption.reusePort;

		auto listener = listenHTTP(settings, router);
		scope (exit)
			listener.stopListening();

		runEventLoop();
	}

	auto workers = new Thread[threads - 1];
	foreach (ref w; workers)
	{
		w = new Thread(&serve);
		w.start();
	}
	lowerPrivileges();
	serve(); // the main thread is the Nth listener
	foreach (w; workers)
		w.join();
}
