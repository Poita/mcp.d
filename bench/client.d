/// Throughput benchmark client for the Streamable HTTP transport.
///
/// Drives one `bench-server` over Streamable HTTP with simple synchronous
/// `tools/call` requests and reports throughput (calls/sec) and mean latency.
///
/// Each modern POST uses a fresh TCP connection (`Connection: close`), so this
/// measures the full per-call cost: connect + request + JSON-RPC + response.
///
/// Options:
///   --url <url>        server endpoint (default http://127.0.0.1:8550/mcp)
///   --calls <n>        total timed tool calls (default 20000)
///   --concurrency <c>  number of parallel client connections (default 1)
///   --warmup <n>       warmup calls per client before timing (default 200)
///
/// With `--concurrency 1` the reported mean latency is the true synchronous
/// round-trip; higher concurrency runs C independent clients in parallel to find
/// the saturating throughput.
module bench_client;

import core.time : MonoTime, Duration;

import std.getopt : getopt;
import std.stdio : writefln, writeln;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, Task;
import vibe.data.json : Json;

import mcp.client.client : McpClient;

void main(string[] args) @safe
{
	string url = "http://127.0.0.1:8550/mcp";
	long calls = 20_000;
	int concurrency = 1;
	long warmup = 200;
	(() @trusted {
		getopt(args, "url|u", "Server endpoint URL.", &url, "calls|n",
			"Total timed tool calls.", &calls, "concurrency|c",
			"Parallel client connections.",
			&concurrency, "warmup|w", "Warmup calls per client.", &warmup);
	})();

	if (concurrency < 1)
		concurrency = 1;

	runBench(url, calls, concurrency, warmup);
}

/// One synchronous tool call against `client`. The handler adds two integers;
/// the result is read back to ensure the full round-trip completed.
private void oneCall(McpClient client, long i) @safe
{
	Json a = Json.emptyObject;
	a["a"] = i;
	a["b"] = 1;
	auto r = client.callTool("add", a);
	// Touch the result so the round-trip is not optimized away.
	if (r.isError)
		throw new Exception("tool call returned an error");
}

private void runBench(string url, long calls, int concurrency, long warmup) @trusted
{
	int rc;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
		{
			// One client (one logical connection identity) per concurrent worker.
			auto clients = new McpClient[concurrency];
			foreach (k; 0 .. concurrency)
			{
				clients[k] = McpClient.http(url);
				clients[k].initialize();
			}
			scope (exit)
				foreach (c; clients)
					c.close();

			// Warmup: prime each client/connection path before timing.
			foreach (c; clients)
				foreach (j; 0 .. warmup)
					oneCall(c, j);

			// Split the total call budget across the workers.
			const perWorker = calls / concurrency;
			const total = perWorker * concurrency;

			const start = MonoTime.currTime;
			auto tasks = new Task[concurrency];
			foreach (k; 0 .. concurrency)
			{
				auto c = clients[k];
				tasks[k] = runTask(() nothrow{
					try
					{
						foreach (j; 0 .. perWorker)
							oneCall(c, j);
					}
					catch (Exception e)
						assert(false, e.msg);
				});
			}
			foreach (t; tasks)
				t.join();
			const elapsed = MonoTime.currTime - start;

			report(url, total, concurrency, elapsed);
		}
		catch (Exception e)
		{
			import std.stdio : stderr;

			try
				stderr.writeln("FAIL: ", e.msg);
			catch (Exception)
			{
			}
			rc = 1;
		}
	});
	runEventLoop();

	import core.stdc.stdlib : exit;

	if (rc != 0)
		exit(rc);
}

private void report(string url, long total, int concurrency, Duration elapsed) @safe
{
	const secs = elapsed.total!"usecs" / 1_000_000.0;
	const throughput = total / secs;
	// Mean wall-clock per call across all workers; equals true round-trip latency
	// only at concurrency 1.
	const meanLatencyUs = (elapsed.total!"usecs" * cast(double) concurrency) / total;

	writeln("=== mcp.d Streamable HTTP throughput ===");
	writefln("endpoint        : %s", url);
	writefln("concurrency     : %d", concurrency);
	writefln("calls (timed)   : %d", total);
	writefln("elapsed         : %.3f s", secs);
	writefln("throughput      : %.0f calls/sec", throughput);
	writefln("mean latency    : %.3f ms/call (per connection)", meanLatencyUs / 1000.0);
}
