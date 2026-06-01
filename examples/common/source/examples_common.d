/// Shared example-support helpers for the mcp.d example servers and clients
/// (#505). The example clients are self-verifying e2e harnesses: they make MCP
/// calls and assert on the results, exiting non-zero on any mismatch so CI can
/// gate on them. These helpers factor out the four things every example
/// server/client pair repeats:
///
///   - `check` / `checkEq` — assertion primitives that print a `FAIL:` line to
///     stderr and throw so the process exits non-zero.
///   - `runClient` — drives the vibe event loop uniformly so the SAME scenario
///     body works over a synchronous stdio (`McpClient.spawn`) transport AND an
///     HTTP transport.
///   - `connectFromArgs` — picks the client transport from argv
///     (`--http <url>` / `--url <url>` -> HTTP, otherwise spawn a sibling server
///     binary).
///   - `runServerFromArgs` — picks the server transport from argv
///     (`--http` -> Streamable HTTP on `--port`/`--host`, otherwise stdio).
module examples_common;

import mcp.client.client : McpClient;
import mcp.server.server : McpServer;

/// Write `"FAIL: " ~ msg` to stderr. `std.stdio.stderr` access is `@system`
/// (global state), so this `@trusted` shim lets the assertion helpers stay
/// `@safe`.
private void logFail(string msg) @trusted nothrow
{
	import std.stdio : stderr;

	try
		stderr.writeln("FAIL: ", msg);
	catch (Exception)
	{
	}
}

/// Assert that `cond` holds. On failure write `"FAIL: " ~ msg` to stderr and
/// throw an `Exception`, so a self-verifying example client exits non-zero.
/// `msg` is `lazy` so the (often concatenated) message is only built on failure.
void check(bool cond, lazy string msg) @safe
{
	if (!cond)
	{
		const m = msg;
		logFail(m);
		throw new Exception(m);
	}
}

/// Assert that `actual == expected`, attributing the failure to `label`. The
/// thrown/printed message includes both values:
/// `label ~ " (got <actual> expected <expected>)"`.
void checkEq(T)(T actual, T expected, lazy string label) @safe
{
	import std.conv : to;

	check(actual == expected,
			label ~ " (got " ~ to!string(actual) ~ " expected " ~ to!string(expected) ~ ")");
}

/// Run a self-verifying client `scenario` to completion and return its int
/// return code (0 = pass, non-zero = fail). The scenario body is executed
/// inside a vibe `runTask` and the event loop is driven uniformly, which is what
/// lets the IDENTICAL scenario work over BOTH a synchronous stdio
/// (`McpClient.spawn` / `spawnSibling`) transport and an HTTP transport: the
/// stdio client's blocking request/response still completes inside the loop, and
/// the HTTP client's background streams get a loop to run on. Any `Throwable`
/// escaping the scenario is reported as a `FAIL:` line and mapped to rc 1.
int runClient(scope int delegate() @safe scenario) @trusted
{
	import vibe.core.core : runTask, runEventLoop, exitEventLoop;

	int rc;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
			rc = scenario();
		catch (Throwable t)
		{
			logFail(t.msg);
			rc = 1;
		}
	});
	runEventLoop();
	return rc;
}

/// Build the example client's transport from command-line `args`. If a
/// `--http <url>` (alias `--url <url>`) option is supplied, connect over
/// Streamable HTTP via `McpClient.http(url)`; otherwise spawn the sibling server
/// binary named `siblingServerName` (resolved next to this executable) over
/// stdio via `McpClient.spawnSibling`. The returned client is NOT yet
/// initialized — call `initialize()` (or `ping()`).
McpClient connectFromArgs(string[] args, string siblingServerName) @safe
{
	import std.getopt : getopt;

	string httpUrl;
	// `getopt` takes the address of the stack locals, which the compiler infers
	// `@system`; the wired-up parse is otherwise pure argv handling, so confine
	// it to a `@trusted` shim to keep this function `@safe`.
	(() @trusted {
		getopt(args, "http", "Connect to a running Streamable HTTP server at <url>.",
			&httpUrl, "url", "Alias for --http: Streamable HTTP server <url>.", &httpUrl);
	})();

	if (httpUrl.length)
		return McpClient.http(httpUrl);
	return McpClient.spawnSibling(siblingServerName);
}

/// Run the example `server` with the transport selected by command-line `args`.
/// If `--http` (a bool flag) is present, serve Streamable HTTP via
/// `runStreamableHttp(server, port, host)` using `--port` (default
/// `defaultPort`) and `--host` (default `defaultHost`); otherwise serve stdio
/// via `runStdio(server)`. Blocks until the chosen transport exits.
void runServerFromArgs(McpServer server, string[] args, ushort defaultPort,
		string defaultHost = "127.0.0.1") @safe
{
	import std.getopt : getopt;
	import mcp.transport.stdio : runStdio;
	import mcp.transport.streamable_http : runStreamableHttp;

	bool http;
	ushort port = defaultPort;
	string host = defaultHost;
	// See `connectFromArgs`: `getopt`'s `&local` arguments force `@system`, so
	// the parse lives in a `@trusted` shim.
	(() @trusted {
		getopt(args, "http", "Serve over Streamable HTTP instead of stdio.", &http, "port",
			"Streamable HTTP listen port.", &port, "host", "Streamable HTTP bind host.", &host);
	})();

	if (http)
		runStreamableHttp(server, port, host);
	else
		runStdio(server);
}
