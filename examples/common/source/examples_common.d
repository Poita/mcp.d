/// Shared example-support helpers for the mcp.d example servers and clients.
/// The example clients are self-verifying e2e harnesses: they make MCP
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
import mcp.transport.streamable_http : StreamableHttpOptions;

/// Shared structured result of the auth example's `whoami` tool. Defined
/// once here so the server (which infers `whoami`'s output schema +
/// `structuredContent` from the return type) and the client (which decodes the
/// result with `structuredContentAs!WhoamiResult`) share ONE type — any field
/// drift becomes a compile error instead of a silent wire mismatch.
struct WhoamiResult
{
	/// The authenticated principal (the token `sub`).
	string subject;
	/// The scopes granted by the validated token.
	string[] scopes;
}

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

/// Parse the HTTP-only `--port`/`--host` surface from `args`, returning the bind
/// host/port through `port`/`host`. When the caller left `opts.bindAddresses` at
/// the SDK default (`["127.0.0.1"]`) or empty, the parsed `--host` is written
/// into `opts.bindAddresses` so the `--host` flag actually drives the bind; an
/// explicitly customised `bindAddresses` is left untouched. Split out from
/// `runHttpServerFromArgs` so it can be unit tested and so a caller that needs the
/// resolved host/port -- e.g. the auth example deriving its RFC 8707 resource
/// audience from the actual socket -- can reuse the exact parse the bind will use.
/// `opts` is taken by `ref` and updated in place.
void parseHttpServerArgs(string[] args, ushort defaultPort, ref StreamableHttpOptions opts,
		out ushort port, out string host, string defaultHost = "127.0.0.1") @safe
{
	import std.getopt : getopt;

	port = defaultPort;
	host = defaultHost;
	// See `connectFromArgs`: `getopt`'s `&local` arguments force `@system`, so the
	// parse lives in a `@trusted` shim.
	(() @trusted {
		getopt(args, "port|p", "Streamable HTTP listen port.", &port,
			"host|h", "Streamable HTTP bind host.", &host);
	})();

	// Honour `--host` unless the caller pinned a non-default bind set: a default or
	// empty `bindAddresses` is replaced by the parsed host so the flag takes effect.
	if (opts.bindAddresses.length == 0 || opts.bindAddresses == ["127.0.0.1"])
		opts.bindAddresses = [host];
}

/// Run the example `server` over Streamable HTTP ONLY, with the caller-supplied
/// `StreamableHttpOptions` (notably `.auth`). Unlike `runServerFromArgs`, this
/// helper has NO stdio fallback: an OAuth resource server must never silently
/// degrade to an unauthenticated stdio transport, so HTTP is the only mode.
/// Parses just `--port`/`--host` (via `parseHttpServerArgs`), lets the parsed
/// host drive `opts.bindAddresses`, writes the resolved bind host/port back
/// through `port`/`host` (so the caller can derive its RFC 8707 resource audience
/// from the actual socket), then calls `runStreamableHttp(server, port, opts)`.
/// Blocks until the transport exits.
void runHttpServerFromArgs(McpServer server, string[] args, ushort defaultPort,
		ref StreamableHttpOptions opts, out ushort port, out string host,
		string defaultHost = "127.0.0.1") @safe
{
	import mcp.transport.streamable_http : runStreamableHttp;

	parseHttpServerArgs(args, defaultPort, opts, port, host, defaultHost);
	runStreamableHttp(server, port, opts);
}

@safe unittest
{
	// Defaults apply when no flags are present, and the default host is carried
	// into bindAddresses.
	StreamableHttpOptions opts;
	ushort port;
	string host;
	parseHttpServerArgs(["prog"], 8742, opts, port, host);
	assert(port == 8742);
	assert(host == "127.0.0.1");
	assert(opts.bindAddresses == ["127.0.0.1"]);
}

@safe unittest
{
	// --port/--host (and their -p/-h aliases) are parsed and the host drives the
	// bind, replacing the SDK-default bindAddresses.
	StreamableHttpOptions opts;
	ushort port;
	string host;
	parseHttpServerArgs(["prog", "--port", "9001", "--host", "0.0.0.0"], 8742, opts, port, host);
	assert(port == 9001);
	assert(host == "0.0.0.0");
	assert(opts.bindAddresses == ["0.0.0.0"]);
}

@safe unittest
{
	// An explicitly customised bindAddresses (not the SDK default) is preserved.
	StreamableHttpOptions opts;
	opts.bindAddresses = ["10.0.0.5"];
	ushort port;
	string host;
	parseHttpServerArgs(["prog", "--host", "127.0.0.1"], 8742, opts, port, host);
	assert(host == "127.0.0.1");
	assert(opts.bindAddresses == ["10.0.0.5"]);
}
