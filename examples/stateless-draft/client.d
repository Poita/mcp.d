/**
 * Stateless (draft) protocol — client side AND the example's e2e test.
 * DUAL TRANSPORT: the SAME assertions run over BOTH stdio and HTTP.
 *
 *   dub run -c client                                   # stdio: spawns the server
 *   dub run -c client -- --http http://127.0.0.1:8431/mcp   # HTTP
 *
 * When `--http <url>` is given the client connects with `McpClient.http(url)`;
 * otherwise it spawns the built `stateless-draft-server` binary (no `--http`)
 * and talks newline-delimited JSON-RPC over its stdin/stdout via
 * `McpClient.stdio`. The draft (2026-07-28) stateless model is engaged the same
 * way on either channel — `enableDraft()` + per-request `_meta` — so a single
 * transport-agnostic assertion body verifies both.
 *
 * It ASSERTS the consumer's-eye view:
 *
 *   - `server/discover` advertises the draft version "2026-07-28" and the
 *     server's identity (no `initialize` handshake);
 *   - `connect()` selects the stateless draft as the negotiated version;
 *   - `listTools()` contains the expected tool, and its draft `CacheableResult`
 *     freshness hint (`cache.ttlMs` / `cache.cacheScope`) matches the server's
 *     per-list hint;
 *   - a `tools/call` returns the expected (typed-struct-derived)
 *     `structuredContent` — read back via `structuredContentAs!SumResult` — and
 *     the JSON text mirror;
 *   - `readResource()` returns the expected text and the per-resource draft
 *     cache hint (`ttlMs` / `cacheScope`);
 *   - a bad `tools/call` returns the expected JSON-RPC error code.
 *
 * On success it prints an "OK:" summary and exits 0; on any mismatch it prints
 * what differed and exits non-zero.
 */
module stateless_draft_client;

import std.algorithm : canFind, map;
import std.array : array;
import std.conv : to;
import std.getopt : getopt;
import std.process : ProcessPipes, pipeProcess, Redirect, wait;
import std.string : stripRight;

import vibe.data.json : Json;

import mcp;
import mcp.protocol.draft : CacheScope;

/// `stderr.writeln` is `@system`; wrap it so the `@safe` e2e body can report.
private void logLine(string s) @trusted nothrow
{
	import std.stdio : stderr;

	try
		stderr.writeln(s);
	catch (Exception)
	{
	}
}

private void printLine(string s) @trusted nothrow
{
	import std.stdio : writeln;

	try
		writeln(s);
	catch (Exception)
	{
	}
}

/// Owns the server subprocess and exposes the newline-delimited JSON-RPC channel
/// expected by `McpClient.stdio`. Holding `ProcessPipes` in a class field keeps
/// the stdin/stdout `File` handles alive for the lifetime of the client.
///
/// (The SDK's `McpClient.spawn` would replace this boilerplate, but its
/// `spawnStdioTransport` currently lets the subprocess pipes' `File` handles be
/// refcounted to zero when the spawn helper returns — the next write fails with
/// "Attempting to write to closed File". Until that is fixed upstream this
/// example keeps the explicit, working `ProcessPipes` owner.)
final class ServerProcess
{
	private ProcessPipes pipes;

	this(string[] command) @trusted
	{
		pipes = pipeProcess(command, Redirect.stdin | Redirect.stdout);
	}

	/// Read one response line (terminator stripped), or null at EOF.
	string readLine() @trusted
	{
		auto f = pipes.stdout;
		if (f.eof)
			return null;
		auto ln = f.readln();
		if (ln.length == 0 && f.eof)
			return null;
		return ln.stripRight("\r\n");
	}

	/// Write one request line (the channel appends the terminator).
	void writeLine(string s) @trusted
	{
		pipes.stdin.writeln(s);
		pipes.stdin.flush();
	}

	/// Close stdin and reap the child.
	void shutdown() @trusted
	{
		pipes.stdin.close();
		wait(pipes.pid);
	}
}

/// Absolute path to the `stateless-draft-server` binary, resolved next to this
/// client binary (dub writes both into the package root).
private string serverBinaryPath() @safe
{
	import std.file : thisExePath;
	import std.path : dirName, buildPath;

	return buildPath(dirName(thisExePath()), "stateless-draft-server");
}

/// Typed arguments for the `add` tool. Passing this struct to the typed
/// `callTool` overload lets the SDK marshal the JSON-RPC `arguments` object from
/// the struct shape — no hand-built `Json` for a statically-known call.
struct AddArgs
{
	long a;
	long b;
}

/// Typed view of the `add` tool's `structuredContent`, mirroring the server's
/// `SumResult`. `structuredContentAs!SumResult` decodes the result's
/// `structuredContent` object into this struct, so the e2e asserts on a typed
/// field instead of reaching into raw `Json`.
struct SumResult
{
	long sum;
}

int main(string[] args)
{
	string httpUrl;
	getopt(args, "http",
			"Connect over Streamable HTTP to this URL (default: spawn server over stdio)",
			&httpUrl);

	// Build the client over the selected transport BEFORE entering the event
	// loop, so the stdio subprocess (and its pipes) outlive the e2e body.
	ServerProcess proc;
	McpClient client;
	bool overHttp = httpUrl.length != 0;
	if (overHttp)
	{
		client = McpClient.http(httpUrl);
	}
	else
	{
		proc = new ServerProcess([serverBinaryPath()]);
		client = McpClient.stdio(&proc.readLine, &proc.writeLine);
	}
	scope (exit)
		if (proc !is null)
			proc.shutdown();

	int rc;
	import vibe.core.core : runTask, runEventLoop, exitEventLoop;

	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
			rc = runE2E(client, overHttp);
		catch (Exception e)
		{
			logLine("FAIL: unexpected exception: " ~ e.msg);
			rc = 1;
		}
	});
	runEventLoop();
	return rc;
}

/// A tiny assertion helper that records the first failure rather than throwing,
/// so the e2e prints exactly what differed and returns a non-zero code.
private struct Checker
{
	bool ok = true;

	void check(bool cond, lazy string what) @safe
	{
		if (!cond)
		{
			ok = false;
			logLine("FAIL: " ~ what);
		}
	}

	void eq(T)(T actual, T expected, string label) @safe
	{
		check(actual == expected,
				label ~ ": expected " ~ expected.to!string ~ ", got " ~ actual.to!string);
	}
}

private int runE2E(McpClient client, bool overHttp) @safe
{
	Checker c;

	// --- 1. server/discover (stateless, up-front version negotiation) ---------
	client.enableDraft();
	auto disc = client.discover();
	c.check(disc.protocolVersions.canFind("2026-07-28"),
			"discover.supportedVersions should contain the draft 2026-07-28; got "
			~ disc.protocolVersions.to!string);
	c.eq(disc.serverInfo.name, "stateless-draft-server", "discover.serverInfo.name");

	// --- 2. connect() selects the stateless draft -----------------------------
	auto negotiated = client.connect();
	c.eq(negotiated, ProtocolVersion.draft, "connect() negotiated version");
	c.eq(client.protocolVersion(), ProtocolVersion.draft, "client.protocolVersion()");

	// --- 3. listTools + per-list draft CacheableResult hint -------------------
	auto tools = client.listTools();
	auto names = tools.tools.map!(t => t.name).array;
	c.check(names.canFind("add"), "listTools should contain 'add'; got " ~ names.to!string);
	c.check(!tools.cache.isNull, "listTools result should carry a draft cache hint");
	if (!tools.cache.isNull)
	{
		c.eq(tools.cache.get.ttlMs, 5000L, "tools/list cache.ttlMs");
		c.eq(tools.cache.get.cacheScope, CacheScope.public_, "tools/list cache.cacheScope");
	}

	// --- 4. tools/call: typed-struct-derived structuredContent + text mirror --
	// Pass typed args (the SDK marshals the `arguments` object from the struct).
	auto res = client.callTool("add", AddArgs(2, 40));
	c.check(!res.isError, "add tool call should not be an error result");
	// The @tool returns a SumResult struct; the SDK mirrors it into a single
	// JSON text content block and into structuredContent.
	c.check(res.content.length == 1, "add result should have one content block; got "
			~ res.content.length.to!string);
	if (res.content.length == 1)
		c.eq(res.content[0].text, `{"sum":42}`, "add result text (struct JSON mirror)");
	// Decode structuredContent into the typed struct instead of reading raw Json.
	auto sum = res.structuredContentAs!SumResult;
	c.eq(sum.sum, 42L, "add structuredContent.sum (typed)");

	// --- 5. readResource + per-resource draft cache hint ----------------------
	auto rr = client.readResource("demo://greeting");
	c.check(rr.contents.length == 1, "greeting should have one content block; got "
			~ rr.contents.length.to!string);
	if (rr.contents.length == 1)
		c.eq(rr.contents[0].text, "hello from the stateless draft server",
				"greeting resource text");
	c.check(!rr.cache.isNull, "greeting resources/read should carry a draft cache hint");
	if (!rr.cache.isNull)
	{
		c.eq(rr.cache.get.ttlMs, 9000L, "resources/read cache.ttlMs");
		c.eq(rr.cache.get.cacheScope, CacheScope.private_, "resources/read cache.cacheScope");
	}

	// --- 6. error path: unknown tool -> invalidParams (-32602) ----------------
	bool threw = false;
	int gotCode = 0;
	try
		client.callTool("does-not-exist", Json.emptyObject);
	catch (McpException e)
	{
		threw = true;
		gotCode = e.code;
	}
	c.check(threw, "calling an unknown tool should throw an McpException");
	if (threw)
		c.eq(gotCode, cast(int) ErrorCode.invalidParams, "unknown-tool error code");

	client.close();

	if (!c.ok)
	{
		logLine("FAIL: one or more assertions did not match the expected stateless-draft behavior.");
		return 1;
	}

	immutable transport = overHttp ? "http" : "stdio";
	printLine("OK: stateless-draft e2e passed over " ~ transport
			~ " — discover(2026-07-28), connect()=draft, "
			~ "listTools[add] cache(5000/public), add->{\"sum\":42} (+structuredContent), "
			~ "greeting resource cache(9000/private), unknown-tool=-32602.");
	return 0;
}
