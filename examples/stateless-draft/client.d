/**
 * Stateless (draft) protocol — client side AND the example's e2e test.
 *
 * Connects to the Streamable HTTP server from `server.d`, drives it under the
 * draft (2026-07-28) stateless model, and ASSERTS the consumer's-eye view:
 *
 *   - `server/discover` advertises the draft version "2026-07-28" and the
 *     server's identity (no `initialize` handshake);
 *   - `connect()` selects the stateless draft as the negotiated version;
 *   - `listTools()` contains the expected tool, and its draft `CacheableResult`
 *     freshness hint (`cache.ttlMs` / `cache.cacheScope`) matches what the
 *     server set per-list;
 *   - a `tools/call` returns the expected text + structuredContent;
 *   - `readResource()` returns the expected text and the per-resource draft
 *     cache hint (`ttlMs` / `cacheScope`);
 *   - a bad `tools/call` returns the expected JSON-RPC error code.
 *
 * On success it prints an "OK:" summary and exits 0; on any mismatch it prints
 * what differed and exits non-zero. CI runs this against a backgrounded
 * `server.d`, so the exit code is the regression signal.
 *
 * Run (two terminals):
 *   dub run -c server                          # terminal 1
 *   dub run -c client -- http://127.0.0.1:8431/mcp   # terminal 2 (default URL if omitted)
 */
module stateless_draft_client;

import std.algorithm : canFind, map;
import std.array : array;
import std.conv : to;

import vibe.core.core : runTask, runEventLoop, exitEventLoop;
import vibe.data.json : Json;

import mcp;
import mcp.protocol.draft : CacheScope;

enum string defaultUrl = "http://127.0.0.1:8431/mcp";

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

int main(string[] args)
{
	string url = (args.length > 1) ? args[$ - 1] : defaultUrl;

	int rc;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
			rc = runE2E(url);
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

private int runE2E(string url) @safe
{
	Checker c;

	auto client = McpClient.http(url);

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

	// --- 4. tools/call: text + structuredContent ------------------------------
	Json addArgs = Json.emptyObject;
	addArgs["a"] = 2;
	addArgs["b"] = 40;
	auto res = client.callTool("add", addArgs);
	c.check(!res.isError, "add tool call should not be an error result");
	c.check(res.content.length == 1, "add result should have one content block; got "
			~ res.content.length.to!string);
	if (res.content.length == 1)
		c.eq(res.content[0].text, "sum = 42", "add result text");
	c.check(res.structuredContent.type == Json.Type.object
			&& "sum" in res.structuredContent,
			"add result should carry structuredContent.sum");
	if (res.structuredContent.type == Json.Type.object && "sum" in res.structuredContent)
		c.eq(res.structuredContent["sum"].get!long, 42L, "add structuredContent.sum");

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

	printLine("OK: stateless-draft e2e passed — discover(2026-07-28), connect()=draft, "
			~ "listTools[add] cache(5000/public), add->42 (+structuredContent), "
			~ "greeting resource cache(9000/private), unknown-tool=-32602.");
	return 0;
}
