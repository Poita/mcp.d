/**
 * Stateless (draft) protocol — client side AND the example's e2e test.
 * DUAL TRANSPORT: the SAME assertions run over BOTH stdio and HTTP.
 *
 *   dub run -c client                                       # stdio: spawns the server
 *   dub run -c client -- --http http://127.0.0.1:8431/mcp   # HTTP
 *
 * Transport selection and event-loop wiring are delegated to the shared
 * `examples_common` scaffold: `connectFromArgs(args, "stateless-draft-server")`
 * returns an `McpClient.http(url)` when `--http <url>` (or `--url <url>`) is
 * given, otherwise `McpClient.spawnSibling("stateless-draft-server")` — which
 * launches the built server binary next to this client and talks
 * newline-delimited JSON-RPC over its stdin/stdout. `runClient(scenario)` drives
 * the vibe event loop uniformly so the IDENTICAL assertion body works over both
 * channels. The draft (2026-07-28) stateless model is engaged the same way on
 * either channel — `enableModern()` + per-request `_meta`.
 *
 * It ASSERTS the consumer's-eye view:
 *
 *   - `server/discover` advertises the draft version "2026-07-28" and the
 *     server's identity (no `initialize` handshake);
 *   - `connect()` selects the stateless draft as the negotiated version;
 *   - `listTools()` contains the expected tool, and its draft `CacheableResult`
 *     freshness hint (`cache.ttl` / `cache.cacheScope`) matches the server's
 *     per-list hint;
 *   - a `tools/call` returns the expected (typed-struct-derived)
 *     `structuredContent` — read back via `structuredContentAs!SumResult` — and
 *     the JSON text mirror;
 *   - `readResource()` returns the expected text and the per-resource draft
 *     cache hint (`ttl` / `cacheScope`);
 *   - a bad `tools/call` returns the expected JSON-RPC error code;
 *   - a second client reconnects with ZERO round trips via
 *     `connect(discoverResult())` (rehydrated through `DiscoverResult`
 *     `toJson`/`fromJson`) — no `server/discover` — and still serves a call.
 *
 * On success it prints an "OK:" summary and the scenario returns 0; on any
 * mismatch the shared `check`/`checkEq` print a `FAIL:` line and throw, so
 * `runClient` returns a non-zero exit code.
 */
module stateless_draft_client;

import std.algorithm : canFind, map;
import std.array : array;
import std.conv : to;

import vibe.data.json : Json;

import mcp;
import mcp.protocol.modern : CacheScope;

import examples_common : check, checkEq, runClient, connectFromArgs;

import core.time : seconds;

private void printLine(string s) @trusted nothrow
{
	import std.stdio : writeln;

	try
		writeln(s);
	catch (Exception)
	{
	}
}

/// Build the `add` tool's JSON-RPC `arguments` object (`{ "a": a, "b": b }`).
/// The client request surface is untyped — callers hand it the JSON a host
/// would receive from a model (see DESIGN.md).
private Json addArgs(long a, long b) @safe
{
	Json j = Json.emptyObject;
	j["a"] = a;
	j["b"] = b;
	return j;
}

/// Typed view of the `add` tool's `structuredContent`, mirroring the server's
/// `SumResult`. `structuredContentAs!SumResult` decodes the result's
/// `structuredContent` object into this struct, so the e2e asserts on a typed
/// field instead of reaching into raw `Json`.
struct SumResult
{
	long sum;
}

int main(string[] args) @safe
{
	// The transport label is purely cosmetic (for the OK: summary); the scaffold
	// derives the actual transport from the same flags.
	immutable overHttp = args.canFind("--http") || args.canFind("--url");
	return runClient(() @safe {
		// connectFromArgs picks HTTP (`--http <url>`/`--url <url>`) or spawns the
		// sibling `stateless-draft-server` over stdio. The client is not yet
		// initialized; the draft path uses enableModern()/connect() below.
		McpClient makeClient() @safe
		{
			return connectFromArgs(args, "stateless-draft-server");
		}

		auto client = makeClient();
		scope (exit)
			client.close();
		return runE2E(client, &makeClient, overHttp);
	});
}

private int runE2E(McpClient client, McpClient delegate() @safe makeClient, bool overHttp) @safe
{
	// --- 1. server/discover (stateless, up-front version negotiation) ---------
	client.enableModern();
	auto disc = client.discover();
	check(disc.protocolVersions.canFind("2026-07-28"),
			"discover.supportedVersions should contain the draft 2026-07-28; got "
			~ disc.protocolVersions.to!string);
	checkEq(disc.serverInfo.name, "stateless-draft-server", "discover.serverInfo.name");

	// --- 2. connect() selects the stateless draft -----------------------------
	auto negotiated = client.connect();
	checkEq(negotiated, ProtocolVersion.modern, "connect() negotiated version");
	checkEq(client.protocolVersion(), ProtocolVersion.modern, "client.protocolVersion()");

	// --- 3. listTools + per-list draft CacheableResult hint -------------------
	auto tools = client.listTools();
	auto names = tools.tools.map!(t => t.name).array;
	check(names.canFind("add"), "listTools should contain 'add'; got " ~ names.to!string);
	check(!tools.cache.isNull, "listTools result should carry a draft cache hint");
	checkEq(tools.cache.get.ttl, 5.seconds, "tools/list cache.ttl");
	checkEq(tools.cache.get.cacheScope, CacheScope.public_, "tools/list cache.cacheScope");

	// --- 4. tools/call: structuredContent + text mirror -----------------------
	// Pass the arguments as a JSON object (the untyped client request surface).
	auto res = client.callTool("add", addArgs(2, 40));
	check(!res.isError, "add tool call should not be an error result");
	// The @tool returns a SumResult struct; the SDK mirrors it into a single
	// JSON text content block and into structuredContent.
	checkEq(res.content.length, 1UL, "add result content block count");
	checkEq(res.content[0].text, `{"sum":42}`, "add result text (struct JSON mirror)");
	// Decode structuredContent into the typed struct instead of reading raw Json.
	auto sum = res.structuredContentAs!SumResult;
	checkEq(sum.sum, 42L, "add structuredContent.sum (typed)");

	// --- 5. readResource + per-resource draft cache hint ----------------------
	auto rr = client.readResource("demo://greeting");
	checkEq(rr.contents.length, 1UL, "greeting content block count");
	checkEq(rr.contents[0].text, "hello from the stateless draft server",
			"greeting resource text");
	check(!rr.cache.isNull, "greeting resources/read should carry a draft cache hint");
	checkEq(rr.cache.get.ttl, 9.seconds, "resources/read cache.ttl");
	checkEq(rr.cache.get.cacheScope, CacheScope.private_, "resources/read cache.cacheScope");

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
	check(threw, "calling an unknown tool should throw an McpException");
	checkEq(gotCode, cast(int) ErrorCode.invalidParams, "unknown-tool error code");

	// --- 7. zero-RTT reconnect via connect(DiscoverResult) --------------------
	// The first client persisted its discovery; a second client rehydrates it and
	// reconnects with NO server/discover round-trip. We round-trip the result
	// through toJson/fromJson to model loading it from a cache.
	check(!client.discoverResult().isNull,
			"client.discoverResult() should be populated after connect()");
	auto persisted = DiscoverResult.fromJson(client.discoverResult().get.toJson());

	auto second = makeClient();
	scope (exit)
		second.close();
	// No enableModern(), no discover(): connect(prior) selects the version from the
	// persisted result alone and adopts modern framing with zero round trips.
	auto reNegotiated = second.connect(persisted);
	checkEq(reNegotiated, ProtocolVersion.modern, "connect(DiscoverResult) negotiated version");
	checkEq(second.protocolVersion(), ProtocolVersion.modern,
			"reconnected client.protocolVersion()");
	// The adopted identity came straight from the persisted discovery (no network).
	checkEq(second.serverInfo().name, "stateless-draft-server",
			"reconnected serverInfo adopted from the persisted discovery");
	// It serves a real call over the adopted draft session.
	auto reAdd = second.callTool("add", addArgs(1, 1));
	check(!reAdd.isError, "reconnected client should serve a tools/call");
	checkEq(reAdd.structuredContentAs!SumResult.sum, 2L, "reconnected add(1,1) should be 2");

	// Transport teardown is owned by main's scope(exit) client.close() (the stdio
	// shutdown sequence on the spawned subprocess), so don't close here.

	immutable transport = overHttp ? "http" : "stdio";
	printLine("OK: stateless-draft e2e passed over " ~ transport
			~ " — discover(2026-07-28), connect()=draft, "
			~ "listTools[add] cache(5000/public), add->{\"sum\":42} (+structuredContent), "
			~ "greeting resource cache(9000/private), unknown-tool=-32602, "
			~ "zero-RTT reconnect via connect(discoverResult).");
	return 0;
}
