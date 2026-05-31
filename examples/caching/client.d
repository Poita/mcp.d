/**
 * Caching (CacheableResult) example — client side AND self-verifying e2e test.
 *
 * Connects to the caching server over Streamable HTTP (draft / stateless), then
 * asserts the server's cache behavior matches exactly what server.d set:
 *
 *   1. resources/list carries the PER-LIST hint (ttlMs=5000, scope=public)
 *      and lists both registered resources.
 *   2. reading config://app carries the PER-RESOURCE hint
 *      (ttlMs=60000, scope=private) and the expected body.
 *   3. reading status://live (no hint) carries NO cache hint.
 *
 * On success it prints "OK: ..." and exits 0. On ANY mismatch it prints what
 * differed and exits non-zero, so CI can run it as a behavioral regression
 * test.
 *
 * Run: start server.d first (dub run -c server), then `dub run -c client`.
 * The server URL/port may be overridden with --url.
 */
module caching_client;

import std.getopt : getopt;
import std.stdio : writeln, stderr;
import std.algorithm : map, canFind;
import std.array : array;
import std.format : format;

import mcp;
import mcp.protocol.draft : CacheScope;

// Expected contract — must match the enums/values in server.d.
enum long ExpectConfigTtlMs = 60_000;
enum long ExpectListTtlMs = 5_000;

int main(string[] args)
{
	string url = "http://127.0.0.1:8531/mcp";
	getopt(args, "url|u", "Server MCP endpoint (default http://127.0.0.1:8531/mcp)", &url);

	string[] failures;
	void check(bool cond, lazy string msg) @safe
	{
		if (!cond)
			failures ~= msg;
	}

	auto client = McpClient.http(url);
	// Cache hints are a draft-only feature: speak the stateless draft protocol.
	client.enableDraft();

	// --- 1. resources/list carries the per-list cache hint --------------------
	auto list = client.listResources();
	auto names = list.resources.map!(r => r.uri).array;
	check(names.canFind("config://app"),
		format("resources/list missing config://app; got %s", names));
	check(names.canFind("status://live"),
		format("resources/list missing status://live; got %s", names));

	check(!list.cache.isNull, "resources/list result carried NO cache hint (expected one)");
	if (!list.cache.isNull)
	{
		check(list.cache.get.ttlMs == ExpectListTtlMs,
			format("resources/list ttlMs = %d, expected %d",
				list.cache.get.ttlMs, ExpectListTtlMs));
		check(list.cache.get.cacheScope == CacheScope.public_,
			format("resources/list cacheScope = %s, expected public",
				cast(string) list.cache.get.cacheScope));
	}

	// --- 2. reading config://app carries the per-resource cache hint ----------
	auto cfg = client.readResource("config://app");
	check(cfg.contents.length == 1,
		format("config://app returned %d content blocks, expected 1", cfg.contents.length));
	if (cfg.contents.length >= 1)
	{
		check(cfg.contents[0].text == `{"theme":"dark","retries":3}`,
			format("config://app body = %s", cfg.contents[0].text));
	}
	check(!cfg.cache.isNull, "config://app read carried NO cache hint (expected one)");
	if (!cfg.cache.isNull)
	{
		check(cfg.cache.get.ttlMs == ExpectConfigTtlMs,
			format("config://app ttlMs = %d, expected %d",
				cfg.cache.get.ttlMs, ExpectConfigTtlMs));
		check(cfg.cache.get.cacheScope == CacheScope.private_,
			format("config://app cacheScope = %s, expected private",
				cast(string) cfg.cache.get.cacheScope));
	}

	// --- 3. reading status://live carries NO cache hint -----------------------
	auto st = client.readResource("status://live");
	check(st.cache.isNull,
		"status://live read carried a cache hint, but the server set none");

	if (failures.length)
	{
		stderr.writeln("FAIL: caching example assertions did not hold:");
		foreach (f; failures)
			stderr.writeln("  - ", f);
		return 1;
	}

	writeln(format(
		"OK: list hint ttlMs=%d/public, config://app hint ttlMs=%d/private, status://live uncached",
		ExpectListTtlMs, ExpectConfigTtlMs));
	return 0;
}
