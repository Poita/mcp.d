/**
 * Caching (CacheableResult) example — client side AND self-verifying e2e test,
 * over BOTH stdio and Streamable HTTP.
 *
 * Connects to the caching server (draft / stateless), then asserts the server's
 * cache behavior matches exactly what server.d set:
 *
 *   1. resources/list carries the PER-LIST hint (ttlMs=5000, scope=public)
 *      and lists both registered resources.
 *   2. reading config://app carries the PER-RESOURCE hint
 *      (ttlMs=60000, scope=private) and the expected body.
 *   3. reading status://live (no @cache) carries the draft-mandatory do-not-cache
 *      default hint (ttlMs:0, public) — the draft CacheableResult schema requires
 *      ttlMs on every cacheable result.
 *
 * Transport selection (same assertions either way) is handled by the shared
 * scaffold helper `connectFromArgs`:
 *   - default (no --http): spawn the sibling `caching-server` binary over stdio
 *     with `McpClient.spawnSibling("caching-server")` — the SDK owns the
 *     subprocess and reaps it (close stdin -> SIGTERM -> SIGKILL) on close().
 *   - `--http <url>`: connect to a running HTTP server via McpClient.http(url).
 *
 * The scenario runs inside the shared `runClient` event-loop driver, which lets
 * the IDENTICAL body verify both transports; assertions use the shared
 * `check` / `checkEq` helpers, which print a `FAIL:` line and exit non-zero on
 * any mismatch, so CI can run this as a behavioral regression test.
 *
 * Run:
 *   # stdio: the client spawns the server for you
 *   dub run -c client
 *
 *   # http: start the server first, then point the client at it
 *   dub run -c server -- --http --port 8531
 *   dub run -c client -- --http http://127.0.0.1:8531/mcp
 */
module caching_client;

import std.algorithm : map, canFind;
import std.array : array;

import mcp.client.client : McpClient;
import mcp.protocol.modern : CacheScope;

import examples_common : check, checkEq, runClient, connectFromArgs;

import core.time : Duration, seconds;

// Expected contract — must match the enums/values in server.d.
enum Duration ExpectConfigTtl = 60.seconds;
enum Duration ExpectListTtl = 5.seconds;

int main(string[] args) @safe
{
	return runClient(() @safe {
		// Transport picked from argv by the scaffold: spawn the sibling
		// `caching-server` over stdio, or connect over HTTP with `--http <url>`.
		auto client = connectFromArgs(args, "caching-server");
		scope (exit)
			client.close();

		// Cache hints are a draft-only feature: speak the stateless draft
		// protocol (no initialize handshake). Transport-agnostic — the same call
		// works over stdio and HTTP.
		client.enableModern();

		// --- 1. resources/list carries the per-list cache hint ----------------
		auto list = client.listResources();
		auto names = list.resources.map!(r => r.uri).array;
		check(names.canFind("config://app"), "resources/list missing config://app");
		check(names.canFind("status://live"), "resources/list missing status://live");

		check(!list.cache.isNull, "resources/list result carried NO cache hint (expected one)");
		checkEq(list.cache.get.ttl, ExpectListTtl, "resources/list ttl");
		checkEq(list.cache.get.cacheScope, CacheScope.public_, "resources/list cacheScope");

		// --- 2. reading config://app carries the per-resource cache hint ------
		auto cfg = client.readResource("config://app");
		checkEq(cfg.contents.length, 1UL, "config://app content block count");
		checkEq(cfg.contents[0].text, `{"theme":"dark","retries":3}`, "config://app body");
		check(!cfg.cache.isNull, "config://app read carried NO cache hint (expected one)");
		checkEq(cfg.cache.get.ttl, ExpectConfigTtl, "config://app ttl");
		checkEq(cfg.cache.get.cacheScope, CacheScope.private_, "config://app cacheScope");

		// --- 3. status://live has no @cache UDA, so under the draft protocol it
		//        still carries the MANDATORY freshness hint as the conservative
		//        do-not-cache default (ttlMs:0, public scope) — the draft
		//        CacheableResult schema requires ttlMs on every cacheable result.
		auto st = client.readResource("status://live");
		check(!st.cache.isNull,
			"status://live read should carry the draft do-not-cache default hint (ttlMs:0)");
		checkEq(st.cache.get.ttl, Duration.zero,
			"status://live ttl should be zero (do-not-cache default)");
		checkEq(st.cache.get.cacheScope, CacheScope.public_,
			"status://live cacheScope should default to public");

		return 0;
	});
}
