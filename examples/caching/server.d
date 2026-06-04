/**
 * Caching (CacheableResult) example — server side, UDA style, DUAL TRANSPORT.
 *
 * Demonstrates the draft `CacheableResult` freshness hints from the server's
 * point of view, using the ergonomic UDA API (`@resource` + `@cache` +
 * `registerHandlers`):
 *
 *   - a PER-RESOURCE hint, declared with the `@cache(ttl, "public"|"private")`
 *     UDA (a `core.time.Duration`) on a `@resource` method. The reflection layer
 *     plumbs it through so it rides on this resource's `resources/read` result as
 *     `ttlMs` / `cacheScope`.
 *   - a PER-LIST hint, attached via `setListCacheHint("resources/list", ...)`.
 *     It rides on the `resources/list` result. (This is a server-level list hint,
 *     not a per-resource registration, so there is no per-method UDA for it.)
 *
 * Both are draft-gated: the server only emits the `ttlMs` / `cacheScope`
 * fields when the negotiated protocol is the stateless draft (2026-07-28).
 *
 * ONE BINARY, EITHER TRANSPORT. The transport is selected by flags via the
 * shared `runServerFromArgs` scaffold helper:
 *   - default (no flags)  -> stdio   (runStdio)            — deployable shape
 *   - `--http`            -> Streamable HTTP (runStreamableHttp) on `--port`
 *
 * The bundled client (client.d) is transport-agnostic: it spawns this binary
 * over stdio (no `--http`), or connects to it over HTTP (`--http` server +
 * `--http <url>` client), and asserts the exact values set here either way.
 *
 * Run:
 *   # stdio (the client spawns this binary for you):
 *   dub run -c client
 *
 *   # http (two steps):
 *   dub run -c server -- --http --port 8531   # serves http://127.0.0.1:8531/mcp
 *   dub run -c client -- --http http://127.0.0.1:8531/mcp
 */
module caching_server;

import mcp;
import mcp.api.attributes : resource, cache;
import mcp.api.reflection : registerHandlers;
import mcp.protocol.modern : CacheHint, CacheScope;

import examples_common : runServerFromArgs;

import std.typecons : nullable;
import core.time : Duration, seconds;

/// The TTL and scope this server attaches to the cached resource read.
/// client.d asserts the wire `ttlMs` these serialize to (60000 / 5000 ms).
enum Duration ConfigTtl = 60.seconds;
enum Duration ListTtl = 5.seconds;

/// The annotated resources of the caching example. `registerHandlers` registers
/// each `@resource` method; the `@cache` UDA declares the per-resource freshness
/// hint that rides on the matching draft `resources/read`.
final class CachingApi
{
	/// A direct resource carrying a PER-RESOURCE cache hint. The body rarely
	/// changes, so we tell consumers/intermediaries it may be cached privately
	/// for 60s — declared with `@cache(ConfigTtl, "private")`.
	@resource("config://app", "Application configuration", "application/json")
	@cache(ConfigTtl, "private")
	string config() @safe
	{
		return `{"theme":"dark","retries":3}`;
	}

	/// A second resource with NO cache hint, to prove the absence is reported
	/// faithfully (client asserts its read carries no cache hint).
	@resource("status://live", "Live status (uncacheable)", "text/plain")
	string status() @safe
	{
		return "ok";
	}
}

void main(string[] args) @safe
{
	auto server = new McpServer("caching-example", "1.0.0",
			nullable("Demonstrates draft CacheableResult freshness hints."));

	// Register the @resource methods (with their @cache hints) in one call.
	registerHandlers(server, new CachingApi);

	// A PER-LIST cache hint on resources/list: the catalogue itself is stable
	// and may be cached publicly for 5s.
	server.setListCacheHint("resources/list", CacheHint(ListTtl, CacheScope.public_));

	// Transport selected by argv via the shared scaffold helper:
	//   (no flags) -> runStdio ; --http [--port N] [--host H] -> runStreamableHttp.
	runServerFromArgs(server, args, 8531);
}
