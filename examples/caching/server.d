/**
 * Caching (CacheableResult) example — server side, UDA style.
 *
 * Demonstrates the draft `CacheableResult` freshness hints from the server's
 * point of view, over the Streamable HTTP transport, using the ergonomic UDA
 * API (`@resource` + `@cache` + `registerHandlers`):
 *
 *   - a PER-RESOURCE hint, declared with the `@cache(ttlMs, "public"|"private")`
 *     UDA on a `@resource` method. The reflection layer plumbs it through so it
 *     rides on this resource's `resources/read` result as `ttlMs` / `cacheScope`.
 *   - a PER-LIST hint, attached via `setListCacheHint("resources/list", ...)`.
 *     It rides on the `resources/list` result. (This is a server-level list hint,
 *     not a per-resource registration, so there is no per-method UDA for it.)
 *
 * Both are draft-gated: the server only emits the `ttlMs` / `cacheScope`
 * fields when the negotiated protocol is the stateless draft (2026-07-28).
 * The bundled client (client.d) speaks draft and asserts the exact values
 * set here, so the two files together are an end-to-end regression test.
 *
 * Run (two terminals):
 *   dub run -c server   # this file — serves http://127.0.0.1:8531/mcp
 *   dub run -c client   # connects and verifies the cache hints
 */
module caching_server;

import std.getopt : getopt;
import std.stdio : stderr;

import mcp;
import mcp.api.attributes : resource, cache;
import mcp.api.reflection : registerHandlers;
import mcp.protocol.draft : CacheHint, CacheScope;
import mcp.transport : StreamableHttpOptions, runStreamableHttp;

import std.typecons : nullable;

/// The TTL and scope this server attaches to the cached resource read.
/// client.d asserts these exact numbers, so they are the contract.
enum long ConfigTtlMs = 60_000;
enum long ListTtlMs = 5_000;

/// The annotated resources of the caching example. `registerHandlers` registers
/// each `@resource` method; the `@cache` UDA declares the per-resource freshness
/// hint that rides on the matching draft `resources/read`.
final class CachingApi
{
	/// A direct resource carrying a PER-RESOURCE cache hint. The body rarely
	/// changes, so we tell consumers/intermediaries it may be cached privately
	/// for 60s — declared with `@cache(ConfigTtlMs, "private")`.
	@resource("config://app", "Application configuration", "application/json")
	@cache(ConfigTtlMs, "private")
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

void main(string[] args)
{
	ushort port = 8531;
	string host = "127.0.0.1";
	getopt(args, "port|p", "Port to listen on (default 8531)", &port,
			"host|h", "Address to bind (default 127.0.0.1)", &host);

	auto server = new McpServer("caching-example", "1.0.0",
			nullable("Demonstrates draft CacheableResult freshness hints."));

	// Register the @resource methods (with their @cache hints) in one call.
	registerHandlers(server, new CachingApi);

	// A PER-LIST cache hint on resources/list: the catalogue itself is stable
	// and may be cached publicly for 5s.
	server.setListCacheHint("resources/list", CacheHint(ListTtlMs, CacheScope.public_));

	StreamableHttpOptions opts;
	opts.bindAddresses = [host];
	() @trusted {
		stderr.writefln("caching-server listening on http://%s:%d/mcp", host, port);
	}();
	runStreamableHttp(server, port, opts);
}
