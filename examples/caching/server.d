/**
 * Caching (CacheableResult) example — server side.
 *
 * Demonstrates the draft `CacheableResult` freshness hints from the server's
 * point of view, over the Streamable HTTP transport:
 *
 *   - a PER-RESOURCE hint, attached at registration via the optional
 *     `CacheHint` argument of `registerResource(...)`. It rides on this
 *     resource's `resources/read` result as `ttlMs` / `cacheScope`.
 *   - a PER-LIST hint, attached via `setListCacheHint("resources/list", ...)`.
 *     It rides on the `resources/list` result.
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
import mcp.protocol.draft : CacheHint, CacheScope;
import mcp.transport : StreamableHttpOptions, runStreamableHttp;

import std.typecons : nullable;

/// The TTL and scope this server attaches to the cached resource read.
/// client.d asserts these exact numbers, so they are the contract.
enum long ConfigTtlMs = 60_000;
enum long ListTtlMs = 5_000;

void main(string[] args)
{
	ushort port = 8531;
	string host = "127.0.0.1";
	getopt(args, "port|p", "Port to listen on (default 8531)", &port,
			"host|h", "Address to bind (default 127.0.0.1)", &host);

	auto server = new McpServer("caching-example", "1.0.0",
			nullable("Demonstrates draft CacheableResult freshness hints."));

	// A direct resource carrying a PER-RESOURCE cache hint. The body rarely
	// changes, so we tell consumers/intermediaries it may be cached privately
	// for 60s. The hint is the third argument to registerResource.
	auto config = Resource("config://app", "Application configuration");
	server.registerResource(config, () @safe {
		return ResourceContents.makeText("config://app", "application/json",
			`{"theme":"dark","retries":3}`);
	}, nullable(CacheHint(ConfigTtlMs, CacheScope.private_)));

	// A second resource with NO cache hint, to prove the absence is reported
	// faithfully (client asserts its read carries no cache hint).
	auto status = Resource("status://live", "Live status (uncacheable)");
	server.registerResource(status, () @safe {
		return ResourceContents.makeText("status://live", "text/plain", "ok");
	});

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
