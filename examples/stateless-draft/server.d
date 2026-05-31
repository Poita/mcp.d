/**
 * Stateless (draft) protocol — server side.
 *
 * A standalone, deployable MCP server exposed over the Streamable HTTP
 * transport. The same server object speaks every protocol revision this SDK
 * supports; the *draft* (2026-07-28) stateless model is engaged per-request by
 * the client (no `initialize` handshake, per-request `_meta`, `server/discover`
 * for version negotiation). Nothing here is draft-specific except the two
 * draft-only freshness hints below — which are simply ignored on the wire for
 * pre-draft peers.
 *
 * The tool and resource are declared in the ergonomic UDA style: a `@tool`
 * method with typed arguments (the input schema is inferred), and a `@resource`
 * method carrying its draft freshness hint via `@cache`. `registerHandlers`
 * wires both onto the server.
 *
 * Run:
 *   dub run -c server            # listens on http://127.0.0.1:8431/mcp
 *
 * The companion `client.d` connects, runs `server/discover`, exercises the
 * tool + resource statelessly, and asserts the results (it is the e2e test).
 */
module stateless_draft_server;

import std.getopt : getopt;
import std.typecons : nullable;
import std.conv : to;
import std.stdio : stderr;

import vibe.data.json : Json;

import mcp;
import mcp.transport : StreamableHttpOptions, runStreamableHttp;
import mcp.protocol.draft : CacheHint, CacheScope;

enum string defaultHost = "127.0.0.1";
enum ushort defaultPort = 8431;

/// The server's tool + resource surface, declared in UDA style.
final class StatelessDraftApi
{
	/// A plain `add` tool. On a draft (stateless) request the transport carries
	/// the per-request `_meta`; the handler itself is protocol-agnostic.
	///
	/// The argument schema (`a`, `b` as integers, both required) is inferred from
	/// the typed parameters. The result is hand-built as a `CallToolResult` so it
	/// carries both the human-readable `"sum = N"` text and a `structuredContent`
	/// object keyed `sum` — a shape the default struct-return marshalling does not
	/// reproduce verbatim (a struct return would emit the JSON itself as the text).
	@tool("add", "Add two integers and return the sum.")
	CallToolResult add(long a, long b) @safe
	{
		const sum = a + b;
		Json sc = Json.emptyObject;
		sc["sum"] = sum;

		CallToolResult r;
		r.content = [Content.makeText("sum = " ~ sum.to!string)];
		r.structuredContent = sc;
		return r;
	}

	/// A static greeting resource. The draft-only per-resource `CacheableResult`
	/// freshness hint is declared via `@cache`; a draft client's
	/// `readResource("demo://greeting").cache` will carry exactly these values
	/// (ttlMs=9000, scope=private). Pre-draft peers see no cache fields.
	@resource("demo://greeting", "greeting", "text/plain")
	@cache(9000, "private")
	string greeting() @safe
	{
		return "hello from the stateless draft server";
	}
}

int main(string[] args)
{
	ushort port = defaultPort;
	getopt(args, "port|p", "Port to listen on (default 8431)", &port);

	auto server = new McpServer("stateless-draft-server", "1.0.0",
			nullable("A stateless (draft) demo server: server/discover + per-request _meta."));

	// Register every @tool / @resource annotated method in one call; input
	// schema, argument marshalling, and the resource's @cache freshness hint are
	// all derived from the annotations and signatures.
	registerHandlers(server, new StatelessDraftApi);

	// Draft-only per-list freshness hint: a draft client's `listTools().cache`
	// will carry these `ttlMs` / `cacheScope` values. Pre-draft wire output is
	// unchanged (no cache fields emitted). This is a server-level list hint, not
	// a per-tool one, so it stays a direct server call.
	server.setListCacheHint("tools/list", CacheHint(5000, CacheScope.public_));

	StreamableHttpOptions opts;
	// Bind loopback only; the transport's Origin guard already restricts to
	// localhost, which is exactly what this local demo wants.
	opts.bindAddresses = [defaultHost];

	stderr.writefln("stateless-draft-server listening on http://%s:%d/mcp", defaultHost, port);
	runStreamableHttp(server, port, opts);
	return 0;
}
