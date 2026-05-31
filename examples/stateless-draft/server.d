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
 * Run:
 *   dub run -c server            # listens on http://127.0.0.1:8431/mcp
 *
 * The companion `client.d` connects, runs `server/discover`, exercises the
 * tool + resource statelessly, and asserts the results (it is the e2e test).
 */
module stateless_draft_server;

import std.getopt : getopt;
import std.typecons : nullable;
import std.stdio : stderr;

import vibe.data.json : Json;

import mcp;
import mcp.transport : StreamableHttpOptions, runStreamableHttp;
import mcp.protocol.draft : CacheHint, CacheScope;

enum string defaultHost = "127.0.0.1";
enum ushort defaultPort = 8431;

int main(string[] args)
{
	ushort port = defaultPort;
	getopt(args, "port|p", "Port to listen on (default 8431)", &port);

	auto server = new McpServer("stateless-draft-server", "1.0.0",
			nullable("A stateless (draft) demo server: server/discover + per-request _meta."));

	registerTools(server);
	registerResources(server);

	// Draft-only per-list freshness hint: a draft client's `listTools().cache`
	// will carry these `ttlMs` / `cacheScope` values. Pre-draft wire output is
	// unchanged (no cache fields emitted).
	server.setListCacheHint("tools/list", CacheHint(5000, CacheScope.public_));

	StreamableHttpOptions opts;
	// Bind loopback only; the transport's Origin guard already restricts to
	// localhost, which is exactly what this local demo wants.
	opts.bindAddresses = [defaultHost];

	stderr.writefln("stateless-draft-server listening on http://%s:%d/mcp", defaultHost, port);
	runStreamableHttp(server, port, opts);
	return 0;
}

private void registerTools(McpServer server) @safe
{
	// A plain `add` tool. On a draft (stateless) request the transport carries
	// the per-request `_meta`; the handler itself is protocol-agnostic.
	Tool add = {
		name: "add",
		description: nullable("Add two integers and return the sum."),
	};
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	Json aProp = Json.emptyObject;
	aProp["type"] = "integer";
	Json bProp = Json.emptyObject;
	bProp["type"] = "integer";
	props["a"] = aProp;
	props["b"] = bProp;
	schema["properties"] = props;
	Json req = Json.emptyArray;
	req ~= Json("a");
	req ~= Json("b");
	schema["required"] = req;
	add.inputSchema = schema;

	server.registerDynamicTool(add, (Json args) @safe {
		const a = args["a"].get!long;
		const b = args["b"].get!long;
		const sum = a + b;
		Json sc = Json.emptyObject;
		sc["sum"] = sum;
		import std.conv : to;

		CallToolResult r;
		r.content = [Content.makeText("sum = " ~ sum.to!string)];
		r.structuredContent = sc;
		return r;
	});
}

private void registerResources(McpServer server) @safe
{
	Resource greeting = {
		uri: "demo://greeting",
		name: "greeting",
		description: nullable("A static greeting resource with a draft cache hint."),
		mimeType: nullable("text/plain"),
	};

	// Draft-only per-resource `CacheableResult` freshness hint. A draft client's
	// `readResource("demo://greeting").cache` will carry exactly these values.
	server.registerResource(greeting,
			() @safe => ResourceContents.makeText("demo://greeting", "text/plain",
				"hello from the stateless draft server"),
			nullable(CacheHint(9000, CacheScope.private_)));
}
