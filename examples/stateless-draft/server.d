/**
 * Stateless (draft) protocol — server side, DUAL TRANSPORT.
 *
 * One binary, either transport:
 *
 *   dub run -c server                          # stdio (default)
 *   dub run -c server -- --http --port 8431    # Streamable HTTP
 *
 * The same server object speaks every protocol revision this SDK supports; the
 * *draft* (2026-07-28) stateless model is engaged per-request by the client (no
 * `initialize` handshake, per-request `_meta`, `server/discover` for version
 * negotiation). Because the draft model is purely message-level (carried in
 * `params._meta`), it rides identically over stdio and HTTP — so the very same
 * client e2e verifies both transports.
 *
 * The tool and resource are declared in the ergonomic UDA style: a `@tool`
 * method returning a TYPED struct (its input schema is inferred from the typed
 * parameters and its `structuredContent` is inferred from the returned struct),
 * and a `@resource` method carrying its draft freshness hint via `@cache`.
 * `registerHandlers` wires both onto the server. There is no hand-built
 * request/response Json anywhere in this file.
 */
module stateless_draft_server;

import std.getopt : getopt;
import std.typecons : nullable;
import std.stdio : stderr;

import mcp;
import mcp.transport : StreamableHttpOptions, runStreamableHttp, runStdio;
import mcp.protocol.draft : CacheHint, CacheScope;

enum string defaultHost = "127.0.0.1";
enum ushort defaultPort = 8431;

/// Typed result of the `add` tool. Returning a struct from a `@tool` method lets
/// the reflection layer DERIVE both the output schema (`jsonSchemaOf!SumResult`)
/// and the per-call `structuredContent` from this shape — no hand-built Json.
struct SumResult
{
	/// The arithmetic sum of the two inputs.
	long sum;
}

/// The server's tool + resource surface, declared in UDA style.
final class StatelessDraftApi
{
	/// A plain `add` tool. On a draft (stateless) request the transport carries
	/// the per-request `_meta`; the handler itself is protocol-agnostic.
	///
	/// The argument schema (`a`, `b` as integers, both required) is inferred from
	/// the typed parameters, and the returned `SumResult` struct is inferred into
	/// `structuredContent` (and a JSON text mirror) by the SDK — the typed path,
	/// no hand-built `CallToolResult`.
	@tool("add", "Add two integers and return the sum.")
	SumResult add(long a, long b) @safe
	{
		return SumResult(a + b);
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
	bool http;
	ushort port = defaultPort;
	string host = defaultHost;
	getopt(args,
			"http", "Serve over Streamable HTTP instead of stdio", &http,
			"port|p", "HTTP port to listen on (default 8431)", &port,
			"host|h", "HTTP address to bind (default 127.0.0.1)", &host);

	auto server = new McpServer("stateless-draft-server", "1.0.0",
			nullable("A stateless (draft) demo server: server/discover + per-request _meta."));

	// Register every @tool / @resource annotated method in one call; input
	// schema, the SumResult-derived output schema + structuredContent, argument
	// marshalling, and the resource's @cache freshness hint are all derived from
	// the annotations and signatures.
	registerHandlers(server, new StatelessDraftApi);

	// Draft-only per-list freshness hint: a draft client's `listTools().cache`
	// will carry these `ttlMs` / `cacheScope` values. Pre-draft wire output is
	// unchanged (no cache fields emitted). This is a server-level list hint, not
	// a per-tool one, so it stays a direct server call.
	server.setListCacheHint("tools/list", CacheHint(5000, CacheScope.public_));

	if (http)
	{
		StreamableHttpOptions opts;
		// Bind loopback only; the transport's Origin guard already restricts to
		// localhost, which is exactly what this local demo wants.
		opts.bindAddresses = [host];
		stderr.writefln("stateless-draft-server listening on http://%s:%d/mcp", host, port);
		runStreamableHttp(server, port, opts);
	}
	else
	{
		// stdio: a single newline-delimited JSON-RPC stream on stdin/stdout. The
		// draft stateless model rides on per-request `_meta` exactly as over HTTP.
		runStdio(server);
	}
	return 0;
}
