/**
 * Authorization (OAuth 2.1) example — SERVER side.
 *
 * A standalone, deployable Streamable HTTP MCP server protected as an OAuth 2.1
 * Resource Server (basic/authorization; RFC 6750 / 8707 / 9728).
 *
 * The single auth entry point is `jwtVerifier`: it is plugged into
 * `ResourceServerConfig.validator`, and from there the Streamable HTTP transport
 *   - replies `401` with a `WWW-Authenticate: Bearer ... resource_metadata=...,
 *     scope=...` challenge when no/invalid token is presented,
 *   - serves the RFC 9728 Protected Resource Metadata document at
 *     `/.well-known/oauth-protected-resource`,
 *   - enforces the RFC 8707 audience binding (a token must name THIS resource),
 *   - enforces the server-wide required scope (`mcp:read`), returning
 *     `403 insufficient_scope` otherwise, and
 *   - surfaces the validated `TokenInfo` to tool handlers via
 *     `RequestContext.auth`, which a tool uses for finer-grained scope checks.
 *
 * The two tools are declared in the ergonomic UDA style (`@tool` methods on an
 * `AuthApi` class, registered in one call via `registerHandlers`). Each takes a
 * `RequestContext ctx` (auto-injected, omitted from the input schema) to read
 * `ctx.auth()`. The TYPED APIs are used throughout:
 *   - `whoami` returns a typed `WhoamiResult` struct, so the reflection layer
 *     INFERS both the tool's output schema (via `jsonSchemaOf`) and the
 *     `structuredContent` of the result — no hand-built `Json`.
 *   - `secret_note` returns a `CallToolResult` built via the `CallToolResult.text`
 *     / `CallToolResult.error` factories (the scope-denied path needs `isError`),
 *     rather than hand-assembled `Json`.
 *
 * TRANSPORT: this example is HTTP-only and stays on `runStreamableHttp`. OAuth
 * 2.1 resource-server protection (401 challenges, the RFC 9728 PRM document, RFC
 * 8707 audience binding) is inherently an HTTP concern, so there is no stdio mode
 * here — adding one would have nothing to demonstrate. The getopt surface is just
 * `--port` / `--host`; the client connects with `--url`.
 *
 *   dub build -c server
 *   ./auth-server --port 8742        # then run the client against it
 */
module auth_example_server;

import std.stdio : stderr, writefln;
import std.typecons : nullable;

import mcp;
import mcp.transport : StreamableHttpOptions, runStreamableHttp;
import mcp.auth : ResourceServerConfig, jwtVerifier, JwtVerifierConfig;

import examples_common : WhoamiResult, parseHttpServerArgs;

/// The canonical resource identifier (RFC 8707 audience) for the DEFAULT bind
/// (host 127.0.0.1, port 8742). When `--port`/`--host` change the listening
/// socket, `main` derives the live resource from the actual host/port instead so
/// the advertised/validated audience can never desync from where we listen.
enum Resource = "http://127.0.0.1:8742/mcp";

/// The token issuer this server trusts. The client mints tokens with this `iss`.
enum Issuer = "https://auth.example.com";

/// The AS signing public key, pinned directly (in production: discovered via
/// `JwtVerifierConfig.jwksUri`). The client signs tokens with the matching
/// private key (see PrivateKeyPem in client.d).
enum PublicKeyPem = "-----BEGIN PUBLIC KEY-----\n"
	~ "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETc1izuCa0VENxRMLhpxCpo3/A6k6\n"
	~ "Uyb2/iyjmioDCWYWx8Cp3defXx7Hl89WmW/0G66IVaqXTpmRM0AW36yqeg==\n"
	~ "-----END PUBLIC KEY-----\n";

/// The tools, declared in the ergonomic UDA style. Each `@tool` method takes a
/// `RequestContext ctx` (auto-injected by the reflection layer and omitted from
/// the inferred input schema) and reads the validated token via `ctx.auth()`.
final class AuthApi
{
@safe:

	/// `whoami` — returns the authenticated principal and the granted scopes, read
	/// straight from the validated token via `ctx.auth()`. Requires only the
	/// server-wide `mcp:read` scope. Returns a TYPED `WhoamiResult`, so the
	/// reflection layer fills in `structuredContent` (and the output schema) for
	/// us — we never touch `Json`.
	@tool("whoami", "Return the authenticated subject and granted scopes")
	WhoamiResult whoami(RequestContext ctx)
	{
		auto info = ctx.auth();
		return WhoamiResult(info.subject, info.scopes.dup);
	}

	/// `secret_note` — a privileged tool guarded by a FINER-GRAINED, per-tool scope
	/// check (`mcp:write`) on top of the server-wide `mcp:read`. The handler reads
	/// `ctx.auth().hasScope` and returns a tool error when the caller lacks the
	/// write scope, demonstrating in-handler authorization decisions. Returns a
	/// `CallToolResult` via the `text`/`error` factories.
	@tool("secret_note", "Return a secret note; requires the mcp:write scope")
	CallToolResult secretNote(RequestContext ctx)
	{
		auto info = ctx.auth();
		if (!info.hasScope("mcp:write"))
			return CallToolResult.error("forbidden: this tool requires the mcp:write scope");
		return CallToolResult.text("the launch code is 0000-MCP");
	}
}

void main(string[] args)
{
	import std.conv : to;

	// Parse the HTTP-only --port/--host surface via the shared scaffold; it also
	// folds the parsed host into opts.bindAddresses so the bind and the audience
	// we derive below stay in lockstep.
	StreamableHttpOptions opts;
	ushort port;
	string host;
	parseHttpServerArgs(args, 8742, opts, port, host);

	// Derive the resource identifier (RFC 8707 audience / RFC 9728 PRM `resource`)
	// from the ACTUAL bind host/port so the listening socket and the
	// advertised/validated audience can never diverge. A wildcard bind host is not
	// routable as an audience, so map it to a canonical loopback hostname.
	const audienceHost = (host == "0.0.0.0" || host == "::") ? "127.0.0.1" : host;
	const resource = "http://" ~ audienceHost ~ ":" ~ port.to!string ~ "/mcp";

	auto server = new McpServer("auth-example", "1.0.0",
			nullable("OAuth 2.1 protected MCP server (Streamable HTTP)."));

	// Register every @tool method of AuthApi (whoami, secret_note) in one call.
	registerHandlers(server, new AuthApi);

	// --- The single auth entry point: a JWT verifier feeding the resource
	// server config. Set the issuer/audience/required-scope here; the transport
	// does the rest (401/403/PRM/audience binding) automatically. ---
	JwtVerifierConfig jwt;
	jwt.staticPublicKeysPem = [PublicKeyPem];
	jwt.issuer = Issuer;
	jwt.audience = resource; // RFC 8707: tokens must be issued for us

	ResourceServerConfig auth;
	auth.validator = jwtVerifier(jwt);
	auth.resource = resource;
	auth.authorizationServers = [Issuer];
	auth.scopesSupported = ["mcp:read", "mcp:write"];
	auth.requiredScope = "mcp:read"; // every request needs at least mcp:read

	opts.auth = auth;

	() @trusted {
		stderr.writefln("auth-example server listening on http://%s:%d/mcp", host, port);
		stderr.writefln("  PRM: http://%s:%d/.well-known/oauth-protected-resource", host, port);
	}();
	runStreamableHttp(server, port, opts);
}
