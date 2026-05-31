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
 * `ctx.auth()` and returns a `CallToolResult` so the example can shape its exact
 * text content and structured payload.
 *
 * In a real deployment the verification key comes from your authorization
 * server's JWKS (`JwtVerifierConfig.jwksUri`). To keep this example
 * self-contained and offline, we pin the AS's public key directly via
 * `staticPublicKeysPem` — the client mints a token with the matching private
 * key, simulating what the AS would issue.
 *
 *   dub build -c server
 *   ./auth-server --port 8742        # then run the client against it
 */
module auth_example_server;

import std.getopt : getopt;
import std.stdio : stderr, writefln;
import std.typecons : nullable;

import vibe.data.json : Json;

import mcp;
import mcp.transport : StreamableHttpOptions, runStreamableHttp;
import mcp.auth : ResourceServerConfig, jwtVerifier, JwtVerifierConfig;

/// The canonical resource identifier (RFC 8707 audience) for this server. The
/// client must mint tokens whose `aud` names exactly this value.
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
	/// server-wide `mcp:read` scope. Returns a `CallToolResult` so the human-
	/// readable text line and the structured payload are shaped exactly.
	@tool("whoami", "Return the authenticated subject and granted scopes")
	CallToolResult whoami(RequestContext ctx)
	{
		import std.array : join;

		auto info = ctx.auth();
		Json structured = Json.emptyObject;
		structured["subject"] = info.subject;
		Json scopes = Json.emptyArray;
		foreach (s; info.scopes)
			scopes ~= Json(s);
		structured["scopes"] = scopes;

		CallToolResult r;
		r.content = [
			Content.makeText("subject=" ~ info.subject ~ " scopes=" ~ info.scopes.join(" "))
		];
		r.structuredContent = structured;
		return r;
	}

	/// `secret_note` — a privileged tool guarded by a FINER-GRAINED, per-tool scope
	/// check (`mcp:write`) on top of the server-wide `mcp:read`. The handler reads
	/// `ctx.auth().hasScope` and returns a tool error when the caller lacks the
	/// write scope, demonstrating in-handler authorization decisions.
	@tool("secret_note", "Return a secret note; requires the mcp:write scope")
	CallToolResult secretNote(RequestContext ctx)
	{
		auto info = ctx.auth();
		CallToolResult r;
		if (!info.hasScope("mcp:write"))
		{
			r.content = [
				Content.makeText("forbidden: this tool requires the mcp:write scope")
			];
			r.isError = true;
			return r;
		}
		r.content = [Content.makeText("the launch code is 0000-MCP")];
		return r;
	}
}

void main(string[] args)
{
	ushort port = 8742;
	string host = "127.0.0.1";
	getopt(args, "port|p", "Port to listen on (default 8742)", &port,
			"host|h", "Address to bind (default 127.0.0.1)", &host);

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
	jwt.audience = Resource; // RFC 8707: tokens must be issued for us

	ResourceServerConfig auth;
	auth.validator = jwtVerifier(jwt);
	auth.resource = Resource;
	auth.authorizationServers = [Issuer];
	auth.scopesSupported = ["mcp:read", "mcp:write"];
	auth.requiredScope = "mcp:read"; // every request needs at least mcp:read

	StreamableHttpOptions opts;
	opts.bindAddresses = [host];
	opts.auth = auth;

	() @trusted {
		stderr.writefln("auth-example server listening on http://%s:%d/mcp", host, port);
		stderr.writefln("  PRM: http://%s:%d/.well-known/oauth-protected-resource", host, port);
	}();
	runStreamableHttp(server, port, opts);
}
