/**
 * Authorization (OAuth 2.1) example — CLIENT side + self-verifying E2E test.
 *
 * Connects to the protected server (see server.d) over Streamable HTTP and
 * exercises every facet of the authorization flow from the consumer's eye,
 * ASSERTING concrete expected values at each step. On any mismatch it prints
 * what differed and exits NON-ZERO, so this doubles as an end-to-end regression
 * test.
 *
 * Scaffold (examples/common, #505): the event-loop plumbing and the assertion
 * primitives come from `examples_common` — `runClient` drives the vibe loop and
 * maps a thrown assertion to a non-zero exit, `check`/`checkEq` print a `FAIL:`
 * line and throw, and `connectFromArgs` selects the transport from argv. This
 * example is HTTP-only, so it is always invoked with `--url` (or the default);
 * there is no stdio/spawn sibling.
 *
 * TRANSPORT: HTTP only. OAuth 2.1 resource-server protection (401 challenges,
 * the RFC 9728 PRM document, RFC 8707 audience binding) is inherently an HTTP
 * concern, so there is no stdio mode. The endpoint is selected with `--url`
 * (default http://127.0.0.1:8742/mcp); `--port` / `--host` remain as a
 * convenience to build the default URL.
 *
 * What it verifies:
 *   1. First-contact (no token): HTTP 401 with a `WWW-Authenticate: Bearer`
 *      challenge carrying `resource_metadata=...` and `scope=...`.
 *   2. The advertised Protected Resource Metadata document (RFC 9728):
 *      `resource`, `authorization_servers`, `scopes_supported`.
 *   3. Happy path: a token obtained via the SDK OAuth client-credentials
 *      acquisition surface (#504) -> initialize succeeds, tools/list contains
 *      `whoami` + `secret_note`, `whoami` returns the token's subject + scopes
 *      in its TYPED structuredContent (inferred from the server's WhoamiResult
 *      struct), `secret_note` returns the privileged payload.
 *   4. Insufficient per-tool scope: a token with only `mcp:read` passes the
 *      server-wide gate but `secret_note` returns an isError tool result.
 *   5. Wrong audience (RFC 8707): a token for another resource -> request
 *      rejected (the high-level call throws).
 *   6. Missing server-wide scope: a token without `mcp:read` -> HTTP 403
 *      `insufficient_scope`.
 *
 * Tokens / acquisition (#504): in a real deployment the client would obtain a
 * token from the authorization server the resource server trusts. To keep this
 * example offline and self-contained, it stands up a tiny in-process
 * authorization-server token endpoint that mints ES256 JWTs with the private
 * key matching the server's pinned public key. The happy path then drives the
 * SDK's real acquisition surface — `OAuthClient.clientCredentials` — against
 * that endpoint and feeds the resulting `TokenSet.accessToken` to
 * `setBearerToken`, rather than ONLY hand-minting the JWT. The remaining
 * negative-path tokens (read-only, wrong-audience, missing-scope) are still
 * hand-minted directly, since they need bespoke claim sets.
 *
 * Run (two-step, mirrors CI):
 *   dub build -c server && dub build -c client
 *   ./auth-server --port 8742 &        # background
 *   sleep 1 ; ./auth-client --url http://127.0.0.1:8742/mcp ; echo "exit=$?"
 */
module auth_example_client;

import std.algorithm : canFind;
import std.conv : to;
import std.datetime.systime : Clock;
import std.getopt : getopt;
import std.string : indexOf;

import vibe.data.json : Json, parseJsonString;
import vibe.http.client : requestHTTP, HTTPClientRequest, HTTPClientResponse;
import vibe.http.common : HTTPMethod;
import vibe.http.server : HTTPServerSettings, HTTPServerRequest, HTTPServerResponse, listenHTTP;
import vibe.http.router : URLRouter;
import vibe.stream.operations : readAllUTF8;

import mcp;
import mcp.auth : signEs256, base64UrlNoPad, parseWwwAuthenticate, WwwAuthenticate, OAuthClient,
	ProtectedResourceMetadata, AuthorizationServerMetadata, RegisteredClient, TokenSet;

import examples_common : check, checkEq, runClient, connectFromArgs, WhoamiResult;

/// The PKCS#8 EC P-256 private key matching server.d's pinned PublicKeyPem.
/// In a real system this lives in the authorization server, never the client.
enum PrivateKeyPem = "-----BEGIN PRIVATE KEY-----\n"
	~ "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiWjpYwGBAi3P7/xX\n"
	~ "PdGy44hxiMGBFrj0BZPOG9uZCNuhRANCAARNzWLO4JrRUQ3FEwuGnEKmjf8DqTpT\n"
	~ "Jvb+LKOaKgMJZhbHwKnd159fHseXz1aZb/QbrohVqpdOmZEzQBbfrKp6\n" ~ "-----END PRIVATE KEY-----\n";

enum Issuer = "https://auth.example.com";

string serverUrl;
string baseOrigin;

int main(string[] args) @safe
{
	ushort port = 8742;
	string host = "127.0.0.1";
	string url;
	(() @trusted {
		getopt(args, "url|u",
			"Server MCP endpoint (default http://127.0.0.1:8742/mcp)", &url, "port|p",
			"Port (used to build the default URL)",
			&port, "host|h", "Host (used to build the default URL)", &host);
	})();

	if (url.length)
	{
		serverUrl = url;
		// The PRM probe and raw 401/403 checks hit the origin (no /mcp path),
		// so derive it by trimming a trailing "/mcp" if present.
		baseOrigin = url;
		const mcpSuffix = "/mcp";
		if (baseOrigin.length >= mcpSuffix.length && baseOrigin[$ - mcpSuffix.length .. $] == mcpSuffix)
			baseOrigin = baseOrigin[0 .. $ - mcpSuffix.length];
	}
	else
	{
		baseOrigin = "http://" ~ host ~ ":" ~ port.to!string;
		serverUrl = baseOrigin ~ "/mcp";
	}

	// `runClient` drives the vibe event loop and maps any thrown assertion to a
	// non-zero exit code, so the scenario below can stay straight-line.
	return runClient(() @safe => run());
}

/// Mint a signed ES256 JWT for the given subject/scope/audience, valid now.
string mintToken(string subject, string scope_, string audience) @safe
{
	const now = Clock.currTime.toUnixTime;
	const header = `{"alg":"ES256","typ":"JWT","kid":"as-1"}`;
	const payload = `{"iss":"` ~ Issuer ~ `","aud":"` ~ audience ~ `","sub":"` ~ subject
		~ `","scope":"` ~ scope_ ~ `","iat":` ~ (now - 10)
			.to!string ~ `,"nbf":` ~ (now - 10).to!string ~ `,"exp":` ~ (now + 3600)
			.to!string ~ `}`;
	const si = base64UrlNoPad(cast(const(ubyte)[]) header) ~ "." ~ base64UrlNoPad(
			cast(const(ubyte)[]) payload);
	auto sig = signEs256(PrivateKeyPem, cast(const(ubyte)[]) si);
	return si ~ "." ~ base64UrlNoPad(sig);
}

/// Stand up a tiny in-process OAuth authorization-server token endpoint and
/// return its URL. On any `POST` it mints a `mcp:read mcp:write` token bound to
/// `audience` (for subject `user-42`) and replies with the RFC 6749 token
/// response JSON. This stands in for the real AS so the happy path can drive the
/// SDK's `OAuthClient.clientCredentials` acquisition surface (#504) end to end
/// while staying offline.
string startTokenEndpoint(string audience) @trusted
{
	auto router = new URLRouter;
	router.post("/token", (scope HTTPServerRequest req, scope HTTPServerResponse res) {
		const tok = mintToken("user-42", "mcp:read mcp:write", audience);
		Json j = Json.emptyObject;
		j["access_token"] = tok;
		j["token_type"] = "Bearer";
		j["expires_in"] = 3600;
		j["scope"] = "mcp:read mcp:write";
		res.writeJsonBody(j);
	});
	auto settings = new HTTPServerSettings;
	settings.port = 0; // ephemeral: let the OS pick a free port
	settings.bindAddresses = ["127.0.0.1"];
	auto listener = listenHTTP(settings, router);
	const p = listener.bindAddresses[0].port;
	return "http://127.0.0.1:" ~ p.to!string ~ "/token";
}

int run() @safe
{
	// ---- 1. First contact with no token: 401 + WWW-Authenticate challenge ----
	//
	// HIGH-LEVEL PASS (SDK #471): drive first contact through the real OAuth
	// client surface. `OAuthClient.probeUnauthorized` POSTs an unauthenticated
	// initialize and hands back the `WWW-Authenticate` header; `parseWwwAuthenticate`
	// turns it into a typed `WwwAuthenticate{scheme, resourceMetadata, scope_}`.
	{
		auto oauth = new OAuthClient;
		oauth.resource = serverUrl;
		const wwwAuth = oauth.probeUnauthorized(serverUrl);
		check(wwwAuth.length > 0, "probeUnauthorized should surface a challenge header");
		const WwwAuthenticate w = parseWwwAuthenticate(wwwAuth);
		checkEq(w.scheme, "Bearer", "challenge scheme should be Bearer");
		check(w.resourceMetadata.length > 0, "challenge should carry resource_metadata: " ~ wwwAuth);
		checkEq(w.scope_, "mcp:read", "challenge scope hint");
	}

	// LOW-LEVEL PASS: assert the wire shape of the 401 challenge directly, so the
	// example still pins the exact header substrings the transport emits.
	{
		int status;
		string wwwAuth;
		() @trusted {
			requestHTTP(serverUrl, (scope HTTPClientRequest req) {
				req.method = HTTPMethod.POST;
				req.headers["Content-Type"] = "application/json";
				req.writeBody(cast(const(ubyte)[]) `{"jsonrpc":"2.0","id":1,"method":"ping"}`);
			}, (scope HTTPClientResponse res) {
				status = res.statusCode;
				wwwAuth = res.headers.get("WWW-Authenticate", "");
				res.bodyReader.readAllUTF8();
			});
		}();
		checkEq(status, 401, "no-token POST status");
		check(wwwAuth.indexOf("Bearer") >= 0, "challenge should be a Bearer scheme: " ~ wwwAuth);
		check(wwwAuth.indexOf("resource_metadata=") >= 0,
				"challenge should carry resource_metadata: " ~ wwwAuth);
		check(wwwAuth.indexOf(`scope="mcp:read"`) >= 0,
				"challenge should carry the scope hint: " ~ wwwAuth);
	}

	// ---- 2. The Protected Resource Metadata document (RFC 9728) ----
	//
	// HIGH-LEVEL PASS (SDK #471): `OAuthClient.discoverProtectedResource` follows
	// the `resource_metadata` URL from the challenge (or the well-known fallbacks)
	// and returns a typed `ProtectedResourceMetadata`, so we assert on its fields
	// rather than re-parsing the JSON document by hand.
	{
		auto oauth = new OAuthClient;
		oauth.resource = serverUrl;
		const wwwAuth = oauth.probeUnauthorized(serverUrl);
		const ProtectedResourceMetadata prm = oauth.discoverProtectedResource(serverUrl, wwwAuth);
		checkEq(prm.resource, serverUrl, "PRM resource");
		check(prm.authorizationServers.length >= 1
				&& prm.authorizationServers[0] == Issuer, "PRM authorization_servers mismatch");
		checkEq(prm.scopesSupported, ["mcp:read", "mcp:write"], "PRM scopes_supported");
	}

	// LOW-LEVEL PASS: fetch the well-known document directly and assert its raw
	// wire shape, pinning what the transport publishes at the PRM URL.
	{
		int status;
		string body_;
		() @trusted {
			requestHTTP(baseOrigin ~ "/.well-known/oauth-protected-resource",
					(scope HTTPClientRequest req) { req.method = HTTPMethod.GET; },
					(scope HTTPClientResponse res) {
				status = res.statusCode;
				body_ = res.bodyReader.readAllUTF8();
			});
		}();
		checkEq(status, 200, "PRM document status");
		auto prm = () @trusted { return parseJsonString(body_); }();
		checkEq(() @trusted { return prm["resource"].get!string; }(),
				serverUrl, "PRM resource (raw)");
		checkEq(() @trusted { return prm["authorization_servers"][0].get!string; }(),
				Issuer, "PRM authorization_servers (raw)");
		auto scopes = () @trusted { return prm["scopes_supported"]; }();
		check(() @trusted {
			return scopes[0].get!string == "mcp:read" && scopes[1].get!string == "mcp:write";
		}(), "PRM scopes_supported mismatch (raw)");
	}

	// ---- 3. Happy path: full-scope token, initialize + tools ----
	//
	// ACQUISITION (#504): obtain the bearer token through the SDK's OAuth client
	// surface rather than hand-minting it inline. A tiny in-process token endpoint
	// (the throwaway AS) issues a `mcp:read mcp:write` JWT; `clientCredentials` is
	// the cleanest automated grant, so we POST to it and feed the returned
	// `TokenSet.accessToken` to `setBearerToken`.
	{
		const tokenUrl = () @trusted { return startTokenEndpoint(serverUrl); }();
		auto oauth = new OAuthClient;
		oauth.resource = serverUrl;
		AuthorizationServerMetadata as_;
		as_.issuer = Issuer;
		as_.tokenEndpoint = tokenUrl;
		const TokenSet ts = oauth.clientCredentials(as_,
				RegisteredClient("auth-example-client", ""), "mcp:read mcp:write");
		check(ts.accessToken.length > 0, "clientCredentials should yield an access token");

		auto client = connectFromArgs(["client", "--url", serverUrl], "auth-server");
		scope (exit)
			client.close();
		client.setBearerToken(ts.accessToken);
		client.initialize();

		auto tools = client.listTools().tools;
		bool haveWhoami, haveSecret;
		foreach (t; tools)
		{
			if (t.name == "whoami")
				haveWhoami = true;
			if (t.name == "secret_note")
				haveSecret = true;
		}
		check(haveWhoami, "tools/list should contain whoami");
		check(haveSecret, "tools/list should contain secret_note");

		auto who = client.callTool("whoami", Json.emptyObject);
		check(!who.isError, "whoami should not be a tool error");
		// `whoami` returns the typed WhoamiResult struct on the server, so the SDK
		// infers structuredContent for us. Decode it back into a typed struct with
		// `structuredContentAs!WhoamiResult` (SDK #464) and assert on real fields
		// instead of reading raw structuredContent["..."] Json.
		const WhoamiResult info = who.structuredContentAs!WhoamiResult;
		checkEq(info.subject, "user-42", "whoami subject");
		checkEq(info.scopes, ["mcp:read", "mcp:write"], "whoami scopes");
		// The reflection layer also mirrors the struct as a JSON text block.
		check(who.content.length == 1 && who.content[0].text.indexOf(`"subject":"user-42"`) >= 0,
				"whoami text should mirror the structured subject, got: " ~ (who.content.length
					? who.content[0].text : "<none>"));

		auto secret = client.callTool("secret_note", Json.emptyObject);
		check(!secret.isError, "secret_note with mcp:write should succeed");
		check(secret.content.length == 1 && secret.content[0].text.indexOf("0000-MCP") >= 0,
				"secret_note should return the privileged payload");
	}

	// ---- 4. Insufficient per-tool scope: read-only token ----
	{
		auto client = McpClient.http(serverUrl);
		scope (exit)
			client.close();
		client.setBearerToken(mintToken("reader", "mcp:read", serverUrl));
		client.initialize();

		auto who = client.callTool("whoami", Json.emptyObject);
		check(!who.isError, "whoami should still work for a read-only token");
		const WhoamiResult info = who.structuredContentAs!WhoamiResult;
		checkEq(info.subject, "reader", "read-only whoami subject");
		checkEq(info.scopes, ["mcp:read"], "read-only whoami scopes");

		auto secret = client.callTool("secret_note", Json.emptyObject);
		check(secret.isError, "secret_note must be a tool error for a token lacking mcp:write");
		check(secret.content.length == 1 && secret.content[0].text.indexOf("mcp:write") >= 0,
				"secret_note error should mention the missing scope");
	}

	// ---- 5. Wrong audience (RFC 8707): token for a different resource ----
	{
		auto client = McpClient.http(serverUrl);
		scope (exit)
			client.close();
		client.setBearerToken(mintToken("user-42", "mcp:read mcp:write",
				"https://other.example.com/mcp"));
		bool rejected = false;
		try
			client.initialize();
		catch (Exception)
			rejected = true;
		check(rejected, "a token for the wrong audience must be rejected (RFC 8707)");
	}

	// ---- 6. Missing the server-wide scope: HTTP 403 insufficient_scope ----
	{
		const tok = mintToken("user-42", "some:other", serverUrl);
		int status;
		string wwwAuth;
		() @trusted {
			requestHTTP(serverUrl, (scope HTTPClientRequest req) {
				req.method = HTTPMethod.POST;
				req.headers["Content-Type"] = "application/json";
				req.headers["Authorization"] = "Bearer " ~ tok;
				req.writeBody(cast(const(ubyte)[]) `{"jsonrpc":"2.0","id":1,"method":"ping"}`);
			}, (scope HTTPClientResponse res) {
				status = res.statusCode;
				wwwAuth = res.headers.get("WWW-Authenticate", "");
				res.bodyReader.readAllUTF8();
			});
		}();
		checkEq(status, 403, "missing-scope token status");
		check(wwwAuth.indexOf(`error="insufficient_scope"`) >= 0,
				"403 challenge should carry insufficient_scope: " ~ wwwAuth);
	}

	() @trusted {
		import std.stdio : writeln;

		writeln(
				"OK: 401+WWW-Authenticate, PRM doc, SDK clientCredentials acquisition, full-scope "
				~ "tools (typed whoami structuredContent + secret_note), per-tool scope enforcement, "
				~ "RFC 8707 audience binding, and 403 insufficient_scope all verified.");
	}();
	return 0;
}
