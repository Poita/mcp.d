/**
 * Authorization (OAuth 2.1) example — CLIENT side + self-verifying E2E test.
 *
 * Connects to the protected server (see server.d) and exercises every facet of
 * the authorization flow from the consumer's eye, ASSERTING concrete expected
 * values at each step. On any mismatch it prints what differed and exits
 * NON-ZERO, so this doubles as an end-to-end regression test.
 *
 * What it verifies:
 *   1. First-contact (no token): HTTP 401 with a `WWW-Authenticate: Bearer`
 *      challenge carrying `resource_metadata=...` and `scope=...`.
 *   2. The advertised Protected Resource Metadata document (RFC 9728):
 *      `resource`, `authorization_servers`, `scopes_supported`.
 *   3. Happy path: a JWT with `mcp:read mcp:write` -> initialize succeeds,
 *      tools/list contains `whoami` + `secret_note`, `whoami` returns the
 *      token's subject, `secret_note` returns the privileged payload.
 *   4. Insufficient per-tool scope: a token with only `mcp:read` passes the
 *      server-wide gate but `secret_note` returns an isError tool result.
 *   5. Wrong audience (RFC 8707): a token for another resource -> request
 *      rejected (the high-level call throws).
 *   6. Missing server-wide scope: a token without `mcp:read` -> HTTP 403
 *      `insufficient_scope`.
 *
 * The client mints its own JWTs with the private key matching the server's
 * pinned public key — standing in for an OAuth authorization server.
 *
 * Run (two-step, mirrors CI):
 *   dub build -c server && dub build -c client
 *   ./auth-server --port 8742 &        # background
 *   sleep 1 ; ./auth-client ; echo "exit=$?"
 */
module auth_example_client;

import core.stdc.stdlib : exit;
import std.algorithm : canFind;
import std.conv : to;
import std.datetime.systime : Clock;
import std.getopt : getopt;
import std.stdio : stderr, writeln;
import std.string : indexOf;

import vibe.core.core : runTask, runEventLoop, exitEventLoop;
import vibe.data.json : Json, parseJsonString;
import vibe.http.client : requestHTTP, HTTPClientRequest, HTTPClientResponse;
import vibe.http.common : HTTPMethod;
import vibe.stream.operations : readAllUTF8;

import mcp;
import mcp.auth : signEs256, base64UrlNoPad;

/// The PKCS#8 EC P-256 private key matching server.d's pinned PublicKeyPem.
/// In a real system this lives in the authorization server, never the client.
enum PrivateKeyPem = "-----BEGIN PRIVATE KEY-----\n"
	~ "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgiWjpYwGBAi3P7/xX\n"
	~ "PdGy44hxiMGBFrj0BZPOG9uZCNuhRANCAARNzWLO4JrRUQ3FEwuGnEKmjf8DqTpT\n"
	~ "Jvb+LKOaKgMJZhbHwKnd159fHseXz1aZb/QbrohVqpdOmZEzQBbfrKp6\n"
	~ "-----END PRIVATE KEY-----\n";

enum Issuer = "https://auth.example.com";

string serverUrl;
string baseOrigin;

void main(string[] args)
{
	ushort port = 8742;
	string host = "127.0.0.1";
	getopt(args, "port|p", &port, "host|h", &host);
	baseOrigin = "http://" ~ host ~ ":" ~ port.to!string;
	serverUrl = baseOrigin ~ "/mcp";

	int rc = 1;
	runTask(() nothrow{
		scope (exit)
			exitEventLoop();
		try
			rc = run();
		catch (Exception e)
		{
			try
				stderr.writeln("FAIL: ", e.msg);
			catch (Exception)
			{
			}
			rc = 1;
		}
	});
	runEventLoop();
	if (rc != 0)
		exit(rc);
}

/// Mint a signed ES256 JWT for the given subject/scope/audience, valid now.
string mintToken(string subject, string scope_, string audience) @safe
{
	const now = Clock.currTime.toUnixTime;
	const header = `{"alg":"ES256","typ":"JWT","kid":"as-1"}`;
	const payload = `{"iss":"` ~ Issuer ~ `","aud":"` ~ audience ~ `","sub":"` ~ subject
		~ `","scope":"` ~ scope_ ~ `","iat":` ~ (now - 10).to!string ~ `,"nbf":`
		~ (now - 10).to!string ~ `,"exp":` ~ (now + 3600).to!string ~ `}`;
	const si = base64UrlNoPad(cast(const(ubyte)[]) header) ~ "."
		~ base64UrlNoPad(cast(const(ubyte)[]) payload);
	auto sig = signEs256(PrivateKeyPem, cast(const(ubyte)[]) si);
	return si ~ "." ~ base64UrlNoPad(sig);
}

/// A small assertion helper that records the first failure and aborts.
void check(bool cond, string what) @safe
{
	if (!cond)
	{
		() @trusted { stderr.writeln("FAIL: ", what); }();
		throw new Exception("assertion failed: " ~ what);
	}
}

int run()
{
	// ---- 1. First contact with no token: 401 + WWW-Authenticate challenge ----
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
		check(status == 401, "no-token POST should be 401, got " ~ status.to!string);
		check(wwwAuth.indexOf("Bearer") >= 0, "challenge should be a Bearer scheme: " ~ wwwAuth);
		check(wwwAuth.indexOf("resource_metadata=") >= 0,
				"challenge should carry resource_metadata: " ~ wwwAuth);
		check(wwwAuth.indexOf(`scope="mcp:read"`) >= 0,
				"challenge should carry the scope hint: " ~ wwwAuth);
	}

	// ---- 2. The Protected Resource Metadata document (RFC 9728) ----
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
		check(status == 200, "PRM should be served 200, got " ~ status.to!string);
		auto prm = () @trusted { return parseJsonString(body_); }();
		check(prm["resource"].get!string == serverUrl,
				"PRM resource mismatch: " ~ prm["resource"].get!string);
		check(prm["authorization_servers"][0].get!string == Issuer,
				"PRM authorization_servers mismatch");
		auto scopes = () @trusted { return prm["scopes_supported"]; }();
		check(scopes[0].get!string == "mcp:read" && scopes[1].get!string == "mcp:write",
				"PRM scopes_supported mismatch");
	}

	// ---- 3. Happy path: full-scope token, initialize + tools ----
	{
		auto client = McpClient.http(serverUrl);
		scope (exit)
			client.close();
		client.setBearerToken(mintToken("user-42", "mcp:read mcp:write", serverUrl));
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
		check(!isToolError(who), "whoami should not be a tool error");
		check(who.content.length == 1 && who.content[0].text.indexOf("subject=user-42") >= 0,
				"whoami text should name the subject, got: "
				~ (who.content.length ? who.content[0].text : "<none>"));
		check(who.structuredContent["subject"].get!string == "user-42",
				"whoami structuredContent.subject mismatch");

		auto secret = client.callTool("secret_note", Json.emptyObject);
		check(!isToolError(secret), "secret_note with mcp:write should succeed");
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
		check(!isToolError(who), "whoami should still work for a read-only token");

		auto secret = client.callTool("secret_note", Json.emptyObject);
		check(isToolError(secret),
				"secret_note must be a tool error for a token lacking mcp:write");
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
		check(status == 403,
				"a token missing mcp:read should be 403 insufficient_scope, got " ~ status.to!string);
		check(wwwAuth.indexOf(`error="insufficient_scope"`) >= 0,
				"403 challenge should carry insufficient_scope: " ~ wwwAuth);
	}

	writeln("OK: 401+WWW-Authenticate, PRM doc, full-scope tools (whoami/secret_note), "
			~ "per-tool scope enforcement, RFC 8707 audience binding, and 403 insufficient_scope "
			~ "all verified.");
	return 0;
}

/// Whether a CallToolResult is flagged as a tool error.
bool isToolError(ref CallToolResult r) @safe
{
	return r.isError;
}
