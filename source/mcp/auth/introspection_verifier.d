/// A ready-made opaque-token verifier that validates bearer tokens via OAuth 2.0
/// Token Introspection (RFC 7662), so MCP server authors don't have to hand-roll
/// the introspection request, response parsing, and claim checks. It is the D
/// analogue of FastMCP's `IntrospectionTokenVerifier`.
///
/// The verifier POSTs the presented token to the authorization server's
/// introspection endpoint (authenticating as a resource server with
/// `client_secret_basic` or `client_secret_post`), then maps the RFC 7662
/// response to a `TokenInfo`: `active:false` (or a 4xx answer or parse error)
/// yields an invalid result, an unreachable endpoint or a 429/5xx answer yields
/// `TokenInfo.temporarilyUnavailable`, and `active:true` yields a valid
/// `TokenInfo` with `scope`, `sub`, and `aud` mapped across, after enforcing the
/// configured audience and required scopes. Concurrent introspections of one
/// token are coalesced, rejections are briefly cached, and positive results may
/// be cached on request.
module mcp.auth.introspection_verifier;

import core.time : Duration, seconds;

import std.algorithm : canFind;

import vibe.data.json : Json, parseJsonString;

import mcp.auth.jwt_verifier : audiences, includesAudience, jsonStr, splitScopes;
import mcp.auth.oauth : TokenEndpointAuthMethod, basicAuthHeader, secureRequestHTTP;
import mcp.auth.resource_server : TokenInfo, TokenValidator,
	TokenVerifierUnavailableException, isSsrfRefusal, isUnavailableStatus, parseRetryAfter;
import mcp.auth.token_cache : TokenCache, TokenCacheOptions;
import mcp.protocol.jsonrpc : parseUntrustedJson;
import mcp.protocol.ssrf : SsrfPolicy;

@safe:

/// Configuration for `introspectionVerifier`.
struct IntrospectionConfig
{
	/// The authorization server's RFC 7662 introspection endpoint (POSTed to).
	string introspectionEndpoint;

	/// The resource server's client identifier registered at the AS, used to
	/// authenticate the introspection request.
	string clientId;

	/// The resource server's client secret at the AS.
	string clientSecret;

	/// How the resource server authenticates at the introspection endpoint:
	/// `clientSecretBasic` (HTTP Basic, the default) or `clientSecretPost`
	/// (credentials in the form body).
	TokenEndpointAuthMethod authMethod = TokenEndpointAuthMethod.clientSecretBasic;

	/// The required audience (the RFC 8707 resource). When set, a token whose
	/// introspection response does not list it among its audiences is rejected.
	string audience;

	/// Scopes the token must carry. All must be present in the introspection
	/// response `scope` for the token to be accepted. A token missing one is
	/// rejected as invalid (401 `invalid_token`); to answer with 403
	/// `insufficient_scope` so the client can step up, require the scopes via
	/// `ResourceServerConfig.requiredScopes` instead.
	string[] requiredScopes;

	/// How introspection results are reused. Concurrent introspections of the
	/// same token always share one request. Rejections are cached for
	/// `cache.negativeTtl` (10 seconds by default). Positive (`active:true`)
	/// results are not cached by default (`cache.ttl` is zero): revocation that
	/// takes effect at once is the usual reason to introspect rather than verify
	/// a JWT locally, and a positive cache would serve a revoked token as valid
	/// until its entry expires. Set `cache.ttl` to trade that latency for fewer
	/// requests; an entry's expiry is clamped to the token's `exp` (RFC 7662), so
	/// it never outlives the token itself.
	TokenCacheOptions cache = TokenCacheOptions(Duration.zero);

	/// The SSRF policy applied to the introspection request. The default
	/// requires `https` to a public host (plain `http` only to loopback); an AS
	/// on a private network needs `SsrfPolicy.allowUserConfigured`.
	SsrfPolicy ssrfPolicy = SsrfPolicy.allowLoopback;
}

// ===========================================================================
// Public entry point
// ===========================================================================

/// Build a `TokenValidator` from `cfg`. The returned delegate introspects a
/// bearer token at the configured endpoint and yields a `TokenInfo`
/// (`valid == false` on `active:false`, HTTP failure, or parse error). Plug it
/// into `ResourceServerConfig.validator`.
///
/// Concurrency: the returned validator and its internal `TokenCache` hold
/// unsynchronized mutable state (the cached results and in-flight lookups).
/// Like the rest of the SDK they are bound to vibe.d's default single-threaded
/// event loop. Do not share the validator across worker threads; running the
/// router with `HTTPServerOption.distribute` or worker threads is unsupported
/// (see the concurrency contract in `mcp.transport.session`).
///
/// Throws when `cfg` names no introspection endpoint or client id, or an
/// `authMethod` other than `clientSecretBasic`/`clientSecretPost`: RFC 7662
/// requires the resource server to authenticate, and no other method is
/// implemented here.
TokenValidator introspectionVerifier(IntrospectionConfig cfg) @safe
{
	import std.exception : enforce;

	enforce(cfg.introspectionEndpoint.length > 0,
			"introspectionVerifier: introspectionEndpoint must be set.");
	enforce(cfg.clientId.length > 0, "introspectionVerifier: clientId must be set.");
	enforce(cfg.authMethod == TokenEndpointAuthMethod.clientSecretBasic
			|| cfg.authMethod == TokenEndpointAuthMethod.clientSecretPost,
			"introspectionVerifier: authMethod must be clientSecretBasic or clientSecretPost.");
	return introspectionValidator(cfg, new HttpIntrospector(cfg));
}

/// `introspectionVerifier` over an arbitrary `Introspector`, so the validation
/// path can be driven without HTTP. A failed introspection call is logged and
/// rejects the token.
package TokenValidator introspectionValidator(IntrospectionConfig cfg, Introspector introspector) @safe
{
	auto cache = new TokenCache(cfg.cache);
	return (string token) @safe {
		if (token.length == 0)
			return TokenInfo.invalid();
		return cache.lookup(token, () @safe => introspectOnce(cfg, introspector, token));
	};
}

/// Introspect `token` once and map the answer, logging a failed call.
private TokenInfo introspectOnce(IntrospectionConfig cfg, Introspector introspector, string token) @safe
{
	TokenInfo ti;
	try
	{
		const doc = introspector.introspect(token);
		ti = introspectionResult(cfg, doc);
	}
	catch (TokenVerifierUnavailableException e)
	{
		import vibe.core.log : logWarn;

		logWarn("Token introspection at %s is unavailable: %s", cfg.introspectionEndpoint, e.msg);
		return TokenInfo.temporarilyUnavailable(e.retryAfter);
	}
	catch (Exception e)
	{
		import vibe.core.log : logWarn;

		logWarn("Token introspection at %s failed; rejecting the token: %s",
				cfg.introspectionEndpoint, e.msg);
		return TokenInfo.invalid();
	}
	return ti;
}

// ===========================================================================
// Response mapping (pure of HTTP / clock; unit-testable)
// ===========================================================================

/// A source of introspection responses for a token. Separated from HTTP so
/// tests can drive verification against a stub endpoint.
interface Introspector
{
	/// Return the raw RFC 7662 introspection response JSON for `token`. Throws
	/// `TokenVerifierUnavailableException` when the endpoint is unreachable or
	/// answers 429/5xx, so the request gets 503 rather than 401.
	string introspect(string token) @safe;
}

/// Whether an introspection `token_type` names a refresh token (`refresh_token`,
/// or the `Refresh` some servers report).
private bool isRefreshTokenType(string tokenType) @safe
{
	import std.uni : sicmp;

	return sicmp(tokenType, "refresh_token") == 0 || sicmp(tokenType, "refresh") == 0;
}

/// Map a raw RFC 7662 introspection response document to a `TokenInfo`, applying
/// the `cfg` audience and required-scope checks. `active:false`, a non-object
/// response, a missing/false `active` member, or a `token_type` naming a
/// refresh token yields an invalid result.
TokenInfo introspectionResult(IntrospectionConfig cfg, string responseJson) @safe
{
	Json doc;
	try
		doc = parseUntrustedJson(responseJson);
	catch (Exception e)
	{
		import vibe.core.log : logWarn;

		logWarn("Token introspection returned a malformed response; rejecting the token: %s", e.msg);
		return TokenInfo.invalid();
	}

	if (doc.type != Json.Type.object)
		return TokenInfo.invalid();

	auto active = doc["active"];
	if (active.type != Json.Type.bool_ || !active.get!bool)
		return TokenInfo.invalid();

	// The hint is advisory: an AS may still describe a refresh token presented
	// as a bearer, which must never authorize a request.
	if (isRefreshTokenType(jsonStr(doc, "token_type")))
		return TokenInfo.invalid();

	auto auds = audiences(doc);
	if (cfg.audience.length && !includesAudience(auds, cfg.audience))
		return TokenInfo.invalid();

	auto scopes = introspectionScopes(doc);
	foreach (req; cfg.requiredScopes)
		if (!scopes.canFind(req))
			return TokenInfo.invalid();

	TokenInfo ti;
	ti.valid = true;
	ti.subject = jsonStr(doc, "sub");
	ti.scopes = scopes;
	ti.audience = auds;
	ti.claims = doc;
	return ti;
}

// ===========================================================================
// HTTP introspection
// ===========================================================================

/// The default `Introspector`: POSTs an RFC 7662 introspection request to the
/// configured endpoint with the resource server's client authentication.
final class HttpIntrospector : Introspector
{
	private IntrospectionConfig cfg;

	this(IntrospectionConfig cfg) @safe
	{
		this.cfg = cfg;
	}

	string introspect(string token) @safe
	{
		return postIntrospect(cfg, token);
	}
}

/// Build the form body for an introspection request (RFC 7662 2.1). A bearer
/// is always an access token, so the request carries
/// `token_type_hint=access_token`. For `client_secret_post`, the client
/// credentials are appended to the body.
string introspectionBody(IntrospectionConfig cfg, string token) @safe
{
	import std.uri : encodeComponent;

	string body_ = "token=" ~ encodeComponent(token) ~ "&token_type_hint=access_token";
	if (cfg.authMethod == TokenEndpointAuthMethod.clientSecretPost)
	{
		body_ ~= "&client_id=" ~ encodeComponent(cfg.clientId);
		body_ ~= "&client_secret=" ~ encodeComponent(cfg.clientSecret);
	}
	return body_;
}

private string postIntrospect(IntrospectionConfig cfg, string token) @safe
{
	import vibe.http.client : HTTPClientRequest, HTTPClientResponse;
	import vibe.http.common : HTTPMethod;
	import vibe.stream.operations : readAllUTF8;

	// The connect is pinned to a pre-vetted resolved address (DNS-rebinding
	// mitigation); secureRequestHTTP throws on a host `cfg.ssrfPolicy` rejects.
	const body_ = introspectionBody(cfg, token);
	string responseBody;
	int status;
	Duration retryAfter;
	try
		secureRequestHTTP(cfg.introspectionEndpoint, cfg.ssrfPolicy, (scope HTTPClientRequest req) {
			req.method = HTTPMethod.POST;
			req.headers["Content-Type"] = "application/x-www-form-urlencoded";
			req.headers["Accept"] = "application/json";
			if (cfg.authMethod == TokenEndpointAuthMethod.clientSecretBasic)
				req.headers["Authorization"] = basicAuthHeader(cfg.clientId, cfg.clientSecret);
			req.writeBody(cast(const(ubyte)[]) body_);
		}, (scope HTTPClientResponse res) {
			status = res.statusCode;
			retryAfter = parseRetryAfter(res.headers.get("Retry-After", ""));
			if (status >= 200 && status < 300)
				responseBody = res.bodyReader.readAllUTF8(false, maxIntrospectionBodyBytes);
			else
				res.dropBody();
		});
	catch (Exception e)
	{
		if (isSsrfRefusal(e))
			throw e;
		throw new TokenVerifierUnavailableException("introspection endpoint unreachable: " ~ e.msg);
	}
	if (status < 200 || status >= 300)
	{
		import std.format : format;

		const msg = format("introspection endpoint returned HTTP %d", status);
		if (isUnavailableStatus(status))
			throw new TokenVerifierUnavailableException(msg, retryAfter);
		throw new Exception(msg);
	}
	return responseBody;
}

// Maximum bytes accepted from an introspection endpoint response body.
// RFC 7662 responses are tiny JSON objects; this cap prevents a hostile or
// misconfigured endpoint from exhausting heap memory by streaming an
// arbitrarily large body.
package enum size_t maxIntrospectionBodyBytes = 256 * 1024;

// ===========================================================================
// Small helpers
// ===========================================================================

/// Extract granted scopes from an introspection response: `scope` is a
/// space-delimited string (RFC 7662 2.2).
string[] introspectionScopes(Json doc) @safe
{
	auto scope_ = doc["scope"];
	if (scope_.type == Json.Type.string)
		return splitScopes(scope_.get!string);
	return null;
}

// ===========================================================================
// Tests
// ===========================================================================

version (unittest)
{
	// A stub Introspector returning a canned response document.
	private final class StubIntrospector : Introspector
	{
		string response;
		string lastToken;
		bool wasCalled; // true if introspect was ever invoked
		this(string response) @safe
		{
			this.response = response;
		}

		string introspect(string token) @safe
		{
			wasCalled = true;
			lastToken = token;
			return response;
		}
	}

	// Build a TokenValidator over a stub introspector through the production
	// wiring, minus the real HTTP.
	private TokenValidator stubVerifier(IntrospectionConfig cfg, Introspector introspector) @safe
	{
		return introspectionValidator(cfg, introspector);
	}
}

unittest  // active:true maps scope/sub/aud into a valid TokenInfo
{
	IntrospectionConfig cfg;
	auto ti = introspectionResult(cfg, `{"active":true,"sub":"user-7","scope":"mcp:read mcp:write","aud":"https://mcp.example.com/mcp","client_id":"rs"}`);
	assert(ti.valid);
	assert(ti.subject == "user-7");
	assert(ti.scopes == ["mcp:read", "mcp:write"]);
	assert(ti.audience == ["https://mcp.example.com/mcp"]);
}

unittest  // active:false yields an invalid TokenInfo
{
	IntrospectionConfig cfg;
	auto ti = introspectionResult(cfg, `{"active":false}`);
	assert(!ti.valid);
}

unittest  // a missing active member is treated as inactive
{
	IntrospectionConfig cfg;
	auto ti = introspectionResult(cfg, `{"sub":"x","scope":"mcp:read"}`);
	assert(!ti.valid);
}

unittest  // a non-object / malformed response is invalid
{
	IntrospectionConfig cfg;
	assert(!introspectionResult(cfg, `"nope"`).valid);
	assert(!introspectionResult(cfg, `not json at all`).valid);
}

unittest  // a response nested past the depth cap is invalid
{
	import std.array : replicate;

	IntrospectionConfig cfg;
	const deep = "[".replicate(1000) ~ "]".replicate(1000);
	assert(!introspectionResult(cfg, `{"active":true,"sub":"u","x":` ~ deep ~ `}`).valid);
}

unittest  // aud may be an array of strings
{
	IntrospectionConfig cfg;
	auto ti = introspectionResult(cfg,
			`{"active":true,"aud":["https://a.example.com","https://b.example.com"]}`);
	assert(ti.valid);
	assert(ti.audience == ["https://a.example.com", "https://b.example.com"]);
}

unittest  // a configured audience must appear among the token's audiences
{
	IntrospectionConfig cfg;
	cfg.audience = "https://mcp.example.com/mcp";
	auto ti = introspectionResult(cfg, `{"active":true,"aud":"https://other.example.com"}`);
	assert(!ti.valid);
}

unittest  // a matching audience is accepted
{
	IntrospectionConfig cfg;
	cfg.audience = "https://mcp.example.com/mcp";
	auto ti = introspectionResult(cfg, `{"active":true,"aud":["https://mcp.example.com/mcp"]}`);
	assert(ti.valid);
}

unittest  // the configured audience is compared in canonical form
{
	IntrospectionConfig cfg;
	cfg.audience = "https://MCP.example.com/mcp/";
	assert(introspectionResult(cfg, `{"active":true,"aud":"https://mcp.example.com/mcp"}`).valid);
	assert(!introspectionResult(cfg,
			`{"active":true,"aud":"https://mcp.example.com/other"}`).valid);
}

unittest  // a missing required scope is rejected
{
	IntrospectionConfig cfg;
	cfg.requiredScopes = ["mcp:admin"];
	auto ti = introspectionResult(cfg, `{"active":true,"scope":"mcp:read mcp:write"}`);
	assert(!ti.valid);
}

unittest  // all required scopes present is accepted
{
	IntrospectionConfig cfg;
	cfg.requiredScopes = ["mcp:read", "mcp:write"];
	auto ti = introspectionResult(cfg, `{"active":true,"scope":"mcp:read mcp:write mcp:admin"}`);
	assert(ti.valid);
}

unittest  // an empty scope string yields no scopes
{
	IntrospectionConfig cfg;
	auto ti = introspectionResult(cfg, `{"active":true,"scope":""}`);
	assert(ti.valid);
	assert(ti.scopes.length == 0);
}

unittest  // internal runs of spaces do not produce empty-string scopes
{
	IntrospectionConfig cfg;
	auto ti = introspectionResult(cfg, `{"active":true,"scope":"a   b"}`);
	assert(ti.valid);
	assert(ti.scopes == ["a", "b"]);
}

unittest  // introspectionBody for client_secret_basic carries only the token and its type hint
{
	IntrospectionConfig cfg;
	cfg.authMethod = TokenEndpointAuthMethod.clientSecretBasic;
	cfg.clientId = "rs";
	cfg.clientSecret = "shh";
	assert(introspectionBody(cfg, "abc 123") == "token=abc%20123&token_type_hint=access_token");
}

unittest  // a response describing a refresh token is rejected
{
	IntrospectionConfig cfg;
	assert(!introspectionResult(cfg, `{"active":true,"token_type":"refresh_token"}`).valid);
	assert(!introspectionResult(cfg, `{"active":true,"token_type":"Refresh"}`).valid);
}

unittest  // a response describing a bearer access token is accepted
{
	IntrospectionConfig cfg;
	assert(introspectionResult(cfg, `{"active":true,"token_type":"Bearer"}`).valid);
	assert(introspectionResult(cfg, `{"active":true,"token_type":"access_token"}`).valid);
}

unittest  // introspectionBody for client_secret_post appends client credentials
{
	IntrospectionConfig cfg;
	cfg.authMethod = TokenEndpointAuthMethod.clientSecretPost;
	cfg.clientId = "rs";
	cfg.clientSecret = "s e c";
	const b = introspectionBody(cfg, "tok");
	assert(b == "token=tok&token_type_hint=access_token&client_id=rs&client_secret=s%20e%20c");
}

unittest  // a stub-backed verifier validates an active token end to end
{
	IntrospectionConfig cfg;
	cfg.audience = "https://mcp.example.com/mcp";
	cfg.requiredScopes = ["mcp:read"];
	auto stub = new StubIntrospector(
			`{"active":true,"sub":"u1","scope":"mcp:read","aud":"https://mcp.example.com/mcp"}`);
	auto v = stubVerifier(cfg, stub);

	auto ti = v("opaque-token");
	assert(ti.valid);
	assert(ti.subject == "u1");
	assert(stub.lastToken == "opaque-token");
}

unittest  // a stub-backed verifier rejects an inactive token
{
	IntrospectionConfig cfg;
	auto stub = new StubIntrospector(`{"active":false}`);
	auto v = stubVerifier(cfg, stub);
	assert(!v("opaque-token").valid);
}

unittest  // an empty token is rejected without introspecting
{
	IntrospectionConfig cfg;
	auto stub = new StubIntrospector(`{"active":true}`);
	auto v = stubVerifier(cfg, stub);
	assert(!v("").valid);
	assert(!stub.wasCalled);
}

unittest  // postIntrospect body read is capped at maxIntrospectionBodyBytes
{
	// Verify that readAllUTF8 throws when given more data than the cap allows.
	// This directly exercises the cap that postIntrospect must pass to readAllUTF8.
	import std.exception : assertThrown;
	import vibe.stream.memory : createMemoryStream;
	import vibe.stream.operations : readAllUTF8;

	// A stream of 1 byte more than the cap must be rejected.
	ubyte[] bigData = new ubyte[](maxIntrospectionBodyBytes + 1);
	auto stream = createMemoryStream(bigData);
	assertThrown(readAllUTF8(stream, false, maxIntrospectionBodyBytes));

	// A stream exactly at the cap must be accepted.
	ubyte[] okData = cast(ubyte[]) new char[](maxIntrospectionBodyBytes);
	foreach (ref b; okData)
		b = 'a'; // ASCII so readAllUTF8's UTF-8 validation passes
	auto okStream = createMemoryStream(okData);
	assert(readAllUTF8(okStream, false, maxIntrospectionBodyBytes)
			.length == maxIntrospectionBodyBytes);
}

unittest  // introspectionVerifier yields a usable TokenValidator
{
	IntrospectionConfig cfg;
	cfg.introspectionEndpoint = "https://as.example.com/introspect";
	cfg.clientId = "rs";
	cfg.clientSecret = "rs-secret";
	TokenValidator v = introspectionVerifier(cfg);
	assert(v !is null);
	// An empty token is rejected before any network call.
	assert(!v("").valid);
}

unittest  // introspectionVerifier refuses an auth method that sends no client credentials
{
	import std.exception : assertThrown;

	IntrospectionConfig cfg;
	cfg.introspectionEndpoint = "https://as.example.com/introspect";
	cfg.clientId = "rs";
	cfg.clientSecret = "rs-secret";
	cfg.authMethod = TokenEndpointAuthMethod.none;
	assertThrown(introspectionVerifier(cfg));
	cfg.authMethod = TokenEndpointAuthMethod.privateKeyJwt;
	assertThrown(introspectionVerifier(cfg));
	cfg.authMethod = TokenEndpointAuthMethod.clientSecretPost;
	assert(introspectionVerifier(cfg) !is null);
}

unittest  // introspectionVerifier requires an endpoint and a client id
{
	import std.exception : assertThrown;

	IntrospectionConfig cfg;
	cfg.introspectionEndpoint = "https://as.example.com/introspect";
	assertThrown(introspectionVerifier(cfg));
	cfg.introspectionEndpoint = "";
	cfg.clientId = "rs";
	assertThrown(introspectionVerifier(cfg));
}

unittest  // HttpIntrospector refuses an insecure (plaintext http) introspection endpoint
{
	import std.exception : assertThrown;

	// A plaintext-http endpoint to a non-loopback host must be rejected before any
	// HTTP request is issued (no token introspection over an insecure transport).
	IntrospectionConfig cfg;
	cfg.introspectionEndpoint = "http://as.example.com/introspect";
	auto introspector = new HttpIntrospector(cfg);
	assertThrown(introspector.introspect("some-token"));
}

version (Posix) unittest  // an introspection endpoint on a non-loopback internal address is reached only when permitted
{
	import std.conv : to;
	import std.exception : assertThrown;
	import vibe.core.core : runTask, runEventLoop, exitEventLoop;
	import vibe.http.server : HTTPServerRequest, HTTPServerResponse,
		HTTPServerSettings, listenHTTP;

	string failure, permitted;
	bool defaultRefused;
	runTask(() @safe nothrow{
		try
		{
			auto settings = new HTTPServerSettings;
			settings.port = 0;
			settings.bindAddresses = ["0.0.0.0"];
			auto listener = listenHTTP(settings, (scope HTTPServerRequest req,
				scope HTTPServerResponse res) @safe {
				res.writeBody(`{"active":true}`, "application/json");
			});
			scope (exit)
				listener.stopListening();
			// 0.0.0.0 is an internal, non-loopback address that still reaches
			// this host's listener on POSIX (Windows refuses to connect to it).
			IntrospectionConfig cfg;
			cfg.introspectionEndpoint = "http://0.0.0.0:"
				~ listener.bindAddresses[0].port.to!string ~ "/introspect";
			try
				cast(void) new HttpIntrospector(cfg).introspect("tok");
			catch (Exception)
				defaultRefused = true;
			cfg.ssrfPolicy = SsrfPolicy.allowUserConfigured;
			permitted = new HttpIntrospector(cfg).introspect("tok");
		}
		catch (Exception e)
			failure = e.msg;
		exitEventLoop();
	});
	runEventLoop();

	assert(failure.length == 0, failure);
	assert(defaultRefused);
	assert(permitted == `{"active":true}`);
}

unittest  // HttpIntrospector refuses an internal/link-local introspection endpoint (SSRF)
{
	import std.exception : assertThrown;

	IntrospectionConfig cfg;
	cfg.introspectionEndpoint = "https://169.254.169.254/introspect";
	auto introspector = new HttpIntrospector(cfg);
	assertThrown(introspector.introspect("some-token"));
}

version (unittest)
{
	import vibe.core.log : LogLevel, Logger, LogLine;

	// Records the text of every warning-or-higher log line.
	private final class CaptureLogger : Logger
	{
		string[] lines;
		this() @safe
		{
			minLevel = LogLevel.warn;
		}

		override void log(ref LogLine line) @safe
		{
			lines ~= line.text;
		}
	}

	private final class ThrowingIntrospector : Introspector
	{
		string introspect(string token) @safe
		{
			throw new Exception("introspection endpoint unreachable");
		}
	}
}

unittest  // a failed introspection call is logged rather than silently rejected
{
	import std.algorithm : any, canFind;
	import vibe.core.log : deregisterLogger, registerLogger;

	auto logger = new CaptureLogger;
	auto shared_ = () @trusted { return cast(shared) logger; }();
	() @trusted { registerLogger(shared_); }();
	scope (exit)
		() @trusted { deregisterLogger(shared_); }();

	IntrospectionConfig cfg;
	cfg.introspectionEndpoint = "https://as.example.com/introspect";
	auto v = introspectionValidator(cfg, new ThrowingIntrospector);
	assert(!v("tok").valid);
	auto lines = (cast() logger).lines;
	assert(lines.any!(l => l.canFind("introspection endpoint unreachable")));
}

unittest  // a caller mutating a cached result's claims, scopes, or audience leaves the cache intact
{
	IntrospectionConfig cfg;
	cfg.cache.ttl = 60.seconds;
	auto stub = new StubIntrospector(`{"active":true,"sub":"u1","scope":"mcp:read","aud":"https://mcp.example.com/mcp","role":"user"}`);
	auto v = stubVerifier(cfg, stub);

	auto first = v("tok");
	first.claims["role"] = "admin";
	first.scopes[0] = "mcp:admin";
	first.audience[0] = "https://evil.example";

	auto second = v("tok");
	second.claims["role"] = "admin";
	second.scopes[0] = "mcp:admin";

	auto third = v("tok");
	assert(third.claims["role"].get!string == "user");
	assert(third.scopes == ["mcp:read"]);
	assert(third.audience == ["https://mcp.example.com/mcp"]);
}

unittest  // positive introspection results are not cached by default, so a revocation takes effect at once
{
	IntrospectionConfig cfg;
	auto stub = new StubIntrospector(`{"active":true,"sub":"u1"}`);
	auto v = stubVerifier(cfg, stub);
	assert(v("tok").valid);
	stub.response = `{"active":false}`;
	assert(!v("tok").valid);
}

unittest  // an inactive token is briefly negatively cached
{
	IntrospectionConfig cfg;
	auto stub = new StubIntrospector(`{"active":false}`);
	auto v = stubVerifier(cfg, stub);
	assert(!v("tok").valid);
	stub.wasCalled = false;
	assert(!v("tok").valid);
	assert(!stub.wasCalled, "a repeated dead token must not cost another introspection");
}

unittest  // an unavailable introspection endpoint yields a temporarily-unavailable TokenInfo
{
	final class DownIntrospector : Introspector
	{
		string introspect(string token) @safe
		{
			throw new TokenVerifierUnavailableException("HTTP 503", 12.seconds);
		}
	}

	IntrospectionConfig cfg;
	cfg.introspectionEndpoint = "https://as.example.com/introspect";
	auto ti = introspectionValidator(cfg, new DownIntrospector)("tok");
	assert(!ti.valid && ti.unavailable);
	assert(ti.retryAfter == 12.seconds);

	// Any other failure still rejects the token outright.
	ti = introspectionValidator(cfg, new ThrowingIntrospector)("tok");
	assert(!ti.valid && !ti.unavailable);
}

unittest  // a 503 introspection response is reported as an unavailable verifier with its status code and Retry-After
{
	import std.algorithm : canFind;
	import std.conv : to;
	import vibe.core.core : runTask, runEventLoop, exitEventLoop;
	import vibe.http.server : HTTPServerRequest, HTTPServerResponse,
		HTTPServerSettings, listenHTTP;

	string failure, thrown;
	Duration retryAfter;
	runTask(() @safe nothrow{
		try
		{
			auto settings = new HTTPServerSettings;
			settings.port = 0;
			settings.bindAddresses = ["127.0.0.1"];
			auto listener = listenHTTP(settings, (scope HTTPServerRequest req,
				scope HTTPServerResponse res) @safe {
				res.statusCode = 503;
				res.headers["Retry-After"] = "20";
				res.writeBody("down for maintenance", "text/plain");
			});
			scope (exit)
				listener.stopListening();
			IntrospectionConfig cfg;
			cfg.introspectionEndpoint = "http://127.0.0.1:"
				~ listener.bindAddresses[0].port.to!string ~ "/introspect";
			try
				cast(void) new HttpIntrospector(cfg).introspect("tok");
			catch (TokenVerifierUnavailableException e)
			{
				thrown = e.msg;
				retryAfter = e.retryAfter;
			}
		}
		catch (Exception e)
			failure = e.msg;
		exitEventLoop();
	});
	runEventLoop();

	assert(failure.length == 0, failure);
	assert(thrown.canFind("HTTP 503"), thrown);
	assert(retryAfter == 20.seconds);
}
