/// A ready-made opaque-token verifier that validates bearer tokens via OAuth 2.0
/// Token Introspection (RFC 7662), so MCP server authors don't have to hand-roll
/// the introspection request, response parsing, and claim checks. It is the D
/// analogue of FastMCP's `IntrospectionTokenVerifier`.
///
/// The verifier POSTs the presented token to the authorization server's
/// introspection endpoint (authenticating as a resource server with
/// `client_secret_basic` or `client_secret_post`), then maps the RFC 7662
/// response to a `TokenInfo`: `active:false` (or any HTTP/parse error) yields an
/// invalid result, while `active:true` yields a valid `TokenInfo` with `scope`,
/// `sub`, and `aud` mapped across, after enforcing the configured audience and
/// required scopes. Positive results may be briefly cached.
module mcp.auth.introspection_verifier;

import core.time : Duration, seconds;

import std.algorithm : canFind;

import vibe.data.json : Json, parseJsonString;

import mcp.auth.jwt_verifier : audiences, currentUnixTime, jsonStr, splitScopes;
import mcp.auth.oauth : TokenEndpointAuthMethod, basicAuthHeader, secureRequestHTTP;
import mcp.auth.resource_server : TokenInfo, TokenValidator;

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
	/// response `scope` for the token to be accepted.
	string[] requiredScopes;

	/// Optional TTL for caching positive (`active:true`) introspection results,
	/// keyed by the raw token. Zero (the default) disables caching. Caching trades
	/// revocation latency for performance: a token revoked at the AS, or one whose
	/// own `exp` is sooner than the TTL, may be served as valid from cache until
	/// the entry expires. Entry expiry is clamped to the token's `exp` (RFC 7662)
	/// when present, so the staleness window never outlives the token itself.
	Duration cacheTtl = Duration.zero;
}

// ===========================================================================
// Public entry point
// ===========================================================================

/// Build a `TokenValidator` from `cfg`. The returned delegate introspects a
/// bearer token at the configured endpoint and yields a `TokenInfo`
/// (`valid == false` on `active:false`, HTTP failure, or parse error). Plug it
/// into `ResourceServerConfig.validator`.
///
/// Concurrency: the returned validator and its internal `PositiveCache` hold
/// unsynchronized mutable state (the cached positive results). Like the rest of
/// the SDK they are bound to vibe.d's default single-threaded event loop. Do not
/// share the validator across worker threads; running the router with
/// `HTTPServerOption.distribute` or worker threads is unsupported (see the
/// concurrency contract in `mcp.transport.session`).
TokenValidator introspectionVerifier(IntrospectionConfig cfg) @safe
{
	auto introspector = new HttpIntrospector(cfg);
	auto cache = cfg.cacheTtl > Duration.zero ? new PositiveCache(cfg.cacheTtl) : null;
	return (string token) @safe {
		if (token.length == 0)
			return TokenInfo.invalid();
		if (cache !is null)
			if (auto hit = cache.get(token, currentUnixTime()))
				return *hit;
		TokenInfo ti;
		try
		{
			const doc = introspector.introspect(token);
			ti = introspectionResult(cfg, doc);
		}
		catch (Exception)
			return TokenInfo.invalid();
		if (ti.valid && cache !is null)
			cache.put(token, ti, currentUnixTime());
		return ti;
	};
}

// ===========================================================================
// Response mapping (pure of HTTP / clock; unit-testable)
// ===========================================================================

/// A source of introspection responses for a token. Separated from HTTP so
/// tests can drive verification against a stub endpoint.
interface Introspector
{
	/// Return the raw RFC 7662 introspection response JSON for `token`.
	string introspect(string token) @safe;
}

/// Map a raw RFC 7662 introspection response document to a `TokenInfo`, applying
/// the `cfg` audience and required-scope checks. `active:false`, a non-object
/// response, or a missing/false `active` member yields an invalid result.
TokenInfo introspectionResult(IntrospectionConfig cfg, string responseJson) @safe
{
	Json doc;
	try
		doc = parseJsonString(responseJson);
	catch (Exception)
		return TokenInfo.invalid();

	if (doc.type != Json.Type.object)
		return TokenInfo.invalid();

	auto active = doc["active"];
	if (active.type != Json.Type.bool_ || !active.get!bool)
		return TokenInfo.invalid();

	auto auds = audiences(doc);
	if (cfg.audience.length && !auds.canFind(cfg.audience))
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

/// Build the form body for an introspection request (RFC 7662 2.1). For
/// `client_secret_post`, the client credentials are appended to the body.
string introspectionBody(IntrospectionConfig cfg, string token) @safe
{
	import std.uri : encodeComponent;

	string body_ = "token=" ~ encodeComponent(token);
	if (cfg.authMethod == TokenEndpointAuthMethod.clientSecretPost)
	{
		body_ ~= "&client_id=" ~ encodeComponent(cfg.clientId);
		body_ ~= "&client_secret=" ~ encodeComponent(cfg.clientSecret);
	}
	return body_;
}

private string postIntrospect(IntrospectionConfig cfg, string token) @trusted
{
	import vibe.http.client : HTTPClientRequest, HTTPClientResponse;
	import vibe.http.common : HTTPMethod;
	import vibe.stream.operations : readAllUTF8;

	// Refuse to introspect over an insecure transport (must be https, or http to
	// a loopback host for dev) or against an internal/link-local address. The
	// connect is pinned to a pre-vetted resolved address (DNS-rebinding
	// mitigation); secureRequestHTTP throws on an unsafe or unresolvable host.
	const body_ = introspectionBody(cfg, token);
	string responseBody;
	bool ok = false;
	secureRequestHTTP(cfg.introspectionEndpoint, (scope HTTPClientRequest req) {
		req.method = HTTPMethod.POST;
		req.headers["Content-Type"] = "application/x-www-form-urlencoded";
		req.headers["Accept"] = "application/json";
		if (cfg.authMethod == TokenEndpointAuthMethod.clientSecretBasic)
			req.headers["Authorization"] = basicAuthHeader(cfg.clientId, cfg.clientSecret);
		req.writeBody(cast(const(ubyte)[]) body_);
	}, (scope HTTPClientResponse res) {
		if (res.statusCode >= 200 && res.statusCode < 300)
		{
			responseBody = res.bodyReader.readAllUTF8();
			ok = true;
		}
		else
			res.dropBody();
	});
	if (!ok)
		return null;
	return responseBody;
}

// ===========================================================================
// Positive-result cache
// ===========================================================================

/// A short-TTL cache of positive (`active:true`) introspection results, keyed by
/// the raw token. Negative results are never cached.
///
/// The keyed lookup is not constant-time, but a hit requires the attacker to
/// already present a token that introspected as active, so it is not a guessing
/// oracle; opaque bearer tokens are assumed to be high-entropy secrets.
final class PositiveCache
{
	private struct Entry
	{
		TokenInfo info;
		long expiresAt; // unix seconds
	}

	private Duration ttl;
	private Entry[string] entries;

	this(Duration ttl) @safe
	{
		this.ttl = ttl;
	}

	/// Return the cached `TokenInfo` for `token` if present and unexpired.
	TokenInfo* get(string token, long now) @safe
	{
		if (auto e = token in entries)
		{
			if (now < e.expiresAt)
				return &e.info;
			entries.remove(token);
		}
		return null;
	}

	/// Cache a positive result for `token`. The entry expiry is the TTL, clamped
	/// down to the token's own `exp` (RFC 7662) when present, so a cached result
	/// never outlives the token it represents.
	void put(string token, TokenInfo info, long now) @safe
	{
		long expiresAt = now + cast(long) ttl.total!"seconds";
		const exp = introspectionExp(info.claims);
		if (exp > 0 && exp < expiresAt)
			expiresAt = exp;
		entries[token] = Entry(info, expiresAt);
	}
}

// ===========================================================================
// Small helpers
// ===========================================================================

/// Extract the `exp` claim (token expiry, unix seconds) from an introspection
/// response (RFC 7662 2.2 / RFC 7519 4.1.1). Returns 0 when absent or not a
/// number, signalling "no known expiry".
long introspectionExp(Json doc) @safe
{
	if (doc.type != Json.Type.object)
		return 0;
	auto e = doc["exp"];
	if (e.type == Json.Type.int_)
		return e.get!long;
	if (e.type == Json.Type.float_)
		return cast(long) e.get!double;
	return 0;
}

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
		this(string response) @safe
		{
			this.response = response;
		}

		string introspect(string token) @safe
		{
			lastToken = token;
			return response;
		}
	}

	// Build a TokenValidator over a stub introspector (mirrors the production
	// wiring in introspectionVerifier, minus the real HTTP).
	private TokenValidator stubVerifier(IntrospectionConfig cfg, Introspector introspector) @safe
	{
		return (string token) @safe {
			if (token.length == 0)
				return TokenInfo.invalid();
			try
				return introspectionResult(cfg, introspector.introspect(token));
			catch (Exception)
				return TokenInfo.invalid();
		};
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

unittest  // introspectionBody for client_secret_basic carries only the token
{
	IntrospectionConfig cfg;
	cfg.authMethod = TokenEndpointAuthMethod.clientSecretBasic;
	cfg.clientId = "rs";
	cfg.clientSecret = "shh";
	assert(introspectionBody(cfg, "abc 123") == "token=abc%20123");
}

unittest  // introspectionBody for client_secret_post appends client credentials
{
	IntrospectionConfig cfg;
	cfg.authMethod = TokenEndpointAuthMethod.clientSecretPost;
	cfg.clientId = "rs";
	cfg.clientSecret = "s e c";
	const b = introspectionBody(cfg, "tok");
	assert(b == "token=tok&client_id=rs&client_secret=s%20e%20c");
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
	assert(stub.lastToken == "");
}

unittest  // PositiveCache returns a hit before expiry and a miss after
{
	auto cache = new PositiveCache(30.seconds);
	TokenInfo ti;
	ti.valid = true;
	ti.subject = "cached-user";
	cache.put("tok", ti, 1000);

	auto hit = cache.get("tok", 1010);
	assert(hit !is null);
	assert(hit.subject == "cached-user");

	assert(cache.get("tok", 1040) is null); // expired (1000 + 30 == 1030)
	assert(cache.get("other", 1010) is null); // never stored
}

unittest  // PositiveCache clamps entry expiry to the token's exp claim
{
	auto cache = new PositiveCache(30.seconds);
	TokenInfo ti;
	ti.valid = true;
	// exp at 1005 is sooner than now(1000) + ttl(30) == 1030, so it must win.
	ti.claims = parseJsonString(`{"active":true,"exp":1005}`);
	cache.put("tok", ti, 1000);

	assert(cache.get("tok", 1004) !is null); // still valid before exp
	assert(cache.get("tok", 1005) is null); // expired at exp, not at 1030
}

unittest  // PositiveCache keeps the TTL when exp is later than now + ttl
{
	auto cache = new PositiveCache(30.seconds);
	TokenInfo ti;
	ti.valid = true;
	ti.claims = parseJsonString(`{"active":true,"exp":9999}`);
	cache.put("tok", ti, 1000);

	assert(cache.get("tok", 1029) !is null); // within TTL window
	assert(cache.get("tok", 1030) is null); // TTL (1030) bounds it, not exp
}

unittest  // PositiveCache falls back to the TTL when no exp is present
{
	auto cache = new PositiveCache(30.seconds);
	TokenInfo ti;
	ti.valid = true;
	ti.claims = parseJsonString(`{"active":true}`);
	cache.put("tok", ti, 1000);

	assert(cache.get("tok", 1029) !is null);
	assert(cache.get("tok", 1030) is null);
}

unittest  // introspectionExp parses integer and floating exp, 0 otherwise
{
	assert(introspectionExp(parseJsonString(`{"exp":1700}`)) == 1700);
	assert(introspectionExp(parseJsonString(`{"exp":1700.9}`)) == 1700);
	assert(introspectionExp(parseJsonString(`{"active":true}`)) == 0);
	assert(introspectionExp(parseJsonString(`{"exp":"soon"}`)) == 0);
	assert(introspectionExp(parseJsonString(`"not-an-object"`)) == 0);
}

unittest  // introspectionVerifier yields a usable TokenValidator
{
	IntrospectionConfig cfg;
	cfg.introspectionEndpoint = "https://as.example.com/introspect";
	TokenValidator v = introspectionVerifier(cfg);
	assert(v !is null);
	// An empty token is rejected before any network call.
	assert(!v("").valid);
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

unittest  // HttpIntrospector refuses an internal/link-local introspection endpoint (SSRF)
{
	import std.exception : assertThrown;

	IntrospectionConfig cfg;
	cfg.introspectionEndpoint = "https://169.254.169.254/introspect";
	auto introspector = new HttpIntrospector(cfg);
	assertThrown(introspector.introspect("some-token"));
}
