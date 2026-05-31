module mcp.auth.resource_server;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

import mcp.auth.oauth : ProtectedResourceMetadata;

@safe:

/// The result of validating a bearer access token. A token validator returns
/// this to the transport: `valid` gates the request, `scopes`/`subject`/`claims`
/// describe the principal and are surfaced to tool handlers via
/// `RequestContext.auth`, and `audience` lets the transport enforce the RFC 8707
/// resource binding ("tokens were issued specifically for them").
struct TokenInfo
{
	bool valid; /// true when the token is genuine, unexpired, and trusted
	string subject; /// the authenticated principal (token `sub`), if any
	string[] scopes; /// the scopes the token grants
	string[] audience; /// the audiences the token was issued for (RFC 8707)
	Json claims = Json.undefined; /// the full claim set, for handler inspection

	/// Whether the token grants the named scope.
	bool hasScope(string scope_) const @safe
	{
		import std.algorithm : canFind;

		return scopes.canFind(scope_);
	}

	/// Whether the token lists the given resource among its audiences (RFC 8707).
	/// The spec (basic/authorization §Access Token Privilege Restriction) requires
	/// servers to "reject tokens that do not include them in the audience claim",
	/// so an empty audience does NOT satisfy the binding: a token must explicitly
	/// name `resource` to be treated as issued for this server.
	bool hasAudience(string resource) const @safe
	{
		import std.algorithm : canFind;

		return audience.canFind(resource);
	}

	/// A convenience constructor for a rejected token.
	static TokenInfo invalid() @safe
	{
		TokenInfo t;
		t.valid = false;
		return t;
	}
}

/// A delegate the server calls to validate a presented bearer token. It receives
/// the raw token string (the value after `Bearer `) and returns a `TokenInfo`.
/// Returning `TokenInfo` with `valid == false` (or throwing) rejects the request
/// with HTTP 401.
alias TokenValidator = TokenInfo delegate(string token) @safe;

/// The kind of authorization failure, mapped to an HTTP status + WWW-Authenticate
/// `error` parameter by the transport (RFC 6750 §3.1).
enum AuthFailure
{
	none, /// authorized; proceed
	missingToken, /// no Authorization: Bearer header -> 401 (no error code)
	invalidToken, /// token rejected / wrong audience -> 401 invalid_token
	insufficientScope, /// token lacks a required scope -> 403 insufficient_scope
}

/// Server-side OAuth 2.1 Resource Server configuration (RFC 6750 / 8707 / 9728).
/// When `validator` is set on the Streamable HTTP transport, every MCP request
/// must carry a valid `Authorization: Bearer` token; otherwise the transport
/// replies 401 with a `WWW-Authenticate` header pointing at the Protected
/// Resource Metadata document, which it serves at
/// `/.well-known/oauth-protected-resource`.
struct ResourceServerConfig
{
	/// Validates a presented bearer token. Required to enable auth; when null the
	/// transport performs no token checks (back-compatible default).
	TokenValidator validator;

	/// The canonical resource identifier for this server (RFC 8707). When set,
	/// the transport enforces that a validated token's audience includes it, and
	/// publishes it as `resource` in the metadata document.
	string resource;

	/// The authorization server issuer URLs advertised in the metadata document
	/// and (first entry) ignored by validation — they are informational for
	/// clients discovering where to obtain a token.
	string[] authorizationServers;

	/// The scopes advertised in the metadata document.
	string[] scopesSupported;

	/// A scope every request must carry, enforced after token validation. Empty
	/// means no scope requirement.
	string requiredScope;

	/// Whether auth enforcement is active.
	bool enabled() const @safe
	{
		return validator !is null;
	}

	/// The scope hint to surface in a `WWW-Authenticate` challenge so clients know
	/// which scopes to request (basic/authorization §Protected Resource Metadata
	/// Discovery Requirements / §Scope Selection Strategy). Prefers the concrete
	/// `requiredScope`; otherwise falls back to the space-joined `scopesSupported`.
	/// Empty when the operator configured neither.
	string scopeHint() const @safe
	{
		import std.array : join;

		if (requiredScope.length)
			return requiredScope;
		return scopesSupported.join(" ");
	}

	/// The RFC 9728 metadata document this server publishes.
	ProtectedResourceMetadata metadata() const @safe
	{
		ProtectedResourceMetadata m;
		m.resource = resource;
		m.authorizationServers = authorizationServers.dup;
		m.scopesSupported = scopesSupported.dup;
		return m;
	}
}

/// Extract the token from an `Authorization` header value, or null when the
/// header is absent or not a `Bearer` credential. The scheme match is
/// case-insensitive per RFC 7235.
string bearerToken(string authHeader) @safe
{
	import std.string : strip, startsWith, toLower;

	auto h = authHeader.strip;
	if (h.length < 7)
		return null;
	if (!h[0 .. 7].toLower.startsWith("bearer "))
		return null;
	return h[7 .. $].strip;
}

unittest  // bearerToken extracts the credential, case-insensitively
{
	assert(bearerToken("Bearer abc123") == "abc123");
	assert(bearerToken("bearer abc123") == "abc123");
	assert(bearerToken("BEARER  abc123  ") == "abc123");
}

unittest  // bearerToken rejects non-Bearer / absent headers
{
	assert(bearerToken("") is null);
	assert(bearerToken("Basic dXNlcjpwYXNz") is null);
	assert(bearerToken("Bearer") is null);
}

/// Decide whether a request bearing `authHeader` is authorized under `cfg`,
/// returning the failure kind (`AuthFailure.none` on success) and, on success,
/// the validated `TokenInfo`. Pure of HTTP concerns so it can be unit-tested and
/// reused by any transport.
AuthFailure authorize(ResourceServerConfig cfg, string authHeader, out TokenInfo info) @safe
{
	if (!cfg.enabled)
		return AuthFailure.none;

	const tok = bearerToken(authHeader);
	if (tok is null || tok.length == 0)
		return AuthFailure.missingToken;

	TokenInfo ti;
	try
		ti = cfg.validator(tok);
	catch (Exception)
		return AuthFailure.invalidToken;

	if (!ti.valid)
		return AuthFailure.invalidToken;

	// RFC 8707: the token MUST have been issued for this resource.
	if (cfg.resource.length && !ti.hasAudience(cfg.resource))
		return AuthFailure.invalidToken;

	// Scope enforcement comes after authentication (RFC 6750 §3.1).
	if (cfg.requiredScope.length && !ti.hasScope(cfg.requiredScope))
	{
		info = ti;
		return AuthFailure.insufficientScope;
	}

	info = ti;
	return AuthFailure.none;
}

/// Build the `WWW-Authenticate` header value for an auth failure (RFC 6750 §3 /
/// RFC 9728 §5.1). Always carries the `resource_metadata` URL when known, plus an
/// `error`/`scope` for token/scope failures.
string wwwAuthenticate(AuthFailure failure, string resourceMetadataUrl, string scope_) @safe
{
	string v = "Bearer";
	string[] parts;
	if (resourceMetadataUrl.length)
		parts ~= `resource_metadata="` ~ resourceMetadataUrl ~ `"`;
	final switch (failure)
	{
	case AuthFailure.none:
		break;
	case AuthFailure.missingToken:
		// First-contact 401: the spec (basic/authorization §Protected Resource
		// Metadata Discovery Requirements) says servers SHOULD include a `scope`
		// hint so the client knows what to request during authorization. RFC 6750
		// §3 permits `scope` on the bare challenge.
		if (scope_.length)
			parts ~= `scope="` ~ scope_ ~ `"`;
		break;
	case AuthFailure.invalidToken:
		parts ~= `error="invalid_token"`;
		if (scope_.length)
			parts ~= `scope="` ~ scope_ ~ `"`;
		break;
	case AuthFailure.insufficientScope:
		parts ~= `error="insufficient_scope"`;
		if (scope_.length)
			parts ~= `scope="` ~ scope_ ~ `"`;
		break;
	}
	foreach (i, p; parts)
		v ~= (i == 0 ? " " : ", ") ~ p;
	return v;
}

unittest  // disabled config authorizes everything
{
	ResourceServerConfig cfg;
	TokenInfo info;
	assert(authorize(cfg, "", info) == AuthFailure.none);
	assert(authorize(cfg, "Bearer whatever", info) == AuthFailure.none);
}

unittest  // a missing token is rejected when auth is enabled
{
	ResourceServerConfig cfg;
	cfg.validator = (string t) => TokenInfo.invalid();
	TokenInfo info;
	assert(authorize(cfg, "", info) == AuthFailure.missingToken);
}

unittest  // an invalid token is rejected
{
	ResourceServerConfig cfg;
	cfg.validator = (string t) => TokenInfo.invalid();
	TokenInfo info;
	assert(authorize(cfg, "Bearer bad", info) == AuthFailure.invalidToken);
}

unittest  // a validator that throws yields invalidToken (not a crash)
{
	ResourceServerConfig cfg;
	cfg.validator = (string t) {
		throw new Exception("boom");
		return TokenInfo.invalid();
	};
	TokenInfo info;
	assert(authorize(cfg, "Bearer x", info) == AuthFailure.invalidToken);
}

unittest  // a valid token authorizes and surfaces TokenInfo
{
	ResourceServerConfig cfg;
	cfg.validator = (string t) {
		TokenInfo ti;
		ti.valid = true;
		ti.subject = "user-1";
		ti.scopes = ["mcp:read"];
		return ti;
	};
	TokenInfo info;
	assert(authorize(cfg, "Bearer good", info) == AuthFailure.none);
	assert(info.subject == "user-1");
	assert(info.hasScope("mcp:read"));
}

unittest  // RFC 8707: a token for the wrong audience is rejected
{
	ResourceServerConfig cfg;
	cfg.resource = "https://mcp.example.com/mcp";
	cfg.validator = (string t) {
		TokenInfo ti;
		ti.valid = true;
		ti.audience = ["https://other.example.com"];
		return ti;
	};
	TokenInfo info;
	assert(authorize(cfg, "Bearer good", info) == AuthFailure.invalidToken);
}

unittest  // RFC 8707: a token whose audience includes the resource is accepted
{
	ResourceServerConfig cfg;
	cfg.resource = "https://mcp.example.com/mcp";
	cfg.validator = (string t) {
		TokenInfo ti;
		ti.valid = true;
		ti.audience = ["https://mcp.example.com/mcp"];
		return ti;
	};
	TokenInfo info;
	assert(authorize(cfg, "Bearer good", info) == AuthFailure.none);
}

unittest  // RFC 8707: an empty audience is rejected when a resource is configured
{
	// The spec (basic/authorization, Access Token Privilege Restriction) says
	// servers MUST reject tokens that do not include them in the audience claim.
	// When the operator has opted into RFC 8707 binding by setting cfg.resource,
	// a validated token with no audience MUST fail closed.
	ResourceServerConfig cfg;
	cfg.resource = "https://mcp.example.com/mcp";
	cfg.validator = (string t) {
		TokenInfo ti;
		ti.valid = true;
		// validator forgot to populate audience
		return ti;
	};
	TokenInfo info;
	assert(authorize(cfg, "Bearer good", info) == AuthFailure.invalidToken);
}

unittest  // RFC 8707: an empty audience is accepted when no resource is configured
{
	// Without cfg.resource the operator has not opted into binding, so an
	// unscoped token remains acceptable (back-compatible default).
	ResourceServerConfig cfg;
	cfg.validator = (string t) { TokenInfo ti; ti.valid = true; return ti; };
	TokenInfo info;
	assert(authorize(cfg, "Bearer good", info) == AuthFailure.none);
}

unittest  // a token lacking the required scope yields insufficientScope
{
	ResourceServerConfig cfg;
	cfg.requiredScope = "mcp:write";
	cfg.validator = (string t) {
		TokenInfo ti;
		ti.valid = true;
		ti.scopes = ["mcp:read"];
		return ti;
	};
	TokenInfo info;
	assert(authorize(cfg, "Bearer good", info) == AuthFailure.insufficientScope);
}

unittest  // WWW-Authenticate for a missing token with no scope hint carries only resource_metadata
{
	const v = wwwAuthenticate(AuthFailure.missingToken,
			"https://mcp.example.com/.well-known/oauth-protected-resource", "");
	assert(v
			== `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`);
}

unittest  // WWW-Authenticate for a missing token (first-contact 401) carries the scope hint
{
	// basic/authorization §Protected Resource Metadata Discovery Requirements:
	// servers SHOULD include a `scope` parameter in the WWW-Authenticate header on
	// the first-contact 401 so clients know what to request. The spec example is a
	// 401 carrying `Bearer resource_metadata="...", scope="files:read"`.
	const v = wwwAuthenticate(AuthFailure.missingToken,
			"https://mcp.example.com/.well-known/oauth-protected-resource", "files:read");
	assert(v == `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", scope="files:read"`);
}

unittest  // WWW-Authenticate for an invalid token with no scope hint carries error only
{
	const v = wwwAuthenticate(AuthFailure.invalidToken, "https://x/meta", "");
	assert(v == `Bearer resource_metadata="https://x/meta", error="invalid_token"`);
}

unittest  // WWW-Authenticate for an invalid token (401) carries error + scope hint
{
	// The 401 invalid_token challenge SHOULD also surface scope guidance so the
	// client can request the right scopes during step-up authorization.
	const v = wwwAuthenticate(AuthFailure.invalidToken, "https://x/meta", "mcp:write");
	assert(
			v == `Bearer resource_metadata="https://x/meta", error="invalid_token", scope="mcp:write"`);
}

unittest  // WWW-Authenticate for insufficient scope carries error + scope
{
	const v = wwwAuthenticate(AuthFailure.insufficientScope, "https://x/meta", "mcp:write");
	assert(v
			== `Bearer resource_metadata="https://x/meta", error="insufficient_scope", scope="mcp:write"`);
}

unittest  // scopeHint prefers requiredScope when set
{
	ResourceServerConfig cfg;
	cfg.requiredScope = "mcp:write";
	cfg.scopesSupported = ["mcp:read", "mcp:write"];
	assert(cfg.scopeHint() == "mcp:write");
}

unittest  // scopeHint falls back to space-joined scopesSupported
{
	ResourceServerConfig cfg;
	cfg.scopesSupported = ["files:read", "files:write"];
	assert(cfg.scopeHint() == "files:read files:write");
}

unittest  // scopeHint is empty when neither field is configured
{
	ResourceServerConfig cfg;
	assert(cfg.scopeHint() == "");
}

unittest  // ResourceServerConfig.metadata mirrors the configured fields
{
	ResourceServerConfig cfg;
	cfg.resource = "https://mcp.example.com/mcp";
	cfg.authorizationServers = ["https://auth.example.com"];
	cfg.scopesSupported = ["mcp:read", "mcp:write"];
	auto m = cfg.metadata();
	assert(m.resource == "https://mcp.example.com/mcp");
	assert(m.authorizationServers == ["https://auth.example.com"]);
	assert(m.scopesSupported == ["mcp:read", "mcp:write"]);
}
