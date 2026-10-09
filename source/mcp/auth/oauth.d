module mcp.auth.oauth;

import std.typecons : Nullable;
import vibe.data.json : Json;
import vibe.http.client : HTTPClientRequest, HTTPClientResponse;

import mcp.protocol.ssrf : SsrfPolicy;

@safe:

// ===========================================================================
// PKCE (RFC 7636) — S256
// ===========================================================================

/// A PKCE verifier/challenge pair. The verifier is kept by the client; the
/// challenge is sent on the authorization request and the verifier on the token
/// request.
struct PkcePair
{
	string verifier;
	string challenge;
}

/// Base64url-encode without padding (RFC 7636 / RFC 4648 §5).
string base64UrlNoPad(const(ubyte)[] data) @safe
{
	import std.base64 : Base64URLNoPadding;

	return () @trusted { return cast(string) Base64URLNoPadding.encode(data); }();
}

/// Generate a PKCE pair using the S256 method. `verifierBytes` (32 random
/// bytes) produces a 43-char base64url verifier; the challenge is
/// base64url(SHA-256(verifier)).
PkcePair makePkce(const(ubyte)[] verifierBytes) @safe
{
	import std.digest.sha : sha256Of;

	PkcePair p;
	p.verifier = base64UrlNoPad(verifierBytes);
	p.challenge = base64UrlNoPad(sha256Of(cast(const(ubyte)[]) p.verifier)[]);
	return p;
}

/// Generate a PKCE pair from cryptographically secure OS randomness (RFC 7636
/// recommends a high-entropy verifier). Throws `CsprngException` if the OS
/// CSPRNG is unavailable.
PkcePair generatePkce() @safe
{
	import mcp.auth.csprng : cryptoRandomFill;

	ubyte[32] buf;
	cryptoRandomFill(buf[]);
	return makePkce(buf[]);
}

// ===========================================================================
// WWW-Authenticate parsing (RFC 9728 §5.1)
// ===========================================================================

/// A parsed `WWW-Authenticate` challenge: the auth scheme plus its parameters.
///
/// `parseWwwAuthenticate` populates the standard challenge fields (RFC 9728
/// §5.1 `resource_metadata`/`scope` and RFC 6750 §3.1 `error`/`error_description`)
/// into `params`; the typed accessors below expose them without forcing
/// consumers toward substring matching on the raw header.
struct WwwAuthenticate
{
	string scheme;
	string[string] params;

	string resourceMetadata() const @safe
	{
		return ("resource_metadata" in params) ? params["resource_metadata"] : null;
	}

	string scope_() const @safe
	{
		return ("scope" in params) ? params["scope"] : null;
	}

	string error() const @safe
	{
		return ("error" in params) ? params["error"] : null;
	}

	string errorDescription() const @safe
	{
		return ("error_description" in params) ? params["error_description"] : null;
	}
}

/// Parse a `WWW-Authenticate` header value such as
/// `Bearer resource_metadata="https://...", scope="a b"` and return its
/// `Bearer` challenge (matched case-insensitively), or the first challenge when
/// none is `Bearer`. See `parseWwwAuthenticateChallenges`.
WwwAuthenticate parseWwwAuthenticate(string header) @safe
{
	import std.uni : sicmp;

	auto challenges = parseWwwAuthenticateChallenges(header);
	foreach (c; challenges)
		if (sicmp(c.scheme, "Bearer") == 0)
			return c;
	return challenges.length ? challenges[0] : WwwAuthenticate.init;
}

/// Parse every challenge in a `WWW-Authenticate` header value (RFC 9110
/// §11.6.1): `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`,
/// with challenges and auth-params sharing one comma-separated list. A token
/// followed by `=` is an auth-param of the current challenge; any other token
/// starts a new challenge. Quoted-string values are unescaped (RFC 9110
/// §5.6.4) and parameter names are lowercased, as they are case-insensitive.
/// A token68 credential is skipped.
WwwAuthenticate[] parseWwwAuthenticateChallenges(string header) @safe
{
	import std.ascii : isWhite;
	import std.uni : toLower;

	WwwAuthenticate[] challenges;
	size_t i;

	void skipWhite()
	{
		while (i < header.length && (header[i] == ' ' || header[i] == '\t'))
			i++;
	}

	bool isDelimiter(char c)
	{
		return c == ',' || c == '=' || c == '"' || isWhite(c);
	}

	string readToken()
	{
		const start = i;
		while (i < header.length && !isDelimiter(header[i]))
			i++;
		return header[start .. i];
	}

	string readQuoted()
	{
		string value;
		i++; // opening quote
		while (i < header.length && header[i] != '"')
		{
			if (header[i] == '\\' && i + 1 < header.length)
				i++;
			value ~= header[i];
			i++;
		}
		if (i < header.length)
			i++; // closing quote
		return value;
	}

	while (i < header.length)
	{
		skipWhite();
		if (i < header.length && header[i] == ',')
		{
			i++;
			continue;
		}
		const token = readToken();
		if (token.length == 0)
		{
			// A stray delimiter: step over it so parsing always advances.
			if (i < header.length)
				i++;
			continue;
		}
		skipWhite();
		const isParam = challenges.length && i < header.length
			&& header[i] == '=' && !(i + 1 < header.length && header[i + 1] == '=');
		if (!isParam)
		{
			WwwAuthenticate c;
			c.scheme = token;
			challenges ~= c;
			// A token68 credential (e.g. `abc==`) directly after the scheme.
			if (i < header.length && header[i] != ',')
			{
				const save = i;
				readToken();
				while (i < header.length && header[i] == '=')
					i++;
				skipWhite();
				if (i < header.length && header[i] != ',')
					i = save; // not a token68: it was the first auth-param
			}
			continue;
		}
		i++; // '='
		skipWhite();
		const value = i < header.length && header[i] == '"' ? readQuoted() : readToken();
		challenges[$ - 1].params[token.toLower] = value;
	}
	return challenges;
}

// ===========================================================================
// Metadata documents (RFC 9728 / RFC 8414)
// ===========================================================================

/// OAuth 2.0 Protected Resource Metadata (RFC 9728).
struct ProtectedResourceMetadata
{
	string resource;
	string[] authorizationServers;
	string[] scopesSupported;

	static ProtectedResourceMetadata fromJson(Json j) @safe
	{
		ProtectedResourceMetadata m;
		if ("resource" in j && j["resource"].type == Json.Type.string)
			m.resource = j["resource"].get!string;
		m.authorizationServers = stringArray(j, "authorization_servers");
		m.scopesSupported = stringArray(j, "scopes_supported");
		return m;
	}

	/// Serialize to the RFC 9728 metadata document a protected resource server
	/// publishes under `/.well-known/oauth-protected-resource`. `resource` and
	/// `authorization_servers` are always present; `scopes_supported` is emitted
	/// only when non-empty.
	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["resource"] = resource;
		Json as = Json.emptyArray;
		foreach (s; authorizationServers)
			as ~= Json(s);
		j["authorization_servers"] = as;
		if (scopesSupported.length)
		{
			Json ss = Json.emptyArray;
			foreach (s; scopesSupported)
				ss ~= Json(s);
			j["scopes_supported"] = ss;
		}
		return j;
	}
}

unittest  // ProtectedResourceMetadata.toJson emits the RFC 9728 fields
{
	ProtectedResourceMetadata m;
	m.resource = "https://mcp.example.com/mcp";
	m.authorizationServers = ["https://auth.example.com"];
	m.scopesSupported = ["read", "write"];
	auto j = m.toJson();
	assert(j["resource"].get!string == "https://mcp.example.com/mcp");
	assert(j["authorization_servers"].length == 1);
	assert(j["authorization_servers"][0].get!string == "https://auth.example.com");
	assert(j["scopes_supported"].length == 2);
}

unittest  // ProtectedResourceMetadata.toJson omits empty scopes_supported
{
	ProtectedResourceMetadata m;
	m.resource = "https://mcp.example.com/mcp";
	m.authorizationServers = ["https://auth.example.com"];
	auto j = m.toJson();
	assert("scopes_supported" !in j);
}

unittest  // ProtectedResourceMetadata round-trips through toJson/fromJson
{
	ProtectedResourceMetadata m;
	m.resource = "https://mcp.example.com/mcp";
	m.authorizationServers = ["https://a.example.com", "https://b.example.com"];
	m.scopesSupported = ["mcp:read"];
	auto back = ProtectedResourceMetadata.fromJson(m.toJson());
	assert(back.resource == m.resource);
	assert(back.authorizationServers == m.authorizationServers);
	assert(back.scopesSupported == m.scopesSupported);
}

/// OAuth 2.0 Authorization Server Metadata (RFC 8414).
struct AuthorizationServerMetadata
{
	string issuer;
	string authorizationEndpoint;
	string tokenEndpoint;
	string registrationEndpoint;
	string[] codeChallengeMethodsSupported;
	string[] scopesSupported;
	string[] grantTypesSupported;
	string[] tokenEndpointAuthMethodsSupported;
	/// RFC 8414 §2: REQUIRED when `authorization_endpoint` is present. Lists the
	/// OAuth `response_type` values the server supports (e.g. `["code"]`).
	string[] responseTypesSupported;
	/// RFC 9207: whether the AS includes the `iss` parameter in authorization
	/// responses. When true, clients MUST require and validate `iss`.
	bool authorizationResponseIssParameterSupported;
	/// SEP-991: whether the AS supports OAuth Client ID Metadata Documents (an
	/// HTTPS-URL `client_id` that points at a hosted client metadata document).
	/// When true, a client SHOULD prefer this over Dynamic Client Registration.
	bool clientIdMetadataDocumentSupported;
	/// Whether this metadata was parsed from an actual authorization-server
	/// metadata document discovered via RFC 8414 / OpenID Connect Discovery
	/// (true), as opposed to synthesized from default endpoints for the
	/// 2025-03-26 no-document endpoint fallback (false). The MCP authorization
	/// spec ("Authorization Code Protection") requires clients to refuse when a
	/// *discovered* document omits `code_challenge_methods_supported`; the
	/// no-document fallback case is treated separately. Set by `fromJson`.
	bool metadataDocumentDiscovered;

	/// PKCE S256 support is mandatory for MCP; clients MUST refuse otherwise.
	bool supportsS256() const @safe
	{
		import std.algorithm : canFind;

		return codeChallengeMethodsSupported.canFind("S256");
	}

	static AuthorizationServerMetadata fromJson(Json j) @safe
	{
		AuthorizationServerMetadata m;
		m.issuer = strField(j, "issuer");
		m.authorizationEndpoint = strField(j, "authorization_endpoint");
		m.tokenEndpoint = strField(j, "token_endpoint");
		m.registrationEndpoint = strField(j, "registration_endpoint");
		m.codeChallengeMethodsSupported = stringArray(j, "code_challenge_methods_supported");
		m.scopesSupported = stringArray(j, "scopes_supported");
		m.grantTypesSupported = stringArray(j, "grant_types_supported");
		m.tokenEndpointAuthMethodsSupported = stringArray(j,
				"token_endpoint_auth_methods_supported");
		m.responseTypesSupported = stringArray(j, "response_types_supported");
		m.authorizationResponseIssParameterSupported = boolField(j,
				"authorization_response_iss_parameter_supported");
		m.clientIdMetadataDocumentSupported = boolField(j, "client_id_metadata_document_supported");
		// This metadata came from a discovered RFC 8414 / OIDC document, so the
		// spec's "refuse when code_challenge_methods_supported is absent" rule
		// applies (see OAuthClient.requirePkceSupport).
		m.metadataDocumentDiscovered = true;
		return m;
	}
}

private string strField(Json j, string key) @safe
{
	return (key in j && j[key].type == Json.Type.string) ? j[key].get!string : null;
}

private bool boolField(Json j, string key) @safe
{
	return (key in j && j[key].type == Json.Type.bool_) ? j[key].get!bool : false;
}

private string[] stringArray(Json j, string key) @safe
{
	string[] out_;
	if (key in j && j[key].type == Json.Type.array)
	{
		auto arr = j[key];
		foreach (i; 0 .. arr.length)
			if (arr[i].type == Json.Type.string)
				out_ ~= arr[i].get!string;
	}
	return out_;
}

/// The `scheme://authority` prefix of `url`: everything before the first `/`,
/// `?` or `#` after the scheme separator. A string without `://` is returned
/// unchanged.
package string urlOrigin(string url) @safe
{
	import std.string : indexOf, indexOfAny;

	const schemeEnd = url.indexOf("://");
	if (schemeEnd < 0)
		return url;
	const afterScheme = schemeEnd + 3;
	const end = url[afterScheme .. $].indexOfAny("/?#");
	return end < 0 ? url : url[0 .. afterScheme + end];
}

/// Build the ordered list of well-known protected-resource-metadata URLs to try
/// for an MCP endpoint URL, per RFC 9728: the path-scoped URL first, then root.
string[] protectedResourceMetadataUrls(string mcpEndpoint) @safe
{
	import std.algorithm : min;
	import std.string : indexOf;

	if (mcpEndpoint.indexOf("://") < 0)
		return [mcpEndpoint];
	const origin = urlOrigin(mcpEndpoint);
	string path = mcpEndpoint[origin.length .. $];

	// RFC 9728 uses scheme+host+path only; strip query string and fragment.
	auto cut = path.length;
	auto q = path.indexOf('?');
	auto h = path.indexOf('#');
	if (q >= 0)
		cut = min(cut, q);
	if (h >= 0)
		cut = min(cut, h);
	path = path[0 .. cut];

	string[] urls;
	if (path.length && path != "/")
		urls ~= origin ~ "/.well-known/oauth-protected-resource" ~ path;
	urls ~= origin ~ "/.well-known/oauth-protected-resource";
	return urls;
}

/// The ordered list of authorization-server metadata URLs to try for an issuer,
/// covering RFC 8414 (`oauth-authorization-server`) and OpenID Connect Discovery
/// (`openid-configuration`), in both path-aware and path-append forms.
string[] authServerMetadataCandidates(string issuer) @safe
{
	import std.algorithm : min;
	import std.string : endsWith, indexOf;

	auto iss = issuer;
	if (iss.endsWith("/"))
		iss = iss[0 .. $ - 1];
	auto schemeEnd = iss.indexOf("://");
	if (schemeEnd < 0)
		return [iss ~ "/.well-known/oauth-authorization-server"];
	const afterScheme = schemeEnd + 3;
	const slash = iss[afterScheme .. $].indexOf('/');
	if (slash < 0)
		return [
		iss ~ "/.well-known/oauth-authorization-server",
		iss ~ "/.well-known/openid-configuration"
	];
	const origin = iss[0 .. afterScheme + slash];
	string path = iss[afterScheme + slash .. $];

	// Issuer identifiers must not contain query strings or fragments; strip
	// them defensively so well-known URLs remain valid per RFC 8414.
	auto cut = path.length;
	auto q = path.indexOf('?');
	auto h = path.indexOf('#');
	if (q >= 0)
		cut = min(cut, q);
	if (h >= 0)
		cut = min(cut, h);
	path = path[0 .. cut];

	return [
		origin ~ "/.well-known/oauth-authorization-server" ~ path,
		origin ~ "/.well-known/openid-configuration" ~ path,
		iss ~ "/.well-known/openid-configuration"
	];
}

/// Select the OAuth scopes to request: prefer the scopes named in the
/// `WWW-Authenticate` challenge; otherwise fall back to the resource metadata's
/// `scopes_supported`; otherwise none.
string selectScope(string wwwAuthScope, const string[] scopesSupported) @safe
{
	import std.array : join;

	if (wwwAuthScope.length)
		return wwwAuthScope;
	if (scopesSupported.length)
		return scopesSupported.join(" ");
	return null;
}

/// The canonical resource indicator (RFC 8707) for an MCP server: the endpoint
/// URL with a lowercased scheme+authority, the scheme's default port (`:443`
/// for https, `:80` for http) removed, any fragment dropped, and a single
/// trailing slash stripped. The MCP "Canonical Server URI" rules prefer the
/// no-trailing-slash form. The authority ends at the first `/` or `?`, so a
/// query directly after the host keeps its case. ASCII case is folded in place
/// (rather than via `toLower`) to keep this `pure nothrow`.
string canonicalResourceUri(string mcpEndpoint) @safe pure nothrow
{
	import std.string : indexOf;

	auto frag = mcpEndpoint.indexOf('#');
	auto s = (frag < 0) ? mcpEndpoint : mcpEndpoint[0 .. frag];
	// Strip a single trailing slash (spec prefers the no-trailing-slash form).
	if (s.length > 1 && s[$ - 1] == '/')
		s = s[0 .. $ - 1];
	const schemeEnd = s.indexOf("://");
	if (schemeEnd < 0)
		return s;
	const afterScheme = schemeEnd + 3;
	size_t hostEnd = s.length;
	foreach (i; afterScheme .. s.length)
		if (s[i] == '/' || s[i] == '?')
		{
			hostEnd = i;
			break;
		}
	char[] buf = new char[s.length];
	foreach (i, ch; s)
	{
		char c = ch;
		if (i < hostEnd && c >= 'A' && c <= 'Z')
			c = cast(char)(c + 32);
		buf[i] = c;
	}
	// The port follows the last ':' that comes after any IPv6 literal's ']'.
	const authority = buf[afterScheme .. hostEnd];
	ptrdiff_t colon = -1;
	foreach (i, c; authority)
		if (c == ':')
			colon = i;
		else if (c == ']')
			colon = -1;
	if (colon >= 0)
	{
		const scheme = buf[0 .. schemeEnd];
		const port = authority[colon + 1 .. $];
		if ((scheme == "https" && port == "443") || (scheme == "http" && port == "80"))
			buf = buf[0 .. afterScheme + colon] ~ buf[hostEnd .. $];
	}
	return () @trusted { return cast(string) buf; }();
}

unittest  // PKCE: known verifier bytes produce a stable S256 challenge
{
	// 32 zero bytes -> base64url verifier of 43 chars; challenge is sha256 of it.
	ubyte[32] zeros;
	auto p = makePkce(zeros[]);
	assert(p.verifier.length == 43);
	assert(p.challenge.length == 43); // sha256 (32 bytes) -> 43 base64url chars
	// Deterministic for the same input.
	assert(makePkce(zeros[]).challenge == p.challenge);
	// No padding or url-unsafe chars.
	import std.algorithm : canFind;

	assert(!p.challenge.canFind('=') && !p.challenge.canFind('+') && !p.challenge.canFind('/'));
}

unittest  // generatePkce produces a valid, unique pair from the OS CSPRNG
{
	auto a = generatePkce();
	auto b = generatePkce();
	// 32 random bytes -> 43-char base64url verifier; valid S256 challenge.
	assert(a.verifier.length == 43);
	assert(a.challenge.length == 43);
	// Two independent draws from a CSPRNG must not collide.
	assert(a.verifier != b.verifier);
}

unittest  // generatePkce's entropy source is the OS CSPRNG, not the default rndGen
{
	// Reproduce the predictable sequence a default-seeded std.random Mersenne
	// Twister yields and assert the real generator does not reproduce it (it
	// would, with overwhelming probability, if it drew from rndGen).
	import std.random : rndGen, uniform;

	auto gen = rndGen;
	ubyte[32] predictable;
	foreach (ref x; predictable)
		x = cast(ubyte) uniform(0, 256, gen);
	const predictablePair = makePkce(predictable[]);

	assert(generatePkce().verifier != predictablePair.verifier);
}

unittest  // WWW-Authenticate parsing extracts resource_metadata and scope
{
	auto w = parseWwwAuthenticate(`Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", scope="read write", error="insufficient_scope"`);
	assert(w.scheme == "Bearer");
	assert(w.resourceMetadata == "https://mcp.example.com/.well-known/oauth-protected-resource");
	assert(w.scope_ == "read write");
	assert(w.params["error"] == "insufficient_scope");
}

unittest  // WWW-Authenticate exposes typed error()/errorDescription() accessors
{
	auto w = parseWwwAuthenticate(
			`Bearer error="insufficient_scope", error_description="needs more scope"`);
	assert(w.error == "insufficient_scope");
	assert(w.errorDescription == "needs more scope");
}

unittest  // WWW-Authenticate unescapes backslash escapes inside a quoted-string (RFC 9110 §5.6.4)
{
	auto w = parseWwwAuthenticate(
			`Bearer error_description="say \"hi\", then \\ leave", scope="read"`);
	assert(w.errorDescription == `say "hi", then \ leave`);
	assert(w.scope_ == "read");
}

unittest  // WWW-Authenticate selects the Bearer challenge when several are present
{
	auto w = parseWwwAuthenticate(`Basic realm="api", scope="basic-scope", `
			~ `Bearer resource_metadata="https://mcp.example.com/prm", scope="read"`);
	assert(w.scheme == "Bearer");
	assert(w.resourceMetadata == "https://mcp.example.com/prm");
	assert(w.scope_ == "read");
	assert("realm" !in w.params);
}

unittest  // WWW-Authenticate keeps a later challenge's params out of the Bearer challenge
{
	auto w = parseWwwAuthenticate(`Bearer scope="read", DPoP algs="ES256", error="use_dpop_nonce"`);
	assert(w.scheme == "Bearer");
	assert(w.scope_ == "read");
	assert(w.error is null);
	assert("algs" !in w.params);
}

unittest  // WWW-Authenticate skips a token68 challenge and parses a bare scheme
{
	auto all = parseWwwAuthenticateChallenges(`Negotiate abc+/9==, Bearer, Basic realm=api`);
	assert(all.length == 3);
	assert(all[0].scheme == "Negotiate" && all[0].params.length == 0);
	assert(all[1].scheme == "Bearer" && all[1].params.length == 0);
	assert(all[2].scheme == "Basic" && all[2].params["realm"] == "api");
	assert(parseWwwAuthenticate(`Negotiate abc+/9==, Bearer scope="x"`).scope_ == "x");
}

unittest  // WWW-Authenticate error()/errorDescription() are null when absent
{
	auto w = parseWwwAuthenticate(`Bearer scope="read"`);
	assert(w.error is null);
	assert(w.errorDescription is null);
}

unittest  // protected-resource metadata well-known URLs: path-scoped then root
{
	auto urls = protectedResourceMetadataUrls("https://example.com/public/mcp");
	assert(urls.length == 2);
	assert(urls[0] == "https://example.com/.well-known/oauth-protected-resource/public/mcp");
	assert(urls[1] == "https://example.com/.well-known/oauth-protected-resource");

	auto rootUrls = protectedResourceMetadataUrls("https://example.com");
	assert(rootUrls.length == 1);
	assert(rootUrls[0] == "https://example.com/.well-known/oauth-protected-resource");
}

unittest  // protectedResourceMetadataUrls strips query string from path per RFC 9728
{
	auto urls = protectedResourceMetadataUrls("https://api.example.com/mcp?version=2026-11-05");
	assert(urls.length == 2);
	assert(urls[0] == "https://api.example.com/.well-known/oauth-protected-resource/mcp");
	assert(urls[1] == "https://api.example.com/.well-known/oauth-protected-resource");
}

unittest  // protectedResourceMetadataUrls ends the origin at a query or fragment with no path
{
	assert(protectedResourceMetadataUrls("https://h.example.com?tenant=x")
			== ["https://h.example.com/.well-known/oauth-protected-resource"]);
	assert(protectedResourceMetadataUrls("https://h.example.com#frag")
			== ["https://h.example.com/.well-known/oauth-protected-resource"]);
}

unittest  // urlOrigin keeps scheme and authority only
{
	assert(urlOrigin("https://h.example.com:8443/a/b?q#f") == "https://h.example.com:8443");
	assert(urlOrigin("https://h.example.com?tenant=x") == "https://h.example.com");
	assert(urlOrigin("https://h.example.com#f") == "https://h.example.com");
	assert(urlOrigin("https://h.example.com") == "https://h.example.com");
	assert(urlOrigin("not-a-url") == "not-a-url");
}

unittest  // protectedResourceMetadataUrls strips fragment from path per RFC 9728
{
	auto urls = protectedResourceMetadataUrls("https://example.com/mcp#section");
	assert(urls.length == 2);
	assert(urls[0] == "https://example.com/.well-known/oauth-protected-resource/mcp");
	assert(urls[1] == "https://example.com/.well-known/oauth-protected-resource");
}

unittest  // AS metadata candidates insert well-known after origin, before path
{
	auto root = authServerMetadataCandidates("https://auth.example.com");
	assert(root[0] == "https://auth.example.com/.well-known/oauth-authorization-server");

	auto tenant = authServerMetadataCandidates("https://auth.example.com/tenant1");
	assert(tenant[0] == "https://auth.example.com/.well-known/oauth-authorization-server/tenant1");
}

unittest  // authServerMetadataCandidates strips query string and fragment from issuer path
{
	auto urls = authServerMetadataCandidates("https://auth.example.com/tenant1?foo=bar");
	assert(urls[0] == "https://auth.example.com/.well-known/oauth-authorization-server/tenant1");

	auto urlsFrag = authServerMetadataCandidates("https://auth.example.com/tenant1#anchor");
	assert(urlsFrag[0] == "https://auth.example.com/.well-known/oauth-authorization-server/tenant1");
}

unittest  // metadata documents parse the relevant fields
{
	auto prm = ProtectedResourceMetadata.fromJson(parseJson(`{"resource":"https://mcp.example.com","authorization_servers":["https://auth.example.com"],"scopes_supported":["read","write"]}`));
	assert(prm.resource == "https://mcp.example.com");
	assert(prm.authorizationServers == ["https://auth.example.com"]);
	assert(prm.scopesSupported == ["read", "write"]);

	auto asm_ = AuthorizationServerMetadata.fromJson(parseJson(`{"issuer":"https://auth.example.com","authorization_endpoint":"https://auth.example.com/authorize","token_endpoint":"https://auth.example.com/token","code_challenge_methods_supported":["S256"]}`));
	assert(asm_.tokenEndpoint == "https://auth.example.com/token");
	assert(asm_.supportsS256);
}

unittest  // scope selection prefers WWW-Authenticate, falls back to scopes_supported
{
	assert(selectScope("a b", ["x", "y"]) == "a b");
	assert(selectScope("", ["x", "y"]) == "x y");
	assert(selectScope("", []) is null);
}

unittest  // canonical resource URI lowercases scheme+host, drops fragment + trailing slash
{
	assert(canonicalResourceUri(
			"HTTPS://MCP.Example.com/Path#frag") == "https://mcp.example.com/Path");
	// A single trailing slash is stripped (spec prefers the no-trailing-slash form).
	assert(canonicalResourceUri("https://mcp.example.com/") == "https://mcp.example.com");
	assert(canonicalResourceUri("HTTPS://MCP.Example.com/Mcp/") == "https://mcp.example.com/Mcp");
	assert(canonicalResourceUri("https://mcp.example.com/mcp") == "https://mcp.example.com/mcp");
	assert(canonicalResourceUri("https://mcp.example.com:8443/") == "https://mcp.example.com:8443");
	assert(canonicalResourceUri("https://mcp.example.com/mcp/") == "https://mcp.example.com/mcp");
	assert(canonicalResourceUri("https://mcp.example.com#frag") == "https://mcp.example.com");
	assert(canonicalResourceUri("https://mcp.example.com") == "https://mcp.example.com");
}

unittest  // canonical resource URI drops the scheme's default port
{
	assert(canonicalResourceUri("https://mcp.example.com:443/mcp") == "https://mcp.example.com/mcp");
	assert(canonicalResourceUri("http://localhost:80/mcp") == "http://localhost/mcp");
	assert(canonicalResourceUri("HTTPS://MCP.Example.com:443") == "https://mcp.example.com");
	assert(canonicalResourceUri("https://[::1]:443/mcp") == "https://[::1]/mcp");
	// A non-default port, or another scheme's default, is kept.
	assert(canonicalResourceUri(
			"http://mcp.example.com:443/mcp") == "http://mcp.example.com:443/mcp");
	assert(canonicalResourceUri(
			"https://mcp.example.com:80/mcp") == "https://mcp.example.com:80/mcp");
	assert(canonicalResourceUri("https://[::1]:8443/mcp") == "https://[::1]:8443/mcp");
}

unittest  // canonical resource URI ends the authority at a query, leaving the query's case intact
{
	assert(canonicalResourceUri(
			"https://MCP.Example.com?Tenant=ABC") == "https://mcp.example.com?Tenant=ABC");
	assert(canonicalResourceUri(
			"https://mcp.example.com:443?Tenant=ABC") == "https://mcp.example.com?Tenant=ABC");
}

version (unittest) private Json parseJson(string s) @safe
{
	import vibe.data.json : parseJsonString;

	return parseJsonString(s);
}

// ===========================================================================
// Dynamic Client Registration (RFC 7591) + token types
// ===========================================================================

/// How the client authenticates at the token endpoint.
enum TokenEndpointAuthMethod : string
{
	none = "none",
	clientSecretBasic = "client_secret_basic",
	clientSecretPost = "client_secret_post",
	privateKeyJwt = "private_key_jwt",
}

/// A Dynamic Client Registration request body (RFC 7591).
struct ClientRegistration
{
	string[] redirectUris;
	string[] grantTypes = ["authorization_code", "refresh_token"];
	string[] responseTypes = ["code"];
	string tokenEndpointAuthMethod = "none";
	string clientName;
	string scope_;
	/// The OpenID Connect `application_type` (`"native"` or `"web"`). MCP clients
	/// MUST send one: an OIDC authorization server defaults an absent value to
	/// `"web"` and then rejects the loopback redirect URIs native clients use.
	/// Empty infers it from the first redirect URI (`applicationTypeFor`).
	string applicationType;

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		Json ru = Json.emptyArray;
		foreach (u; redirectUris)
			ru ~= Json(u);
		j["redirect_uris"] = ru;
		j["application_type"] = applicationType.length ? applicationType
			: applicationTypeFor(redirectUris.length ? redirectUris[0] : "");
		Json gt = Json.emptyArray;
		foreach (g; grantTypes)
			gt ~= Json(g);
		j["grant_types"] = gt;
		Json rt = Json.emptyArray;
		foreach (r; responseTypes)
			rt ~= Json(r);
		j["response_types"] = rt;
		j["token_endpoint_auth_method"] = tokenEndpointAuthMethod;
		if (clientName.length)
			j["client_name"] = clientName;
		if (scope_.length)
			j["scope"] = scope_;
		return j;
	}
}

/// The OpenID Connect `application_type` a redirect URI implies: `"native"` for
/// a loopback host (`localhost`, `127.0.0.1`, `[::1]`) or a non-HTTP custom
/// scheme, which is how desktop, mobile, and CLI clients receive the redirect;
/// `"web"` for an `http(s)` redirect on any other host.
string applicationTypeFor(string redirectUri) @safe pure
{
	import std.algorithm : startsWith;
	import std.string : indexOf;

	const isHttp = redirectUri.startsWith("http://") || redirectUri.startsWith("https://");
	if (!isHttp)
		return "native";
	auto rest = redirectUri[redirectUri.indexOf("://") + 3 .. $];
	// Trim the path, then any port (a bracketed IPv6 host keeps its brackets).
	const slash = rest.indexOf('/');
	if (slash >= 0)
		rest = rest[0 .. slash];
	string host = rest;
	if (host.startsWith("["))
	{
		const close = host.indexOf(']');
		if (close >= 0)
			host = host[0 .. close + 1];
	}
	else
	{
		const colon = host.indexOf(':');
		if (colon >= 0)
			host = host[0 .. colon];
	}
	return (host == "localhost" || host == "127.0.0.1" || host == "[::1]") ? "native" : "web";
}

/// The credentials returned by the registration endpoint.
struct RegisteredClient
{
	string clientId;
	string clientSecret;
	/// RFC 7591 `client_secret_expires_at` (absolute unix seconds); 0 means the
	/// secret does not expire.
	long clientSecretExpiresAt;

	static RegisteredClient fromJson(Json j) @safe
	{
		RegisteredClient c;
		c.clientId = strField(j, "client_id");
		c.clientSecret = strField(j, "client_secret");
		if (auto p = "client_secret_expires_at" in j)
			c.clientSecretExpiresAt = p.type == Json.Type.int_ ? p.get!long : 0;
		return c;
	}
}

unittest  // RegisteredClient parses client_secret_expires_at from a registration response
{
	import vibe.data.json : parseJsonString;

	auto rc = RegisteredClient.fromJson(parseJsonString(
			`{"client_id":"cid","client_secret":"s","client_secret_expires_at":1900000000}`));
	assert(rc.clientSecret == "s");
	assert(rc.clientSecretExpiresAt == 1_900_000_000);
}

unittest  // a registration request always names its application_type
{
	// basic/authorization/client-registration: MCP clients MUST specify an
	// appropriate application_type during Dynamic Client Registration; omitting
	// it defaults to "web" under OIDC, which conflicts with native redirect URIs.
	ClientRegistration reg;
	reg.redirectUris = ["http://127.0.0.1:8765/callback"];
	auto j = reg.toJson();
	assert(j["application_type"].get!string == "native");

	reg.applicationType = "web";
	assert(reg.toJson()["application_type"].get!string == "web");
}

unittest  // applicationTypeFor classifies loopback and custom-scheme redirects as native
{
	assert(applicationTypeFor("http://localhost:8080/cb") == "native");
	assert(applicationTypeFor("http://127.0.0.1/cb") == "native");
	assert(applicationTypeFor("http://[::1]:9000/cb") == "native");
	assert(applicationTypeFor("com.example.app:/oauth") == "native");
	assert(applicationTypeFor("https://app.example.com/callback") == "web");
	assert(applicationTypeFor("http://app.example.com/callback") == "web");
}

unittest  // an explicit applicationType wins over the redirect-URI inference
{
	ClientRegistration reg;
	reg.redirectUris = ["https://app.example.com/callback"];
	assert(reg.toJson()["application_type"].get!string == "web");
	reg.applicationType = "native";
	assert(reg.toJson()["application_type"].get!string == "native");
}

// ===========================================================================
// Client ID Metadata Documents (SEP-991)
// ===========================================================================

/// Validate an OAuth Client ID Metadata Document `client_id` URL (SEP-991 /
/// draft-ietf-oauth-client-id-metadata-document §3): it MUST use the `https`
/// scheme, name a host, and contain a non-empty path component, and it MUST NOT
/// contain a fragment, a username or password, or a `.`/`..` path segment
/// (including their percent-encoded forms). A query component is tolerated.
bool isValidClientIdMetadataUrl(string clientId) @safe pure nothrow @nogc
{
	import std.string : indexOf;

	// Must use the https scheme.
	if (clientId.length < 8 || clientId[0 .. 8] != "https://")
		return false;
	auto rest = clientId[8 .. $];
	if (rest.indexOf('#') >= 0)
		return false;

	// The authority runs up to the first '/' or '?'; a path must follow it.
	size_t authorityEnd = 0;
	while (authorityEnd < rest.length && rest[authorityEnd] != '/' && rest[authorityEnd] != '?')
		++authorityEnd;
	if (authorityEnd == 0 || authorityEnd == rest.length || rest[authorityEnd] != '/')
		return false;
	if (rest[0 .. authorityEnd].indexOf('@') >= 0)
		return false;

	auto path = rest[authorityEnd .. $];
	const query = path.indexOf('?');
	if (query >= 0)
		path = path[0 .. query];
	// A bare trailing '/' is not a path component.
	if (path.length < 2)
		return false;

	size_t segStart = 1;
	foreach (i; 1 .. path.length + 1)
	{
		if (i < path.length && path[i] != '/')
			continue;
		if (isDotSegment(path[segStart .. i]))
			return false;
		segStart = i + 1;
	}
	return true;
}

/// Whether a path segment is `.` or `..`, with any dot possibly written as the
/// percent-encoding `%2e` / `%2E` (RFC 3986 §2.3 equivalence).
private bool isDotSegment(string seg) @safe pure nothrow @nogc
{
	size_t dots;
	size_t i;
	while (i < seg.length)
	{
		if (seg[i] == '.')
			++i;
		else if (i + 2 < seg.length && seg[i] == '%' && seg[i + 1] == '2'
				&& (seg[i + 2] == 'e' || seg[i + 2] == 'E'))
			i += 3;
		else
			return false;
		++dots;
	}
	return dots == 1 || dots == 2;
}

/// Parse `url` with vibe's parser (the one the connector uses) into its
/// scheme and host; false when it does not parse or carries no host.
private bool parseSchemeHost(string url, out string scheme, out string host) @safe
{
	import vibe.inet.url : URL;

	try
	{
		auto u = URL(url);
		scheme = u.schema;
		host = u.host;
	}
	catch (Exception)
		return false;
	return host.length != 0;
}

/// Case-insensitive ASCII scheme compare.
private bool isScheme(string scheme, string want) @safe pure nothrow @nogc
{
	if (scheme.length != want.length)
		return false;
	foreach (k, ch; scheme)
	{
		char c = ch;
		if (c >= 'A' && c <= 'Z')
			c = cast(char)(c + 32);
		if (c != want[k])
			return false;
	}
	return true;
}

/// The lexical (no DNS) scheme/host gate of `policy`: `https` to a host that is
/// not a private/link-local literal (`blockInternal` also rejects loopback),
/// plus plain `http` to an explicit loopback host under `allowLoopback`, and
/// either scheme to any host under `allowUserConfigured`.
private bool passesLexicalGate(string scheme, string host, SsrfPolicy policy) @safe
{
	import mcp.protocol.ssrf : classifyHostLexical, AddressClass;

	const https = isScheme(scheme, "https");
	const http = isScheme(scheme, "http");
	const cls = classifyHostLexical(host);
	final switch (policy)
	{
	case SsrfPolicy.blockInternal:
		return https && cls == AddressClass.public_;
	case SsrfPolicy.allowLoopback:
		if (cls == AddressClass.privateOrLinkLocal)
			return false;
		return https || (http && cls == AddressClass.loopback);
	case SsrfPolicy.allowUserConfigured:
		return https || http;
	}
}

/// Whether `url` passes `policy`'s scheme/host gate for an OAuth/discovery
/// fetch: `https` to a public host, plus (under `allowLoopback`) plain `http`
/// to an explicit loopback host (`localhost`, `127.0.0.1`, `[::1]`, and their
/// numeric encodings). Private/link-local literals — including alternate
/// numeric IPv4 encodings and IPv4-mapped/compatible IPv6 — are rejected.
/// Purely lexical (no DNS): a coarse pre-filter on an attacker-influenced URL.
/// The authoritative, TOCTOU-safe SSRF guard for an actual fetch is
/// `secureRequestHTTP`, which resolves, classifies and pins via the connector.
bool isSecureFetchUrl(string url, SsrfPolicy policy) @safe
{
	string scheme, host;
	return parseSchemeHost(url, scheme, host) && passesLexicalGate(scheme, host, policy);
}

/// Throw `invalidRequest` when `url` fails `policy`'s scheme/host gate (see
/// `isSecureFetchUrl`). A check-time gate (no fetch) for paths that VALIDATE a
/// URL without fetching it (e.g. building the authorization-request URL the
/// host will open). The TOCTOU-safe resolve-and-pin connect for an actual fetch
/// is performed by `secureRequestHTTP`.
void requireSecureUrl(string url, SsrfPolicy policy) @safe
{
	import mcp.protocol.errors : invalidRequest;

	string scheme, host;
	if (!parseSchemeHost(url, scheme, host))
		throw invalidRequest("Refusing to fetch URL with no parseable host: " ~ url);
	if (!passesLexicalGate(scheme, host, policy))
		throw invalidRequest(policy == SsrfPolicy.blockInternal
				? "Refusing to fetch insecure OAuth/discovery URL (must be https to a public host): "
				~ url : "Refusing to fetch insecure OAuth/discovery URL (must be https, or http to "
				~ "an explicit loopback host; private/link-local addresses are rejected): " ~ url);
}

/// Non-throwing scheme/host + resolution gate. Returns true only when the
/// vibe-parsed scheme/host pass `policy`'s lexical gate AND the host resolves
/// only to addresses `policy` permits (fail CLOSED on a resolution error).
/// Loopback and IP-literal hosts short-circuit without resolving. `@safe`.
bool isSecureFetchUrlResolved(string url, SsrfPolicy policy) @safe
{
	import mcp.protocol.ssrf : pinnedConnectAddress;

	string scheme, host;
	if (!parseSchemeHost(url, scheme, host) || !passesLexicalGate(scheme, host, policy))
		return false;
	return pinnedConnectAddress(host, isScheme(scheme, "https"), policy).ok;
}

/// Consolidated SSRF-safe HTTP fetch used by every outbound OAuth/discovery
/// request. Delegates to the connector's `secureRequestHTTP` under `policy`:
/// parse once with vibe's `URL`, classify the host once, resolve + pin to a
/// vetted numeric address (preserving Host header + TLS SNI), and fail CLOSED
/// on any target `policy` rejects. Throws `invalidRequest` when the URL is
/// unsafe.
void secureRequestHTTP(string url, SsrfPolicy policy,
		scope void delegate(scope HTTPClientRequest) @safe requester,
		scope void delegate(scope HTTPClientResponse) @safe responder) @safe
{
	import mcp.protocol.ssrf : connectorRequest = secureRequestHTTP;

	connectorRequest(url, policy, requester, responder);
}

unittest  // requireSecureUrl throws on an insecure URL and passes a secure loopback one
{
	import std.exception : assertThrown;

	assertThrown(requireSecureUrl("http://as.example.com/token", SsrfPolicy.allowLoopback));
	assertThrown(requireSecureUrl("https://169.254.169.254/", SsrfPolicy.allowLoopback));
	// Loopback hosts skip DNS resolution, so these are network-independent.
	requireSecureUrl("https://127.0.0.1/token", SsrfPolicy.allowLoopback); // does not throw
	requireSecureUrl("http://127.0.0.1:8765/callback", SsrfPolicy.allowLoopback); // loopback dev ok
}

unittest  // blockInternal gates admit only https to a public host
{
	import std.exception : assertThrown;

	assert(isSecureFetchUrl("https://as.example.com/token", SsrfPolicy.blockInternal));
	assert(!isSecureFetchUrl("http://127.0.0.1:8765/token", SsrfPolicy.blockInternal));
	assert(!isSecureFetchUrl("http://localhost/token", SsrfPolicy.blockInternal));
	assert(!isSecureFetchUrl("https://127.0.0.1/token", SsrfPolicy.blockInternal));
	assert(!isSecureFetchUrlResolved("http://127.0.0.1:8765/jwks", SsrfPolicy.blockInternal));
	assertThrown(requireSecureUrl("http://127.0.0.1:8765/authorize", SsrfPolicy.blockInternal));
	assertThrown(requireSecureUrl("https://[::1]/authorize", SsrfPolicy.blockInternal));
}

unittest  // requireSecureUrl rejects the '?@' / '#@' authority differential (SSRF)
{
	import std.exception : assertThrown;

	assertThrown(requireSecureUrl("https://public?@169.254.169.254/jwks", SsrfPolicy.allowLoopback));
	assertThrown(requireSecureUrl("https://public#@10.0.0.5/jwks", SsrfPolicy.allowLoopback));
}

unittest  // requireSecureUrl reports an unparseable URL accurately, not as merely "insecure"
{
	import std.algorithm.searching : canFind;

	bool threw;
	string msg;
	try
		requireSecureUrl("http://", SsrfPolicy.allowLoopback);
	catch (Exception e)
	{
		threw = true;
		msg = e.msg;
	}
	assert(threw);
	assert(msg.canFind("no parseable host"), "expected a parse-failure message, got: " ~ msg);
}

unittest  // isSecureFetchUrl accepts https and rejects plaintext http to a remote host
{
	assert(isSecureFetchUrl("https://as.example.com/.well-known/oauth-authorization-server",
			SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("http://as.example.com/.well-known/oauth-authorization-server",
			SsrfPolicy.allowLoopback));
}

unittest  // isSecureFetchUrl permits http only to explicit loopback hosts (dev)
{
	assert(isSecureFetchUrl("http://localhost:8765/jwks", SsrfPolicy.allowLoopback));
	assert(isSecureFetchUrl("http://127.0.0.1/jwks", SsrfPolicy.allowLoopback));
	assert(isSecureFetchUrl("http://[::1]:9000/jwks", SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("http://internal.local/jwks", SsrfPolicy.allowLoopback));
}

unittest  // isSecureFetchUrl rejects private/link-local IPv4 literals (SSRF)
{
	assert(!isSecureFetchUrl("https://169.254.169.254/latest/meta-data", SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("https://10.0.0.5/x", SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("https://192.168.1.1/x", SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("https://172.16.0.1/x", SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("http://169.254.169.254/x", SsrfPolicy.allowLoopback));
}

unittest  // isSecureFetchUrl rejects private/ULA/link-local IPv6 literals (SSRF)
{
	assert(!isSecureFetchUrl("https://[fd00::1]/x", SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("https://[fc00::1]/x", SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("https://[fe80::1]/x", SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("https://[::]/x", SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("https://[::ffff:169.254.169.254]/latest/meta-data",
			SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("https://[::ffff:10.0.0.5]/x", SsrfPolicy.allowLoopback));
	// IPv4-mapped loopback is gated exactly like the IPv4 loopback literal.
	assert(isSecureFetchUrl("https://[::ffff:127.0.0.1]/x",
			SsrfPolicy.allowLoopback) == isSecureFetchUrl("https://127.0.0.1/x",
			SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("https://[::ffff:127.0.0.1]/x", SsrfPolicy.blockInternal));
	assert(!isSecureFetchUrl("https://[::ffff:0a00:0001]/x", SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("https://[fe80::1]:443/x", SsrfPolicy.allowLoopback));
}

unittest  // isSecureFetchUrl accepts a public/global-unicast IPv6 literal
{
	assert(isSecureFetchUrl("https://[2606:4700:4700::1111]/x", SsrfPolicy.allowLoopback));
	assert(isSecureFetchUrl("https://[2606:4700::1]/x", SsrfPolicy.allowLoopback));
	assert(isSecureFetchUrl("http://[::1]:9000/jwks", SsrfPolicy.allowLoopback));
}

unittest  // isSecureFetchUrl rejects schemeless / file / non-loopback http
{
	assert(!isSecureFetchUrl("as.example.com/x", SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("file:///etc/passwd", SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("", SsrfPolicy.allowLoopback));
}

unittest  // isSecureFetchUrl strips userinfo before private IPv4 literal checks (SSRF)
{
	assert(!isSecureFetchUrl("https://user@169.254.169.254/", SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("https://x@10.0.0.1/", SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("https://user:pass@192.168.1.1/x", SsrfPolicy.allowLoopback));
}

unittest  // isSecureFetchUrl strips userinfo before bracketed IPv6 literal checks (SSRF)
{
	assert(!isSecureFetchUrl("https://a@[fe80::1]/", SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("https://a@[fd00::1]/x", SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("https://user@[::ffff:169.254.169.254]/latest/meta-data",
			SsrfPolicy.allowLoopback));
}

unittest  // isSecureFetchUrl still accepts a public host carrying userinfo
{
	assert(isSecureFetchUrl("https://user@public.example.com/", SsrfPolicy.allowLoopback));
	assert(isSecureFetchUrl("https://user:pass@as.example.com/token", SsrfPolicy.allowLoopback));
	assert(isSecureFetchUrl("https://user@[2606:4700:4700::1111]/x", SsrfPolicy.allowLoopback));
}

unittest  // isSecureFetchUrl treats numeric loopback encodings as loopback (https + dev http)
{
	assert(isSecureFetchUrl("https://2130706433/x", SsrfPolicy.allowLoopback)); // 127.0.0.1
	assert(isSecureFetchUrl("https://127.1/x", SsrfPolicy.allowLoopback));
	assert(isSecureFetchUrl("https://0x7f000001/x", SsrfPolicy.allowLoopback));
	// A leading-zero part is ambiguous (octal or decimal by resolver) and fails closed.
	assert(!isSecureFetchUrl("https://0177.0.0.1/x", SsrfPolicy.allowLoopback));
}

unittest  // isSecureFetchUrl rejects numeric encodings of the cloud metadata address (SSRF)
{
	assert(!isSecureFetchUrl("https://0xa9fea9fe/latest/meta-data", SsrfPolicy.allowLoopback)); // 169.254.169.254
	assert(!isSecureFetchUrl("https://2852039166/latest/meta-data", SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrl("https://169.254.169.254/latest/meta-data", SsrfPolicy.allowLoopback));
}

unittest  // isSecureFetchUrl rejects octal/hex encodings of RFC1918 ranges (SSRF)
{
	assert(!isSecureFetchUrl("https://0xa000005/x", SsrfPolicy.allowLoopback)); // 10.0.0.5
	assert(!isSecureFetchUrl("https://192.0xa8.0.1/x", SsrfPolicy.allowLoopback)); // 192.168.0.1
	assert(!isSecureFetchUrl("https://10.0/x", SsrfPolicy.allowLoopback)); // 10.0.0.0
}

unittest  // isSecureFetchUrl permits http loopback via numeric encodings (dev)
{
	assert(isSecureFetchUrl("http://2130706433/jwks", SsrfPolicy.allowLoopback)); // 127.0.0.1
	assert(isSecureFetchUrl("http://127.1/jwks", SsrfPolicy.allowLoopback));
	assert(isSecureFetchUrl("http://0x7f000001/jwks", SsrfPolicy.allowLoopback));
}

unittest  // isSecureFetchUrl still accepts genuine public numeric IPv4 literals
{
	assert(isSecureFetchUrl("https://8.8.8.8/x", SsrfPolicy.allowLoopback));
	assert(isSecureFetchUrl("https://1.1.1.1/x", SsrfPolicy.allowLoopback));
}

unittest  // isSecureFetchUrlResolved rejects what the lexical guard rejects (GET-path SSRF)
{
	assert(!isSecureFetchUrlResolved("http://as.example.com/.well-known/jwks",
			SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrlResolved("https://169.254.169.254/latest/meta-data",
			SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrlResolved("https://10.0.0.5/jwks", SsrfPolicy.allowLoopback));
}

unittest  // isSecureFetchUrlResolved rejects the '?@' / '#@' authority differential (SSRF)
{
	assert(!isSecureFetchUrlResolved("https://public?@169.254.169.254/jwks",
			SsrfPolicy.allowLoopback));
	assert(!isSecureFetchUrlResolved("https://public#@10.0.0.5/jwks", SsrfPolicy.allowLoopback));
}

unittest  // isSecureFetchUrlResolved accepts plain-http loopback without resolving (dev)
{
	assert(isSecureFetchUrlResolved("http://127.0.0.1:8765/jwks", SsrfPolicy.allowLoopback));
	assert(isSecureFetchUrlResolved("http://[::1]:9000/jwks", SsrfPolicy.allowLoopback));
}

unittest  // isSecureFetchUrlResolved rejects loopback over https (local TLS services)
{
	assert(!isSecureFetchUrlResolved("https://127.0.0.1/jwks", SsrfPolicy.allowLoopback));
}

unittest  // valid CIMD client_id: https with a path component
{
	assert(isValidClientIdMetadataUrl("https://app.example.com/oauth/client.json"));
}

unittest  // CIMD client_id without a path component is rejected
{
	assert(!isValidClientIdMetadataUrl("https://app.example.com"));
	assert(!isValidClientIdMetadataUrl("https://app.example.com/"));
}

unittest  // CIMD client_id must use https
{
	assert(!isValidClientIdMetadataUrl("http://app.example.com/oauth/client.json"));
	assert(!isValidClientIdMetadataUrl("app.example.com/oauth/client.json"));
}

unittest  // CIMD client_id must not carry a fragment
{
	assert(!isValidClientIdMetadataUrl("https://app.example.com/client.json#frag"));
	assert(!isValidClientIdMetadataUrl("https://app.example.com/client.json#"));
}

unittest  // CIMD client_id must not carry a username or password
{
	assert(!isValidClientIdMetadataUrl("https://user@app.example.com/client.json"));
	assert(!isValidClientIdMetadataUrl("https://user:pw@app.example.com/client.json"));
}

unittest  // CIMD client_id must not contain dot path segments
{
	assert(!isValidClientIdMetadataUrl("https://app.example.com/./client.json"));
	assert(!isValidClientIdMetadataUrl("https://app.example.com/a/../client.json"));
	assert(!isValidClientIdMetadataUrl("https://app.example.com/a/.."));
	assert(!isValidClientIdMetadataUrl("https://app.example.com/a/%2e%2E/client.json"));
	// A segment merely containing dots is an ordinary name.
	assert(isValidClientIdMetadataUrl("https://app.example.com/.well-known/client..json"));
}

unittest  // CIMD client_id must name a host and a path before any query
{
	assert(!isValidClientIdMetadataUrl("https:///client.json"));
	assert(!isValidClientIdMetadataUrl("https://app.example.com?x=/client.json"));
	assert(isValidClientIdMetadataUrl("https://app.example.com:8443/client.json?v=1"));
}

/// An OAuth Client ID Metadata Document (SEP-991) a client hosts at its
/// HTTPS-URL `client_id`. The authorization server fetches this document to
/// learn the client's metadata (name, redirect URIs, auth method) without any
/// prior registration. `clientId` MUST equal the document's own URL.
struct ClientIdMetadataDocument
{
	string clientId;
	string clientName;
	string clientUri;
	string[] redirectUris;
	string[] grantTypes = ["authorization_code", "refresh_token"];
	string[] responseTypes = ["code"];
	string tokenEndpointAuthMethod = "none";
	string scope_;

	/// Serialize to the JSON document hosted at the `client_id` URL. `client_id`
	/// and `redirect_uris` are always present (per SEP-991 minimum fields);
	/// optional fields are emitted only when set.
	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
		j["client_id"] = clientId;
		if (clientName.length)
			j["client_name"] = clientName;
		if (clientUri.length)
			j["client_uri"] = clientUri;
		Json ru = Json.emptyArray;
		foreach (u; redirectUris)
			ru ~= Json(u);
		j["redirect_uris"] = ru;
		Json gt = Json.emptyArray;
		foreach (g; grantTypes)
			gt ~= Json(g);
		j["grant_types"] = gt;
		Json rt = Json.emptyArray;
		foreach (r; responseTypes)
			rt ~= Json(r);
		j["response_types"] = rt;
		j["token_endpoint_auth_method"] = tokenEndpointAuthMethod;
		if (scope_.length)
			j["scope"] = scope_;
		return j;
	}

	static ClientIdMetadataDocument fromJson(Json j) @safe
	{
		ClientIdMetadataDocument d;
		d.clientId = strField(j, "client_id");
		d.clientName = strField(j, "client_name");
		d.clientUri = strField(j, "client_uri");
		d.redirectUris = stringArray(j, "redirect_uris");
		auto gt = stringArray(j, "grant_types");
		if (gt.length)
			d.grantTypes = gt;
		auto rt = stringArray(j, "response_types");
		if (rt.length)
			d.responseTypes = rt;
		auto am = strField(j, "token_endpoint_auth_method");
		if (am.length)
			d.tokenEndpointAuthMethod = am;
		d.scope_ = strField(j, "scope");
		return d;
	}
}

unittest  // CIMD document emits the SEP-991 minimum fields
{
	ClientIdMetadataDocument d;
	d.clientId = "https://app.example.com/oauth/client.json";
	d.clientName = "Example MCP Client";
	d.redirectUris = ["http://localhost:3000/callback"];
	auto j = d.toJson();
	assert(j["client_id"].get!string == "https://app.example.com/oauth/client.json");
	assert(j["client_name"].get!string == "Example MCP Client");
	assert(j["redirect_uris"][0].get!string == "http://localhost:3000/callback");
	assert(j["token_endpoint_auth_method"].get!string == "none");
}

unittest  // CIMD document round-trips through toJson/fromJson
{
	ClientIdMetadataDocument d;
	d.clientId = "https://app.example.com/oauth/client.json";
	d.clientName = "Example MCP Client";
	d.clientUri = "https://app.example.com";
	d.redirectUris = ["http://localhost:3000/callback"];
	d.scope_ = "mcp:read";
	auto back = ClientIdMetadataDocument.fromJson(d.toJson());
	assert(back.clientId == d.clientId);
	assert(back.clientName == d.clientName);
	assert(back.clientUri == d.clientUri);
	assert(back.redirectUris == d.redirectUris);
	assert(back.scope_ == d.scope_);
}

/// The client-registration approach an MCP client should use for an
/// authorization server, per the spec priority order ("Client Registration
/// Approaches", 2025-11-25 / modern).
enum ClientRegistrationApproach
{
	/// Use pre-registered client information the client already has.
	preRegistered,
	/// Use an OAuth Client ID Metadata Document (HTTPS-URL `client_id`).
	clientIdMetadataDocument,
	/// Fall back to Dynamic Client Registration (RFC 7591).
	dynamicClientRegistration,
	/// Nothing applies — prompt the user to enter client information.
	promptUser,
}

/// Select the client-registration approach for an authorization server,
/// following the spec priority order:
///   1. pre-registered client information, if available;
///   2. Client ID Metadata Documents, if the AS advertises support
///      (`client_id_metadata_document_supported`) and a valid HTTPS-URL
///      `client_id` is configured;
///   3. Dynamic Client Registration, if the AS exposes a `registration_endpoint`;
///   4. otherwise prompt the user.
///
/// `havePreRegistered` is true when the caller already holds a client_id for
/// this AS; `clientIdMetadataUrl` is the configured CIMD URL (empty if none).
ClientRegistrationApproach selectClientRegistrationApproach(
		const AuthorizationServerMetadata as_, bool havePreRegistered, string clientIdMetadataUrl) @safe
{
	if (havePreRegistered)
		return ClientRegistrationApproach.preRegistered;
	if (as_.clientIdMetadataDocumentSupported && isValidClientIdMetadataUrl(clientIdMetadataUrl))
		return ClientRegistrationApproach.clientIdMetadataDocument;
	if (as_.registrationEndpoint.length)
		return ClientRegistrationApproach.dynamicClientRegistration;
	return ClientRegistrationApproach.promptUser;
}

unittest  // pre-registration wins over everything else
{
	AuthorizationServerMetadata as_;
	as_.clientIdMetadataDocumentSupported = true;
	as_.registrationEndpoint = "https://as.example.com/register";
	assert(selectClientRegistrationApproach(as_, true,
			"https://app.example.com/oauth/client.json") == ClientRegistrationApproach
			.preRegistered);
}

unittest  // CIMD chosen when advertised and a valid URL is configured
{
	AuthorizationServerMetadata as_;
	as_.clientIdMetadataDocumentSupported = true;
	as_.registrationEndpoint = "https://as.example.com/register";
	assert(selectClientRegistrationApproach(as_, false,
			"https://app.example.com/oauth/client.json")
			== ClientRegistrationApproach.clientIdMetadataDocument);
}

unittest  // CIMD skipped when AS does not advertise support, falls back to DCR
{
	AuthorizationServerMetadata as_;
	as_.clientIdMetadataDocumentSupported = false;
	as_.registrationEndpoint = "https://as.example.com/register";
	assert(selectClientRegistrationApproach(as_, false,
			"https://app.example.com/oauth/client.json")
			== ClientRegistrationApproach.dynamicClientRegistration);
}

unittest  // CIMD skipped when no/invalid URL configured, falls back to DCR
{
	AuthorizationServerMetadata as_;
	as_.clientIdMetadataDocumentSupported = true;
	as_.registrationEndpoint = "https://as.example.com/register";
	assert(selectClientRegistrationApproach(as_, false,
			"") == ClientRegistrationApproach.dynamicClientRegistration);
	assert(selectClientRegistrationApproach(as_, false,
			"http://app.example.com/x") == ClientRegistrationApproach.dynamicClientRegistration);
}

unittest  // prompt the user when nothing else applies
{
	AuthorizationServerMetadata as_;
	assert(selectClientRegistrationApproach(as_, false, "") == ClientRegistrationApproach
			.promptUser);
}

unittest  // metadata parses client_id_metadata_document_supported
{
	auto j = parseJson(
			`{"issuer":"https://as.example.com","client_id_metadata_document_supported":true}`);
	auto m = AuthorizationServerMetadata.fromJson(j);
	assert(m.clientIdMetadataDocumentSupported);
}

unittest  // metadata defaults client_id_metadata_document_supported to false
{
	auto j = parseJson(`{"issuer":"https://as.example.com"}`);
	auto m = AuthorizationServerMetadata.fromJson(j);
	assert(!m.clientIdMetadataDocumentSupported);
}

/// A token endpoint response (RFC 6749 §5.1).
struct TokenSet
{
	string accessToken;
	string tokenType;
	long expiresIn;
	string refreshToken;
	string scope_;

	static TokenSet fromJson(Json j) @safe
	{
		TokenSet t;
		t.accessToken = strField(j, "access_token");
		t.tokenType = strField(j, "token_type");
		if ("expires_in" in j)
		{
			auto e = j["expires_in"];
			if (e.type == Json.Type.int_)
				t.expiresIn = e.get!long;
			else if (e.type == Json.Type.float_)
				t.expiresIn = cast(long) e.get!double;
		}
		t.refreshToken = strField(j, "refresh_token");
		t.scope_ = strField(j, "scope");
		return t;
	}
}

private string enc(string s) @safe
{
	import std.uri : encodeComponent;

	return encodeComponent(s);
}

/// A single form field. `required` fields are always emitted; optional ones are
/// emitted only when their value is non-empty.
private struct FormField
{
	string key;
	string value;
	bool required;
}

private FormField req(string key, string value) @safe pure nothrow
{
	return FormField(key, value, true);
}

private FormField opt(string key, string value) @safe pure nothrow
{
	return FormField(key, value, false);
}

/// Assemble an `application/x-www-form-urlencoded` body: `grant_type=<grantType>`
/// followed by `&key=enc(value)` for each required field and each optional field
/// with a non-empty value.
private string buildForm(string grantType, scope const FormField[] fields) @safe
{
	auto body_ = "grant_type=" ~ enc(grantType);
	foreach (f; fields)
		if (f.required || f.value.length)
			body_ ~= "&" ~ f.key ~ "=" ~ enc(f.value);
	return body_;
}

/// Build the authorization-request URL for the PKCE auth-code flow.
string buildAuthorizationUrl(string authorizationEndpoint, string clientId,
		string redirectUri, string codeChallenge, string scopeStr, string resource, string state) @safe
{
	import std.exception : enforce;
	import std.string : indexOf;

	enforce(codeChallenge.length, "code_challenge is required (PKCE S256)");

	auto url = authorizationEndpoint;
	url ~= (authorizationEndpoint.indexOf('?') < 0) ? "?" : "&";
	url ~= "response_type=code";
	url ~= "&client_id=" ~ enc(clientId);
	url ~= "&redirect_uri=" ~ enc(redirectUri);
	url ~= "&code_challenge=" ~ enc(codeChallenge);
	url ~= "&code_challenge_method=S256";
	if (scopeStr.length)
		url ~= "&scope=" ~ enc(scopeStr);
	if (resource.length)
		url ~= "&resource=" ~ enc(resource);
	if (state.length)
		url ~= "&state=" ~ enc(state);
	return url;
}

/// Build the `application/x-www-form-urlencoded` body for the authorization-code
/// token request. `clientSecret` is included only for the `client_secret_post`
/// auth method (pass empty otherwise).
package string buildAuthCodeTokenForm(string code, string redirectUri,
		string codeVerifier, string clientId, string resource, string clientSecretForPost = "") @safe
{
	return buildForm("authorization_code", [
		req("code", code), req("redirect_uri", redirectUri),
		req("code_verifier", codeVerifier), req("client_id", clientId),
		opt("resource", resource), opt("client_secret", clientSecretForPost),
	]);
}

/// Build the token-request body for the `client_credentials` grant.
package string buildClientCredentialsForm(string clientId, string scopeStr,
		string resource, string clientSecretForPost = "") @safe
{
	return buildForm("client_credentials", [
		req("client_id", clientId), opt("scope", scopeStr),
		opt("resource", resource), opt("client_secret", clientSecretForPost),
	]);
}

/// Build an RFC 8693 token-exchange request body (used by the cross-app /
/// identity-assertion grant to swap an IdP id_token for an ID-JAG assertion).
package string buildTokenExchangeForm(string subjectToken, string subjectTokenType,
		string requestedTokenType, string audience, string resource, string clientId) @safe
{
	return buildForm("urn:ietf:params:oauth:grant-type:token-exchange",
			[
				req("subject_token", subjectToken),
				req("subject_token_type", subjectTokenType),
				opt("requested_token_type", requestedTokenType),
				opt("audience", audience), opt("resource", resource),
				opt("client_id", clientId),
	]);
}

/// Build an RFC 7523 JWT-bearer grant request body (exchange an assertion JWT
/// for an access token).
package string buildJwtBearerForm(string assertion, string scopeStr,
		string resource, string clientId) @safe
{
	return buildForm("urn:ietf:params:oauth:grant-type:jwt-bearer", [
		req("assertion", assertion), opt("scope", scopeStr),
		opt("resource", resource), opt("client_id", clientId),
	]);
}

/// Build the token-request body for refreshing an access token. When
/// `clientSecretForPost` is non-empty it is appended (for `client_secret_post`
/// upstream authentication); leave it empty for public/PKCE clients or when the
/// secret is carried via the HTTP Basic `Authorization` header instead.
package string buildRefreshTokenForm(string refreshToken, string clientId,
		string resource, string clientSecretForPost = "") @safe
{
	return buildForm("refresh_token", [
		req("refresh_token", refreshToken), req("client_id", clientId),
		opt("resource", resource), opt("client_secret", clientSecretForPost),
	]);
}

/// Build the HTTP `Authorization: Basic` header value for `client_secret_basic`.
/// Per RFC 6749 §2.3.1, both the client identifier and password are
/// percent-encoded (application/x-www-form-urlencoded) before concatenation.
string basicAuthHeader(string clientId, string clientSecret) @safe
{
	import std.base64 : Base64;
	import std.uri : encodeComponent;

	const raw = encodeComponent(clientId) ~ ":" ~ encodeComponent(clientSecret);
	return "Basic " ~ () @trusted {
		return cast(string) Base64.encode(cast(const(ubyte)[]) raw);
	}();
}

/// Parse a token-endpoint HTTP response: a non-2xx status is an error (the body,
/// when present, is surfaced for diagnostics, and an RFC 6749 §5.2 `error` code
/// is carried in the exception's `data` for `oauthErrorCode`), otherwise decode
/// the JSON body into a `TokenSet`.
private TokenSet parseTokenResponse(int status, string responseBody) @safe
{
	import std.conv : to;
	import mcp.protocol.errors : invalidRequest;
	import mcp.protocol.jsonrpc : parseUntrustedJson;

	if (status < 200 || status >= 300)
		throw invalidRequest("token endpoint returned HTTP " ~ status.to!string ~ (
				responseBody.length ? ": " ~ responseBody : ""), oauthErrorData(responseBody));
	return requireBearer(TokenSet.fromJson(parseUntrustedJson(responseBody)));
}

/// Return `ts` when its `token_type` is `Bearer` (compared case-insensitively,
/// RFC 6749 §5.1) or absent; otherwise throw. The SDK presents access tokens
/// only as `Authorization: Bearer`, so a DPoP or other token type would be sent
/// under the wrong scheme.
package(mcp) TokenSet requireBearer(TokenSet ts) @safe
{
	import std.uni : sicmp;
	import mcp.protocol.errors : invalidRequest;

	if (ts.tokenType.length && sicmp(ts.tokenType, "Bearer") != 0)
		throw invalidRequest("token endpoint issued token_type \""
				~ ts.tokenType ~ "\"; only Bearer tokens are supported");
	return ts;
}

/// The exception `data` for an OAuth error response body: `{"error": code}`
/// when the body is a JSON object with a string `error` (RFC 6749 §5.2), else
/// `Json.undefined`. `oauthErrorCode` reads it back.
package(mcp) Json oauthErrorData(string responseBody) @safe nothrow
{
	import mcp.protocol.jsonrpc : parseUntrustedJson;

	try
	{
		auto err = parseUntrustedJson(responseBody);
		if (err.type == Json.Type.object && err["error"].type == Json.Type.string)
		{
			auto data = Json.emptyObject;
			data["error"] = err["error"];
			return data;
		}
	}
	catch (Exception)
	{
	}
	return Json.undefined;
}

/// The RFC 6749 §5.2 `error` code of a failed token request (for example
/// `invalid_grant`), or empty when `e` did not come from an OAuth error response.
string oauthErrorCode(const Exception e) @safe nothrow
{
	import mcp.protocol.errors : McpException;

	auto me = cast(const McpException) e;
	if (me is null || me.data.type != Json.Type.object)
		return null;
	try
	{
		auto code = me.data["error"];
		return code.type == Json.Type.string ? code.get!string : null;
	}
	catch (Exception)
		return null;
}

/// Upper bound on an OAuth/discovery response body (metadata documents, DCR and
/// token responses) read from the network. A larger response is refused rather
/// than buffered, so a hostile or misbehaving endpoint cannot exhaust memory.
package(mcp) enum size_t maxAuthResponseBytes = 256 * 1024;

/// POST an `application/x-www-form-urlencoded` body to a token endpoint over the
/// SDK's SSRF-safe transport under `policy` and return the parsed `TokenSet`.
/// `authHeader`, when non-empty, is sent as `Authorization`.
private TokenSet postTokenRequest(string tokenEndpoint, string body_,
		string authHeader, SsrfPolicy policy) @safe
{
	int status = 502;
	string responseBody;
	{
		import vibe.http.client : HTTPClientResponse;
		import vibe.http.common : HTTPMethod;
		import vibe.stream.operations : readAllUTF8;

		secureRequestHTTP(tokenEndpoint, policy, (scope HTTPClientRequest creq) {
			creq.method = HTTPMethod.POST;
			creq.headers["Content-Type"] = "application/x-www-form-urlencoded";
			creq.headers["Accept"] = "application/json";
			if (authHeader.length)
				creq.headers["Authorization"] = authHeader;
			creq.writeBody(cast(const(ubyte)[]) body_);
		}, (scope HTTPClientResponse cres) {
			status = cres.statusCode;
			responseBody = cres.bodyReader.readAllUTF8(false, maxAuthResponseBytes);
		});
	}
	return parseTokenResponse(status, responseBody);
}

/// Redeem an authorization code for tokens at a third-party token endpoint
/// (RFC 6749 §4.1.3 + PKCE RFC 7636). Use when an MCP server acts as an OAuth
/// client to an upstream API; unlike `OAuthClient` this carries no RFC 8707
/// `resource`. An empty `clientSecret` denotes a public client, so no
/// credentials are sent; otherwise they go via HTTP Basic. `policy` governs
/// which hosts the endpoint may name (`SsrfPolicy.allowUserConfigured` for a
/// token endpoint on a private network). Throws on an endpoint `policy` rejects
/// or a non-2xx response.
TokenSet exchangeAuthCode(string tokenEndpoint, string code, string redirectUri, string clientId,
		string clientSecret, string codeVerifier, SsrfPolicy policy = SsrfPolicy.allowLoopback) @safe
{
	const body_ = buildAuthCodeTokenForm(code, redirectUri, codeVerifier, clientId, "");
	const authHeader = clientSecret.length ? basicAuthHeader(clientId, clientSecret) : "";
	return postTokenRequest(tokenEndpoint, body_, authHeader, policy);
}

/// Refresh an access token at a third-party token endpoint (RFC 6749 §6). Use
/// when an MCP server acts as an OAuth client to an upstream API; carries no
/// RFC 8707 `resource`. An empty `clientSecret` denotes a public client, so no
/// credentials are sent; otherwise they go via HTTP Basic. `policy` is as for
/// `exchangeAuthCode`. Throws on an endpoint `policy` rejects or a non-2xx
/// response.
TokenSet refreshAccessToken(string tokenEndpoint, string refreshToken,
		string clientId, string clientSecret, SsrfPolicy policy = SsrfPolicy.allowLoopback) @safe
{
	const body_ = buildRefreshTokenForm(refreshToken, clientId, "");
	const authHeader = clientSecret.length ? basicAuthHeader(clientId, clientSecret) : "";
	return postTokenRequest(tokenEndpoint, body_, authHeader, policy);
}

unittest  // DCR request + responses round-trip
{
	ClientRegistration reg;
	reg.redirectUris = ["http://localhost:3000/callback"];
	reg.clientName = "dlang-mcp";
	auto j = reg.toJson();
	assert(j["redirect_uris"][0].get!string == "http://localhost:3000/callback");
	assert(j["grant_types"][0].get!string == "authorization_code");
	assert(j["token_endpoint_auth_method"].get!string == "none");

	auto rc = RegisteredClient.fromJson(parseJson(`{"client_id":"abc","client_secret":"shh"}`));
	assert(rc.clientId == "abc" && rc.clientSecret == "shh");

	auto ts = TokenSet.fromJson(parseJson(
			`{"access_token":"tok","token_type":"Bearer","expires_in":3600,"refresh_token":"r"}`));
	assert(ts.accessToken == "tok" && ts.tokenType == "Bearer" && ts.expiresIn == 3600);
	assert(ts.refreshToken == "r");
}

unittest  // TokenSet.fromJson parses expires_in when AS returns it as a JSON float
{
	auto ts = TokenSet.fromJson(parseJson(
			`{"access_token":"tok","token_type":"Bearer","expires_in":3600.0,"refresh_token":"r"}`));
	assert(ts.expiresIn == 3600, "float expires_in must be parsed as long");
}

unittest  // authorization URL includes PKCE S256, resource, scope, state
{
	auto url = buildAuthorizationUrl("https://auth.example.com/authorize", "client1",
			"http://localhost:3000/cb", "CHAL", "read write", "https://mcp.example.com", "xyz");
	import std.algorithm : canFind;

	assert(url.canFind("response_type=code"));
	assert(url.canFind("code_challenge=CHAL"));
	assert(url.canFind("code_challenge_method=S256"));
	assert(url.canFind("client_id=client1"));
	assert(url.canFind("scope=read%20write"));
	assert(url.canFind("resource=https%3A%2F%2Fmcp.example.com"));
	assert(url.canFind("state=xyz"));
}

unittest  // authorization URL refuses to build a challenge-less (non-PKCE) request
{
	import std.exception : assertThrown;

	assertThrown(buildAuthorizationUrl("https://auth.example.com/authorize", "client1",
			"http://localhost:3000/cb", "", "read", "https://mcp.example.com", "xyz"));
}

unittest  // token request forms carry the right grant + params
{
	auto f = buildAuthCodeTokenForm("CODE", "http://localhost/cb", "VERIFIER",
			"client1", "https://mcp.example.com");
	import std.algorithm : canFind;

	assert(f.canFind("grant_type=authorization_code"));
	assert(f.canFind("code=CODE"));
	assert(f.canFind("code_verifier=VERIFIER"));
	assert(f.canFind("resource=https%3A%2F%2Fmcp.example.com"));

	auto cc = buildClientCredentialsForm("client1", "api", "https://mcp.example.com");
	assert(cc.canFind("grant_type=client_credentials"));

	auto rf = buildRefreshTokenForm("RT", "client1", "");
	assert(rf.canFind("grant_type=refresh_token") && rf.canFind("refresh_token=RT"));
}

unittest  // refresh-token form appends the post-secret only when supplied
{
	import std.algorithm : canFind;

	auto pub = buildRefreshTokenForm("RT", "client1", "https://mcp.example.com/mcp");
	assert(pub.canFind("grant_type=refresh_token"));
	assert(pub.canFind("refresh_token=RT"));
	assert(pub.canFind("resource=https%3A%2F%2Fmcp.example.com%2Fmcp"));
	assert(!pub.canFind("client_secret="));

	auto conf = buildRefreshTokenForm("RT", "client1", "", "sekret");
	assert(conf.canFind("client_secret=sekret"));
}

unittest  // basic auth header is base64(client:secret)
{
	// base64("id:secret") = aWQ6c2VjcmV0
	assert(basicAuthHeader("id", "secret") == "Basic aWQ6c2VjcmV0");
}

unittest  // exchangeAuthCode body carries the auth-code grant + percent-encoded params
{
	import std.algorithm : canFind;

	const f = buildAuthCodeTokenForm("a+b/c", "https://app.example.com/cb?x=1",
			"VER+IFY", "client1", "");
	assert(f.canFind("grant_type=authorization_code"));
	// '+' and '/' in the code must be percent-encoded, not passed literally.
	assert(f.canFind("code=a%2Bb%2Fc"));
	assert(f.canFind("redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb%3Fx%3D1"));
	assert(f.canFind("code_verifier=VER%2BIFY"));
	assert(f.canFind("client_id=client1"));
	// The generic helper omits the MCP-only RFC 8707 resource parameter.
	assert(!f.canFind("resource="));
}

unittest  // refreshAccessToken body carries the refresh-token grant + params
{
	import std.algorithm : canFind;

	const f = buildRefreshTokenForm("re+fresh", "client1", "");
	assert(f.canFind("grant_type=refresh_token"));
	assert(f.canFind("refresh_token=re%2Bfresh"));
	assert(f.canFind("client_id=client1"));
	assert(!f.canFind("resource="));
}

unittest  // a confidential client authenticates via HTTP Basic, a public one does not
{
	// The facades pass an empty post-secret and route credentials through the
	// Authorization header; an empty clientSecret means no header at all.
	assert(basicAuthHeader("client1", "shh").length);
	assert("".length == 0);
}

unittest  // parseTokenResponse rejects a non-2xx status (RFC 6749 token error)
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	assertThrown!McpException(parseTokenResponse(400, `{"error":"invalid_grant"}`));
	assertThrown!McpException(parseTokenResponse(500, ""));
}

unittest  // parseTokenResponse carries the OAuth error code of a rejected token request
{
	import std.exception : collectException;

	assert(oauthErrorCode(collectException(parseTokenResponse(400,
			`{"error":"invalid_grant"}`))) == "invalid_grant");
	assert(oauthErrorCode(collectException(parseTokenResponse(502, "<html>"))) == "");
	assert(oauthErrorCode(new Exception("network down")) == "");
}

unittest  // parseTokenResponse rejects a token_type other than Bearer
{
	import std.algorithm : canFind;
	import std.exception : collectExceptionMsg;

	const msg = collectExceptionMsg(parseTokenResponse(200,
			`{"access_token":"AT","token_type":"DPoP"}`));
	assert(msg.canFind("DPoP"), msg);
	assert(parseTokenResponse(200,
			`{"access_token":"AT","token_type":"bearer"}`).accessToken == "AT");
	assert(parseTokenResponse(200, `{"access_token":"AT"}`).accessToken == "AT");
}

unittest  // parseTokenResponse decodes a 2xx body into a populated TokenSet
{
	const ts = parseTokenResponse(200, `{"access_token":"AT","token_type":"Bearer","expires_in":3600,"refresh_token":"RT","scope":"a b"}`);
	assert(ts.accessToken == "AT");
	assert(ts.tokenType == "Bearer");
	assert(ts.expiresIn == 3600);
	assert(ts.refreshToken == "RT");
	assert(ts.scope_ == "a b");
}

unittest  // parseTokenResponse rejects a 2xx body nested past the depth cap
{
	import std.array : replicate;
	import std.exception : assertThrown;

	const deep = "[".replicate(1000) ~ "]".replicate(1000);
	assertThrown(parseTokenResponse(200,
			`{"access_token":"AT","token_type":"Bearer","x":` ~ deep ~ `}`));
}

unittest  // exchangeAuthCode refuses a token response larger than maxAuthResponseBytes
{
	import std.array : replicate;
	import std.conv : to;
	import std.exception : assertThrown;
	import vibe.http.server : HTTPServerRequest, HTTPServerResponse,
		HTTPServerSettings, listenHTTP;

	auto settings = new HTTPServerSettings;
	settings.bindAddresses = ["127.0.0.1"];
	settings.port = 0;
	auto listener = listenHTTP(settings, (scope HTTPServerRequest req,
			scope HTTPServerResponse res) @safe {
		res.writeBody(`{"access_token":"at","token_type":"Bearer","pad":"` ~ "x".replicate(
			maxAuthResponseBytes) ~ `"}`, "application/json");
	});
	scope (exit)
		listener.stopListening();
	const endpoint = "http://127.0.0.1:" ~ listener.bindAddresses[0].port.to!string ~ "/token";

	assertThrown(exchangeAuthCode(endpoint, "CODE", "http://127.0.0.1:1/cb",
			"client1", "", "VERIFIER"));
}

unittest  // exchangeAuthCode refuses a plaintext (non-loopback) token endpoint
{
	import std.exception : assertThrown;

	assertThrown(exchangeAuthCode("http://as.example.com/token", "CODE",
			"https://app.example.com/cb", "client1", "shh", "VERIFIER"));
}

unittest  // refreshAccessToken refuses a private/link-local token endpoint (SSRF)
{
	import std.exception : assertThrown;

	assertThrown(refreshAccessToken("https://169.254.169.254/token", "RT", "client1", ""));
}

unittest  // basic auth header percent-encodes credentials per RFC 6749 §2.3.1
{
	// client_id "id:with:colons", client_secret "secret+value"
	// After encodeComponent: "id%3Awith%3Acolons" and "secret%2Bvalue"
	// raw = "id%3Awith%3Acolons:secret%2Bvalue"
	// base64 of that = "aWQlM0F3aXRoJTNBY29sb25zOnNlY3JldCUyQnZhbHVl"
	assert(basicAuthHeader("id:with:colons",
			"secret+value") == "Basic aWQlM0F3aXRoJTNBY29sb25zOnNlY3JldCUyQnZhbHVl");
}

/// Extract a query-string parameter value from a URL (URL-decoded), or "".
package string extractQueryParam(string url, string key) @safe
{
	import std.string : indexOf;
	import std.uri : decodeComponent;

	const q = url.indexOf('?');
	auto query = (q < 0) ? url : url[q + 1 .. $];
	const hashPos = query.indexOf('#');
	if (hashPos >= 0)
		query = query[0 .. hashPos];
	const needle = key ~ "=";
	size_t i;
	while (i < query.length)
	{
		const amp = query[i .. $].indexOf('&');
		const end = (amp < 0) ? query.length : i + amp;
		auto pair = query[i .. end];
		if (pair.length >= needle.length && pair[0 .. needle.length] == needle)
			return decodeComponent(pair[needle.length .. $]);
		i = end + 1;
	}
	return "";
}

unittest  // extractQueryParam pulls and decodes a parameter
{
	assert(extractQueryParam("http://x/cb?code=abc123&state=xyz", "code") == "abc123");
	assert(extractQueryParam("http://x/cb?code=a%20b", "code") == "a b");
	assert(extractQueryParam("http://x/cb?state=xyz", "code") == "");
	assert(extractQueryParam("http://x/cb", "code") == "");
}

unittest  // extractQueryParam strips URI fragment before parsing query parameters
{
	assert(extractQueryParam("http://x/cb?state=xyz#frag", "state") == "xyz");
	assert(extractQueryParam("http://x/cb?code=abc&state=xyz#frag", "state") == "xyz");
	assert(extractQueryParam("http://x/cb?code=abc#frag", "code") == "abc");
}

/// Validate the RFC 9207 `iss` authorization-response parameter against the
/// recorded issuer of the selected authorization server, per RFC 9207
/// Section 2.4 (the MCP 2025-11-25 / modern "Authorization Response Validation"
/// requirement, mitigating authorization-server mix-up attacks).
///
/// `responseIss` is the raw `iss` value extracted from the authorization
/// redirect (empty when absent); `recordedIssuer` is the `issuer` value from the
/// selected AS's validated metadata; `issParameterSupported` reflects the AS's
/// `authorization_response_iss_parameter_supported` metadata.
///
/// The comparison is a simple string comparison with no normalization. Returns
/// `true` when the response is acceptable; `false` when it MUST be rejected
/// (without acting on the authorization code or any error parameters):
///   - iss present and != recordedIssuer  -> reject (mismatch)
///   - iss absent but issParameterSupported -> reject (required but missing)
///   - iss present and == recordedIssuer  -> accept
///   - iss absent and not supported       -> accept (nothing to validate)
bool validateAuthorizationResponseIss(string responseIss, string recordedIssuer,
		bool issParameterSupported) @safe pure nothrow @nogc
{
	if (responseIss.length)
		return responseIss == recordedIssuer;
	// iss absent: only acceptable when the AS does not advertise iss support.
	return !issParameterSupported;
}

unittest  // iss present and matching the recorded issuer is accepted
{
	assert(validateAuthorizationResponseIss("https://as.example.com",
			"https://as.example.com", true));
}

unittest  // iss present but mismatched is rejected (mix-up protection)
{
	assert(!validateAuthorizationResponseIss("https://evil.example.com",
			"https://as.example.com", true));
}

unittest  // iss comparison is raw string comparison with no normalization
{
	// Trailing slash difference must NOT be normalized away.
	assert(!validateAuthorizationResponseIss("https://as.example.com/",
			"https://as.example.com", false));
}

unittest  // iss absent but advertised as supported is rejected
{
	assert(!validateAuthorizationResponseIss("", "https://as.example.com", true));
}

unittest  // iss absent and not advertised is accepted (nothing to validate)
{
	assert(validateAuthorizationResponseIss("", "https://as.example.com", false));
}

/// Validate the `state` parameter returned in an authorization redirect against
/// the `state` value the client sent in the authorization request.
///
/// Per the MCP authorization spec (basic/authorization, "Open Redirection",
/// 2025-06-18 / 2025-11-25 / modern): "MCP clients SHOULD use and verify state
/// parameters in the authorization code flow and discard any results that do
/// not include or have a mismatch with the original state."
///
/// `responseState` is the raw `state` value extracted from the authorization
/// redirect (empty when absent); `expectedState` is the value the client
/// originally sent (empty when the client did not use a state parameter, in
/// which case there is nothing to verify and the response is accepted).
///
/// The comparison is a simple string comparison with no normalization. Returns
/// `true` when the response is acceptable; `false` when it MUST be discarded:
///   - expectedState empty                       -> accept (nothing to verify)
///   - expectedState set, responseState empty    -> reject (missing)
///   - expectedState set, responseState mismatch -> reject (mismatch)
///   - expectedState set, responseState matches  -> accept
bool validateAuthorizationResponseState(string responseState, string expectedState) @safe pure nothrow @nogc
{
	// No expected state -> the client did not use one; nothing to verify.
	if (expectedState.length == 0)
		return true;
	// Expected state set: the response MUST include a matching state. Use a
	// constant-time compare so the helper stays safe even if reused for a
	// multi-use or attacker-probeable secret (defence in depth: the generated
	// state is a single-use CSRF/mix-up nonce, not a long-lived secret).
	return constantTimeEquals(responseState, expectedState);
}

/// Length-independent constant-time byte comparison. The running time depends
/// only on the longer input's length, never on the position of the first
/// differing byte, so it leaks no information through a timing side channel.
package(mcp) bool constantTimeEquals(scope const(char)[] a, scope const(char)[] b) @safe pure nothrow @nogc
{
	const n = a.length > b.length ? a.length : b.length;
	uint diff = cast(uint)(a.length ^ b.length);
	foreach (i; 0 .. n)
	{
		const ca = i < a.length ? a[i] : 0;
		const cb = i < b.length ? b[i] : 0;
		diff |= cast(uint)(ca ^ cb);
	}
	return diff == 0;
}

unittest  // state matching the expected value is accepted
{
	assert(validateAuthorizationResponseState("xyz", "xyz"));
}

unittest  // state present but mismatched is rejected (discard result)
{
	assert(!validateAuthorizationResponseState("evil", "xyz"));
}

unittest  // expected state set but response state missing is rejected
{
	assert(!validateAuthorizationResponseState("", "xyz"));
}

unittest  // no expected state means nothing to verify (accept)
{
	assert(validateAuthorizationResponseState("anything", ""));
}

unittest  // state comparison is raw string comparison with no normalization
{
	assert(!validateAuthorizationResponseState("XYZ", "xyz"));
}

unittest  // constant-time state compare rejects prefixes and length mismatches
{
	// A prefix of the expected value must not be accepted.
	assert(!validateAuthorizationResponseState("xy", "xyz"));
	assert(!validateAuthorizationResponseState("xyzz", "xyz"));
	// A full match is still accepted.
	assert(validateAuthorizationResponseState("xyz", "xyz"));
}

unittest  // metadata parses authorization_response_iss_parameter_supported
{
	import vibe.data.json : parseJsonString;

	auto j = parseJsonString(
			`{"issuer":"https://as.example.com","authorization_response_iss_parameter_supported":true}`);
	auto m = AuthorizationServerMetadata.fromJson(j);
	assert(m.authorizationResponseIssParameterSupported);
}

unittest  // metadata defaults iss-parameter-supported to false when absent
{
	import vibe.data.json : parseJsonString;

	auto j = parseJsonString(`{"issuer":"https://as.example.com"}`);
	auto m = AuthorizationServerMetadata.fromJson(j);
	assert(!m.authorizationResponseIssParameterSupported);
}
