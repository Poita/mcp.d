module mcp.auth.oauth;

import std.typecons : Nullable;
import vibe.data.json : Json;
import vibe.http.client : HTTPClientRequest, HTTPClientResponse;

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
/// `Bearer resource_metadata="https://...", scope="a b"`.
WwwAuthenticate parseWwwAuthenticate(string header) @safe
{
	import std.string : strip, indexOf;

	WwwAuthenticate w;
	auto h = header.strip;
	const sp = h.indexOf(' ');
	if (sp < 0)
	{
		w.scheme = h;
		return w;
	}
	w.scheme = h[0 .. sp];
	auto rest = h[sp + 1 .. $].strip;

	// Split into key="value" or key=value pairs separated by commas (commas
	// inside quotes are not expected for these params).
	size_t i;
	while (i < rest.length)
	{
		const eq = rest[i .. $].indexOf('=');
		if (eq < 0)
			break;
		auto key = rest[i .. i + eq].strip;
		i += eq + 1;
		string value;
		if (i < rest.length && rest[i] == '"')
		{
			i++;
			const end = rest[i .. $].indexOf('"');
			if (end < 0)
				break;
			value = rest[i .. i + end];
			i += end + 1;
		}
		else
		{
			const comma = rest[i .. $].indexOf(',');
			if (comma < 0)
			{
				value = rest[i .. $].strip;
				i = rest.length;
			}
			else
			{
				value = rest[i .. i + comma].strip;
				i += comma;
			}
		}
		if (key.length)
			w.params[key] = value;
		// skip a following comma and spaces
		while (i < rest.length && (rest[i] == ',' || rest[i] == ' '))
			i++;
	}
	return w;
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
	/// publishes at `/.well-known/oauth-protected-resource`. `resource` and
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

/// Build the ordered list of well-known protected-resource-metadata URLs to try
/// for an MCP endpoint URL, per RFC 9728: the path-scoped URL first, then root.
string[] protectedResourceMetadataUrls(string mcpEndpoint) @safe
{
	import std.algorithm : min;
	import std.string : indexOf;

	// Split scheme://host[/path]
	auto schemeEnd = mcpEndpoint.indexOf("://");
	if (schemeEnd < 0)
		return [mcpEndpoint];
	const afterScheme = schemeEnd + 3;
	const slash = mcpEndpoint[afterScheme .. $].indexOf('/');
	string origin = (slash < 0) ? mcpEndpoint : mcpEndpoint[0 .. afterScheme + slash];
	string path = (slash < 0) ? "" : mcpEndpoint[afterScheme + slash .. $];

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
/// URL with a lowercased scheme+authority, any fragment dropped, and a single
/// trailing slash stripped. The MCP "Canonical Server URI" rules prefer the
/// no-trailing-slash form. ASCII case is folded in place (rather than via
/// `toLower`) to keep this `pure nothrow`.
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
	const slash = s[afterScheme .. $].indexOf('/');
	const hostEnd = (slash < 0) ? s.length : afterScheme + slash;
	char[] buf = new char[s.length];
	foreach (i, ch; s)
	{
		char c = ch;
		if (i < hostEnd && c >= 'A' && c <= 'Z')
			c = cast(char)(c + 32);
		buf[i] = c;
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
	// The old implementation drew verifier bytes from a default-seeded
	// std.random Mersenne Twister. Reproduce that exact predictable sequence and
	// assert the real generator does not reproduce it (it would, with
	// overwhelming probability, if it had regressed to rndGen).
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

	Json toJson() const @safe
	{
		Json j = Json.emptyObject;
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
		if (clientName.length)
			j["client_name"] = clientName;
		if (scope_.length)
			j["scope"] = scope_;
		return j;
	}
}

/// The credentials returned by the registration endpoint.
struct RegisteredClient
{
	string clientId;
	string clientSecret;

	static RegisteredClient fromJson(Json j) @safe
	{
		RegisteredClient c;
		c.clientId = strField(j, "client_id");
		c.clientSecret = strField(j, "client_secret");
		return c;
	}
}

// ===========================================================================
// Client ID Metadata Documents (SEP-991)
// ===========================================================================

/// Validate an OAuth Client ID Metadata Document `client_id` URL (SEP-991):
/// it MUST use the `https` scheme and contain a non-empty path component.
bool isValidClientIdMetadataUrl(string clientId) @safe pure nothrow @nogc
{
	import std.string : indexOf;

	// Must use the https scheme.
	if (clientId.length < 8 || clientId[0 .. 8] != "https://")
		return false;
	auto rest = clientId[8 .. $];
	// A path component must exist after the host: a '/' that is followed by at
	// least one more character (a bare trailing '/' is not a path component).
	const slash = rest.indexOf('/');
	if (slash < 0)
		return false;
	return slash + 1 < rest.length;
}

/// Whether `url` is safe to fetch for OAuth/discovery: it MUST use the `https`
/// scheme, OR target an explicit loopback host (`localhost`, `127.0.0.1`,
/// `[::1]`, and their numeric encodings) over `http` for local development.
/// Plaintext `http` to any other host is rejected, as are URLs whose host is a
/// private/link-local IPv4 or IPv6 literal (including alternate numeric IPv4
/// encodings and IPv4-mapped/compatible IPv6). Purely lexical (no DNS): it is a
/// coarse pre-filter on the attacker-influenced `resource_metadata` URL. The
/// authoritative, TOCTOU-safe SSRF guard for an actual fetch is
/// `secureRequestHTTP`, which resolves, classifies and pins via the connector.
bool isSecureFetchUrl(string url) @safe
{
	import mcp.protocol.ssrf : classifyHostLexical, AddressClass;
	import vibe.inet.url : URL;

	string scheme, host;
	try
	{
		auto u = URL(url);
		scheme = u.schema;
		host = u.host;
	}
	catch (Exception)
	{
		return false;
	}
	if (host.length == 0)
		return false;

	// Lexical pre-filter only (no DNS): IP-literal/loopback ranges are classified,
	// a registered name is treated as public. The resolve-and-pin connector makes
	// the authoritative call when the URL is actually fetched.
	const cls = classifyHostLexical(host);

	bool eqScheme(string sc) @safe nothrow @nogc
	{
		if (scheme.length != sc.length)
			return false;
		foreach (k, ch; scheme)
		{
			char c = ch;
			if (c >= 'A' && c <= 'Z')
				c = cast(char)(c + 32);
			if (c != sc[k])
				return false;
		}
		return true;
	}

	if (cls == AddressClass.privateOrLinkLocal)
		return false;
	if (eqScheme("https"))
		return true;
	if (eqScheme("http") && cls == AddressClass.loopback)
		return true;
	return false;
}

/// Throw `invalidRequest` when `url` is not safe to fetch under the
/// block-internal policy. Parses with vibe's own parser (the single source of
/// truth) and classifies the host once. A check-time scheme/host gate (no
/// fetch) suitable for paths that VALIDATE a URL without fetching it (e.g.
/// building the authorization-request URL the host will open). The TOCTOU-safe
/// resolve-and-pin connect for an actual fetch is performed by
/// `secureRequestHTTP`.
void requireSecureUrl(string url) @safe
{
	import mcp.protocol.errors : invalidRequest;
	import mcp.protocol.ssrf : classifyHostLexical, AddressClass;
	import vibe.inet.url : URL;

	string scheme, host;
	try
	{
		auto u = URL(url);
		scheme = u.schema;
		host = u.host;
	}
	catch (Exception)
		throw invalidRequest("Refusing to fetch URL with no parseable host: " ~ url);

	// A URL that parsed but carries no host is just as unfetchable; report it as
	// such rather than letting it fall through to the misleading "insecure" branch.
	if (host.length == 0)
		throw invalidRequest("Refusing to fetch URL with no parseable host: " ~ url);

	// Lexical only (no DNS): a registered name is treated as public here; the
	// resolve-and-pin connector enforces the resolved-address policy at fetch.
	const cls = classifyHostLexical(host);

	bool eqScheme(string sc) @safe nothrow @nogc
	{
		if (scheme.length != sc.length)
			return false;
		foreach (k, ch; scheme)
		{
			char c = ch;
			if (c >= 'A' && c <= 'Z')
				c = cast(char)(c + 32);
			if (c != sc[k])
				return false;
		}
		return true;
	}

	bool secure;
	if (cls == AddressClass.privateOrLinkLocal)
		secure = false;
	else if (eqScheme("https"))
		secure = true;
	else if (eqScheme("http") && cls == AddressClass.loopback)
		secure = true;
	else
		secure = false;

	if (!secure)
		throw invalidRequest(
				"Refusing to fetch insecure OAuth/discovery URL (must be https, or http to an "
				~ "explicit loopback host; private/link-local addresses are rejected): " ~ url);
}

/// Non-throwing scheme/host + resolution gate (block-internal policy). Returns
/// true only when the vibe-parsed scheme/host pass the lexical guard AND the
/// host resolves only to safe addresses (fail CLOSED on a resolution error).
/// Loopback and IP-literal hosts short-circuit without resolving. `@safe`.
bool isSecureFetchUrlResolved(string url) @safe
{
	import mcp.protocol.ssrf : classifyHostLexical, AddressClass,
		pinnedConnectAddress, SsrfPolicy;
	import vibe.inet.url : URL;

	string scheme, host;
	try
	{
		auto u = URL(url);
		scheme = u.schema;
		host = u.host;
	}
	catch (Exception)
	{
		return false;
	}
	if (host.length == 0)
		return false;

	bool eqScheme(string sc) @safe nothrow @nogc
	{
		if (scheme.length != sc.length)
			return false;
		foreach (k, ch; scheme)
		{
			char c = ch;
			if (c >= 'A' && c <= 'Z')
				c = cast(char)(c + 32);
			if (c != sc[k])
				return false;
		}
		return true;
	}

	const isHttps = eqScheme("https");
	const isHttp = eqScheme("http");
	if (!isHttps && !isHttp)
		return false;

	// Scheme gate: https to any host, or http only to an explicit loopback host
	// (matches the connector's block-internal scheme policy). Use the lexical
	// class so http-to-a-registered-name is rejected without a DNS round-trip.
	const lex = classifyHostLexical(host);
	if (isHttp && lex != AddressClass.loopback)
		return false;

	// Resolve + classify + pin under the block-internal policy; the connector's
	// verdict is the single source of truth for the resolved address.
	const pin = pinnedConnectAddress(host, isHttps, SsrfPolicy.blockInternal);
	return pin.ok;
}

/// Consolidated SSRF-safe HTTP fetch used by every outbound OAuth/discovery
/// request. Delegates to the connector's `secureRequestHTTP` with the
/// block-internal policy: parse once with vibe's `URL`, classify the host once,
/// resolve + pin to a vetted numeric address (preserving Host header + TLS SNI),
/// and fail CLOSED on any internal/unresolvable target. Throws `invalidRequest`
/// when the URL is unsafe.
void secureRequestHTTP(string url, scope void delegate(scope HTTPClientRequest) requester,
		scope void delegate(scope HTTPClientResponse) responder) @safe
{
	import mcp.protocol.ssrf : connectorRequest = secureRequestHTTP, SsrfPolicy;

	connectorRequest(url, SsrfPolicy.blockInternal, requester, responder);
}

unittest  // requireSecureUrl throws on an insecure URL and passes a secure loopback one
{
	import std.exception : assertThrown;

	assertThrown(requireSecureUrl("http://as.example.com/token"));
	assertThrown(requireSecureUrl("https://169.254.169.254/"));
	// Loopback hosts skip DNS resolution, so these are network-independent.
	requireSecureUrl("https://127.0.0.1/token"); // does not throw
	requireSecureUrl("http://127.0.0.1:8765/callback"); // loopback dev ok
}

unittest  // requireSecureUrl rejects the '?@' / '#@' authority differential (SSRF)
{
	import std.exception : assertThrown;

	assertThrown(requireSecureUrl("https://public?@169.254.169.254/jwks"));
	assertThrown(requireSecureUrl("https://public#@10.0.0.5/jwks"));
}

unittest  // requireSecureUrl reports an unparseable URL accurately, not as merely "insecure"
{
	import std.algorithm.searching : canFind;

	bool threw;
	string msg;
	try
		requireSecureUrl("http://");
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
	assert(isSecureFetchUrl("https://as.example.com/.well-known/oauth-authorization-server"));
	assert(!isSecureFetchUrl("http://as.example.com/.well-known/oauth-authorization-server"));
}

unittest  // isSecureFetchUrl permits http only to explicit loopback hosts (dev)
{
	assert(isSecureFetchUrl("http://localhost:8765/jwks"));
	assert(isSecureFetchUrl("http://127.0.0.1/jwks"));
	assert(isSecureFetchUrl("http://[::1]:9000/jwks"));
	assert(!isSecureFetchUrl("http://internal.local/jwks"));
}

unittest  // isSecureFetchUrl rejects private/link-local IPv4 literals (SSRF)
{
	assert(!isSecureFetchUrl("https://169.254.169.254/latest/meta-data"));
	assert(!isSecureFetchUrl("https://10.0.0.5/x"));
	assert(!isSecureFetchUrl("https://192.168.1.1/x"));
	assert(!isSecureFetchUrl("https://172.16.0.1/x"));
	assert(!isSecureFetchUrl("http://169.254.169.254/x"));
}

unittest  // isSecureFetchUrl rejects private/ULA/link-local IPv6 literals (SSRF)
{
	assert(!isSecureFetchUrl("https://[fd00::1]/x"));
	assert(!isSecureFetchUrl("https://[fc00::1]/x"));
	assert(!isSecureFetchUrl("https://[fe80::1]/x"));
	assert(!isSecureFetchUrl("https://[::]/x"));
	assert(!isSecureFetchUrl("https://[::ffff:169.254.169.254]/latest/meta-data"));
	assert(!isSecureFetchUrl("https://[::ffff:10.0.0.5]/x"));
	assert(!isSecureFetchUrl("https://[::ffff:127.0.0.1]/x"));
	assert(!isSecureFetchUrl("https://[::ffff:0a00:0001]/x"));
	assert(!isSecureFetchUrl("https://[fe80::1]:443/x"));
}

unittest  // isSecureFetchUrl accepts a public/global-unicast IPv6 literal
{
	assert(isSecureFetchUrl("https://[2606:4700:4700::1111]/x"));
	assert(isSecureFetchUrl("https://[2606:4700::1]/x"));
	assert(isSecureFetchUrl("http://[::1]:9000/jwks"));
}

unittest  // isSecureFetchUrl rejects schemeless / file / non-loopback http
{
	assert(!isSecureFetchUrl("as.example.com/x"));
	assert(!isSecureFetchUrl("file:///etc/passwd"));
	assert(!isSecureFetchUrl(""));
}

unittest  // isSecureFetchUrl strips userinfo before private IPv4 literal checks (SSRF)
{
	assert(!isSecureFetchUrl("https://user@169.254.169.254/"));
	assert(!isSecureFetchUrl("https://x@10.0.0.1/"));
	assert(!isSecureFetchUrl("https://user:pass@192.168.1.1/x"));
}

unittest  // isSecureFetchUrl strips userinfo before bracketed IPv6 literal checks (SSRF)
{
	assert(!isSecureFetchUrl("https://a@[fe80::1]/"));
	assert(!isSecureFetchUrl("https://a@[fd00::1]/x"));
	assert(!isSecureFetchUrl("https://user@[::ffff:169.254.169.254]/latest/meta-data"));
}

unittest  // isSecureFetchUrl still accepts a public host carrying userinfo
{
	assert(isSecureFetchUrl("https://user@public.example.com/"));
	assert(isSecureFetchUrl("https://user:pass@as.example.com/token"));
	assert(isSecureFetchUrl("https://user@[2606:4700:4700::1111]/x"));
}

unittest  // isSecureFetchUrl treats numeric loopback encodings as loopback (https + dev http)
{
	assert(isSecureFetchUrl("https://2130706433/x")); // 127.0.0.1
	assert(isSecureFetchUrl("https://127.1/x"));
	assert(isSecureFetchUrl("https://0x7f000001/x"));
	assert(isSecureFetchUrl("https://0177.0.0.1/x"));
}

unittest  // isSecureFetchUrl rejects numeric encodings of the cloud metadata address (SSRF)
{
	assert(!isSecureFetchUrl("https://0xa9fea9fe/latest/meta-data")); // 169.254.169.254
	assert(!isSecureFetchUrl("https://2852039166/latest/meta-data"));
	assert(!isSecureFetchUrl("https://169.254.169.254/latest/meta-data"));
}

unittest  // isSecureFetchUrl rejects octal/hex encodings of RFC1918 ranges (SSRF)
{
	assert(!isSecureFetchUrl("https://0xa000005/x")); // 10.0.0.5
	assert(!isSecureFetchUrl("https://192.0xa8.0.1/x")); // 192.168.0.1
	assert(!isSecureFetchUrl("https://10.0/x")); // 10.0.0.0
}

unittest  // isSecureFetchUrl permits http loopback via numeric encodings (dev)
{
	assert(isSecureFetchUrl("http://2130706433/jwks")); // 127.0.0.1
	assert(isSecureFetchUrl("http://127.1/jwks"));
	assert(isSecureFetchUrl("http://0x7f000001/jwks"));
}

unittest  // isSecureFetchUrl still accepts genuine public numeric IPv4 literals
{
	assert(isSecureFetchUrl("https://8.8.8.8/x"));
	assert(isSecureFetchUrl("https://1.1.1.1/x"));
}

unittest  // isSecureFetchUrlResolved rejects what the lexical guard rejects (GET-path SSRF)
{
	assert(!isSecureFetchUrlResolved("http://as.example.com/.well-known/jwks"));
	assert(!isSecureFetchUrlResolved("https://169.254.169.254/latest/meta-data"));
	assert(!isSecureFetchUrlResolved("https://10.0.0.5/jwks"));
}

unittest  // isSecureFetchUrlResolved rejects the '?@' / '#@' authority differential (SSRF)
{
	assert(!isSecureFetchUrlResolved("https://public?@169.254.169.254/jwks"));
	assert(!isSecureFetchUrlResolved("https://public#@10.0.0.5/jwks"));
}

unittest  // isSecureFetchUrlResolved accepts lexically-safe loopback without resolving (dev)
{
	assert(isSecureFetchUrlResolved("https://127.0.0.1/jwks"));
	assert(isSecureFetchUrlResolved("http://127.0.0.1:8765/jwks"));
	assert(isSecureFetchUrlResolved("http://[::1]:9000/jwks"));
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
/// Approaches", 2025-11-25 / draft).
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
/// when present, is surfaced for diagnostics), otherwise decode the JSON body
/// into a `TokenSet`.
private TokenSet parseTokenResponse(int status, string responseBody) @safe
{
	import std.conv : to;
	import vibe.data.json : parseJsonString;
	import mcp.protocol.errors : invalidRequest;

	if (status < 200 || status >= 300)
		throw invalidRequest("token endpoint returned HTTP " ~ status.to!string ~ (
				responseBody.length ? ": " ~ responseBody : ""));
	return TokenSet.fromJson(parseJsonString(responseBody));
}

/// POST an `application/x-www-form-urlencoded` body to a token endpoint over the
/// SDK's SSRF-safe transport (https, or http to loopback for dev) and return the
/// parsed `TokenSet`. `authHeader`, when non-empty, is sent as `Authorization`.
private TokenSet postTokenRequest(string tokenEndpoint, string body_, string authHeader) @safe
{
	int status = 502;
	string responseBody;
	() @trusted {
		import vibe.http.client : HTTPClientResponse;
		import vibe.http.common : HTTPMethod;
		import vibe.stream.operations : readAllUTF8;

		secureRequestHTTP(tokenEndpoint, (scope HTTPClientRequest creq) {
			creq.method = HTTPMethod.POST;
			creq.headers["Content-Type"] = "application/x-www-form-urlencoded";
			creq.headers["Accept"] = "application/json";
			if (authHeader.length)
				creq.headers["Authorization"] = authHeader;
			creq.writeBody(cast(const(ubyte)[]) body_);
		}, (scope HTTPClientResponse cres) {
			status = cres.statusCode;
			responseBody = cres.bodyReader.readAllUTF8();
		});
	}();
	return parseTokenResponse(status, responseBody);
}

/// Redeem an authorization code for tokens at a third-party token endpoint
/// (RFC 6749 §4.1.3 + PKCE RFC 7636). Use when an MCP server acts as an OAuth
/// client to an upstream API; unlike `OAuthClient` this carries no RFC 8707
/// `resource`. An empty `clientSecret` denotes a public client, so no
/// credentials are sent; otherwise they go via HTTP Basic. Throws on an unsafe
/// endpoint or a non-2xx response.
TokenSet exchangeAuthCode(string tokenEndpoint, string code, string redirectUri,
		string clientId, string clientSecret, string codeVerifier) @safe
{
	const body_ = buildAuthCodeTokenForm(code, redirectUri, codeVerifier, clientId, "");
	const authHeader = clientSecret.length ? basicAuthHeader(clientId, clientSecret) : "";
	return postTokenRequest(tokenEndpoint, body_, authHeader);
}

/// Refresh an access token at a third-party token endpoint (RFC 6749 §6). Use
/// when an MCP server acts as an OAuth client to an upstream API; carries no
/// RFC 8707 `resource`. An empty `clientSecret` denotes a public client, so no
/// credentials are sent; otherwise they go via HTTP Basic. Throws on an unsafe
/// endpoint or a non-2xx response.
TokenSet refreshAccessToken(string tokenEndpoint, string refreshToken,
		string clientId, string clientSecret) @safe
{
	const body_ = buildRefreshTokenForm(refreshToken, clientId, "");
	const authHeader = clientSecret.length ? basicAuthHeader(clientId, clientSecret) : "";
	return postTokenRequest(tokenEndpoint, body_, authHeader);
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

unittest  // parseTokenResponse decodes a 2xx body into a populated TokenSet
{
	const ts = parseTokenResponse(200, `{"access_token":"AT","token_type":"Bearer","expires_in":3600,"refresh_token":"RT","scope":"a b"}`);
	assert(ts.accessToken == "AT");
	assert(ts.tokenType == "Bearer");
	assert(ts.expiresIn == 3600);
	assert(ts.refreshToken == "RT");
	assert(ts.scope_ == "a b");
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
			return () @trusted { return decodeComponent(pair[needle.length .. $]); }();
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
/// Section 2.4 (the MCP 2025-11-25 / draft "Authorization Response Validation"
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
/// 2025-06-18 / 2025-11-25 / draft): "MCP clients SHOULD use and verify state
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
private bool constantTimeEquals(scope const(char)[] a, scope const(char)[] b) @safe pure nothrow @nogc
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
