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

/// A parsed `WWW-Authenticate` challenge: the auth scheme plus its parameters
/// (e.g. `resource_metadata`, `scope`, `error`).
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
	import std.string : indexOf;

	// Split scheme://host[/path]
	auto schemeEnd = mcpEndpoint.indexOf("://");
	if (schemeEnd < 0)
		return [mcpEndpoint];
	const afterScheme = schemeEnd + 3;
	const slash = mcpEndpoint[afterScheme .. $].indexOf('/');
	string origin = (slash < 0) ? mcpEndpoint : mcpEndpoint[0 .. afterScheme + slash];
	string path = (slash < 0) ? "" : mcpEndpoint[afterScheme + slash .. $];

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
	const path = iss[afterScheme + slash .. $];
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

unittest  // AS metadata candidates insert well-known after origin, before path
{
	auto root = authServerMetadataCandidates("https://auth.example.com");
	assert(root[0] == "https://auth.example.com/.well-known/oauth-authorization-server");

	auto tenant = authServerMetadataCandidates("https://auth.example.com/tenant1");
	assert(tenant[0] == "https://auth.example.com/.well-known/oauth-authorization-server/tenant1");
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

/// Canonicalize a bare all-numeric IPv4 authority host into four octets using
/// `inet_aton` rules so that alternate encodings cannot slip past the SSRF
/// guard. Accepts 1-4 parts where each part may be decimal, octal (`0`-prefix)
/// or hex (`0x`-prefix); a short form lets the final part absorb the remaining
/// low bytes (1 part = 32 bits, 2 parts = a.(24 bits), 3 parts = a.b.(16 bits)).
/// Returns true and fills `outOct` only when the whole host is such a literal;
/// returns false for any host that is not a pure numeric IPv4 literal (e.g. a
/// registered hostname), which the caller treats as "not an IP literal".
/// `@safe pure nothrow @nogc`.
private bool canonicalizeNumericIpv4(string host, out ubyte[4] outOct) @safe pure nothrow @nogc
{
	if (host.length == 0)
		return false;

	// Parse 1-4 dot-separated parts, each decimal/octal/hex.
	ulong[4] part;
	size_t parts;
	size_t i;
	while (i < host.length)
	{
		if (parts >= 4)
			return false;
		ulong v;
		size_t digits;
		if (i + 1 < host.length && host[i] == '0' && (host[i + 1] == 'x' || host[i + 1] == 'X'))
		{
			// Hex part.
			i += 2;
			while (i < host.length)
			{
				const ch = host[i];
				uint d;
				if (ch >= '0' && ch <= '9')
					d = cast(uint)(ch - '0');
				else if (ch >= 'a' && ch <= 'f')
					d = cast(uint)(ch - 'a' + 10);
				else if (ch >= 'A' && ch <= 'F')
					d = cast(uint)(ch - 'A' + 10);
				else
					break;
				v = v * 16 + d;
				if (v > 0xFFFF_FFFFUL)
					return false;
				i++;
				digits++;
			}
		}
		else if (host[i] == '0' && i + 1 < host.length && host[i + 1] >= '0'
				&& host[i + 1] <= '7' && !(i + 1 < host.length && host[i + 1] == '.'))
		{
			// Octal part (leading 0 followed by octal digits).
			i++; // skip leading 0
			digits++;
			while (i < host.length && host[i] >= '0' && host[i] <= '7')
			{
				v = v * 8 + cast(uint)(host[i] - '0');
				if (v > 0xFFFF_FFFFUL)
					return false;
				i++;
				digits++;
			}
			// A non-octal digit (8/9) inside an octal part is not a valid literal.
			if (i < host.length && host[i] >= '0' && host[i] <= '9')
				return false;
		}
		else
		{
			// Decimal part.
			while (i < host.length && host[i] >= '0' && host[i] <= '9')
			{
				v = v * 10 + cast(uint)(host[i] - '0');
				if (v > 0xFFFF_FFFFUL)
					return false;
				i++;
				digits++;
			}
		}
		if (digits == 0)
			return false; // empty part -> not a numeric literal
		part[parts++] = v;
		if (i < host.length)
		{
			if (host[i] != '.')
				return false; // trailing junk -> not a numeric literal
			i++;
			if (i == host.length)
				return false; // trailing dot
		}
	}
	if (parts == 0)
		return false;

	// Combine parts per inet_aton short-form rules into a 32-bit address.
	ulong addr;
	final switch (parts)
	{
	case 1:
		addr = part[0];
		break;
	case 2:
		if (part[0] > 0xFF || part[1] > 0x00FF_FFFF)
			return false;
		addr = (part[0] << 24) | part[1];
		break;
	case 3:
		if (part[0] > 0xFF || part[1] > 0xFF || part[2] > 0xFFFF)
			return false;
		addr = (part[0] << 24) | (part[1] << 16) | part[2];
		break;
	case 4:
		if (part[0] > 0xFF || part[1] > 0xFF || part[2] > 0xFF || part[3] > 0xFF)
			return false;
		addr = (part[0] << 24) | (part[1] << 16) | (part[2] << 8) | part[3];
		break;
	}
	if (addr > 0xFFFF_FFFFUL)
		return false;
	outOct[0] = cast(ubyte)((addr >> 24) & 0xFF);
	outOct[1] = cast(ubyte)((addr >> 16) & 0xFF);
	outOct[2] = cast(ubyte)((addr >> 8) & 0xFF);
	outOct[3] = cast(ubyte)(addr & 0xFF);
	return true;
}

/// The set of explicit loopback hosts permitted over plaintext `http` for
/// local development (MCP loopback redirect URIs, locally-hosted dev auth
/// servers). Any other host MUST use `https`. Numeric encodings of the loopback
/// address (e.g. `127.1`, `2130706433`, `0x7f000001`) are canonicalized so they
/// are recognized rather than slipping through as opaque hostnames.
private bool isLoopbackHost(string host) @safe pure nothrow @nogc
{
	// Strip an optional port suffix (host:port). IPv6 literals are bracketed.
	import std.string : indexOf;

	if (host.length && host[0] == '[')
	{
		const close = host.indexOf(']');
		if (close > 0)
			host = host[1 .. close];
	}
	else
	{
		// Strip a `host:port` suffix, but not the colons of a bracketless IPv6
		// literal (vibe's URL parser yields IPv6 hosts without brackets). A single
		// colon is a port separator; two or more colons mark an IPv6 address.
		const colon = host.indexOf(':');
		if (colon >= 0 && host.indexOf(':', colon + 1) < 0)
			host = host[0 .. colon];
	}
	if (host == "localhost" || host == "::1")
		return true;
	// Treat any numeric encoding that canonicalizes into 127.0.0.0/8 as loopback
	// (covers 127.0.0.1, 127.1, 2130706433, 0x7f000001, 0177.0.0.1, ...).
	ubyte[4] oct;
	if (canonicalizeNumericIpv4(host, oct))
		return oct[0] == 127;
	return false;
}

/// Reject a private/link-local IPv4 literal host to close the SSRF /
/// DNS-rebinding vector the MCP authorization spec calls out (e.g. the cloud
/// metadata service at 169.254.169.254, RFC 1918 ranges). Returns true when the
/// host is a private/link-local IPv4 *literal* that is not an explicit loopback
/// (loopback is handled separately and permitted for dev). Numeric encodings
/// (decimal-integer, octal, hex and inet_aton short forms such as `0x7f000001`
/// or `2852039166`) are canonicalized first so they cannot bypass the filter.
private bool isPrivateIpv4Literal(string host) @safe pure nothrow @nogc
{
	import std.string : indexOf;

	// Strip an optional port suffix.
	const colon = host.indexOf(':');
	if (colon >= 0)
		host = host[0 .. colon];

	ubyte[4] oct;
	if (!canonicalizeNumericIpv4(host, oct))
		return false; // not a numeric IPv4 literal in any encoding

	// 127.0.0.0/8 loopback is handled/permitted by isLoopbackHost; not flagged here.
	if (oct[0] == 127)
		return false;
	return isUnsafeIpv4Octets(oct[0], oct[1], oct[2], oct[3]);
}

/// Parse an IPv6 literal (the inner text of a bracketed host, with any zone-id
/// stripped) into 16 bytes, expanding a `::` run. Returns false (fail closed)
/// on any malformed input. Handles the embedded-IPv4 tail forms
/// (`::ffff:a.b.c.d`, `::a.b.c.d`) by parsing the dotted-decimal suffix into the
/// final 4 bytes. `@safe pure nothrow @nogc`.
private bool parseIpv6Literal(string s, out ubyte[16] outBytes) @safe pure nothrow @nogc
{
	import std.string : indexOf;

	// Strip a zone id (e.g. fe80::1%eth0).
	const pct = s.indexOf('%');
	if (pct >= 0)
		s = s[0 .. pct];
	if (s.length == 0)
		return false;

	// Detect and parse a trailing embedded IPv4 (dotted-decimal) tail.
	bool haveV4;
	ubyte[4] v4;
	{
		// Find the last ':' — the IPv4 tail (if any) follows it.
		ptrdiff_t lastColon = -1;
		foreach (k, ch; s)
			if (ch == ':')
				lastColon = k;
		auto tail = (lastColon < 0) ? s : s[lastColon + 1 .. $];
		bool hasDot;
		foreach (ch; tail)
			if (ch == '.')
				hasDot = true;
		if (hasDot)
		{
			uint[4] oct;
			size_t idx;
			size_t i;
			while (i < tail.length)
			{
				uint v;
				size_t digits;
				while (i < tail.length && tail[i] >= '0' && tail[i] <= '9')
				{
					v = v * 10 + cast(uint)(tail[i] - '0');
					if (v > 255)
						return false;
					i++;
					digits++;
				}
				if (digits == 0)
					return false;
				if (idx >= 4)
					return false;
				oct[idx++] = v;
				if (i < tail.length)
				{
					if (tail[i] != '.')
						return false;
					i++;
				}
			}
			if (idx != 4)
				return false;
			v4 = [
				cast(ubyte) oct[0], cast(ubyte) oct[1], cast(ubyte) oct[2],
				cast(ubyte) oct[3]
			];
			haveV4 = true;
			// Replace the IPv4 tail with the hextet portion for hextet parsing.
			s = (lastColon < 0) ? "" : s[0 .. lastColon + 1];
		}
	}

	// Split on "::" (at most one allowed).
	ptrdiff_t dbl = -1;
	for (size_t k = 0; k + 1 < s.length; k++)
	{
		if (s[k] == ':' && s[k + 1] == ':')
		{
			dbl = k;
			break;
		}
	}

	const v4bytes = haveV4 ? 4 : 0;
	const totalHextetBytes = 16 - v4bytes;

	if (dbl < 0)
	{
		// No "::": must fully fill the hextet area.
		ubyte[16] tmp;
		const n = parseHextets(s, tmp[0 .. totalHextetBytes]);
		if (n != totalHextetBytes)
			return false;
		outBytes[0 .. totalHextetBytes] = tmp[0 .. totalHextetBytes];
	}
	else
	{
		auto left = s[0 .. dbl];
		auto right = (dbl + 2 <= s.length) ? s[dbl + 2 .. $] : "";
		// A leading or trailing ':' adjacent to "::" (i.e. ":::") is invalid; left
		// must not end with ':' and right must not start with ':'.
		if (left.length && left[$ - 1] == ':')
			return false;
		if (right.length && right[0] == ':')
			return false;
		ubyte[16] lbuf;
		ubyte[16] rbuf;
		const ln = parseHextets(left, lbuf[]);
		if (ln < 0)
			return false;
		const rn = parseHextets(right, rbuf[]);
		if (rn < 0)
			return false;
		if (ln + rn > totalHextetBytes)
			return false;
		outBytes[] = 0;
		outBytes[0 .. ln] = lbuf[0 .. ln];
		outBytes[totalHextetBytes - rn .. totalHextetBytes] = rbuf[0 .. rn];
	}

	if (haveV4)
		outBytes[12 .. 16] = v4[];
	return true;
}

/// Parse a colon-separated list of IPv6 hextets into bytes; returns count of
/// bytes written, or -1 on error. An empty segment yields 0 bytes.
private ptrdiff_t parseHextets(string seg, ubyte[] dst) @safe pure nothrow @nogc
{
	if (seg.length == 0)
		return 0;
	size_t written;
	size_t i;
	while (i <= seg.length)
	{
		// Read one hextet (1-4 hex digits) up to ':' or end.
		uint v;
		size_t digits;
		while (i < seg.length && seg[i] != ':')
		{
			const ch = seg[i];
			uint d;
			if (ch >= '0' && ch <= '9')
				d = ch - '0';
			else if (ch >= 'a' && ch <= 'f')
				d = ch - 'a' + 10;
			else if (ch >= 'A' && ch <= 'F')
				d = ch - 'A' + 10;
			else
				return -1;
			v = (v << 4) | d;
			digits++;
			if (digits > 4)
				return -1;
			i++;
		}
		if (digits == 0)
			return -1;
		if (written + 2 > dst.length)
			return -1;
		dst[written++] = cast(ubyte)(v >> 8);
		dst[written++] = cast(ubyte)(v & 0xff);
		if (i == seg.length)
			break;
		i++; // skip ':'
		if (i == seg.length)
			return -1; // trailing single ':'
	}
	return written;
}

/// Reject an IPv6 *literal* host (the inner text of a bracketed `[...]` host)
/// that targets an internal/link-local/loopback/embedded-private address.
/// Returns true when the literal must be rejected. Unparseable literals fail
/// closed (rejected). The `loopback` flag is passed so that the explicit
/// `[::1]` dev case (already permitted over http elsewhere) is not flagged.
private bool isUnsafeIpv6Literal(string inner, bool loopback) @safe pure nothrow @nogc
{
	ubyte[16] b;
	if (!parseIpv6Literal(inner, b))
		return true; // fail closed

	// Unspecified "::".
	bool allZero = true;
	foreach (x; b)
		if (x != 0)
		{
			allZero = false;
			break;
		}
	if (allZero)
		return true;

	// Loopback ::1 — permitted only via the loopback dev path.
	bool isLoopbackV6 = true;
	foreach (k; 0 .. 15)
		if (b[k] != 0)
		{
			isLoopbackV6 = false;
			break;
		}
	if (isLoopbackV6 && b[15] == 1)
		return !loopback;

	// ULA fc00::/7 (first byte 0xFC or 0xFD).
	if (b[0] == 0xFC || b[0] == 0xFD)
		return true;
	// Link-local fe80::/10 (0xFE 0x80..0xBF).
	if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80)
		return true;

	// IPv4-mapped ::ffff:a.b.c.d/96 and IPv4-compatible ::/96 (first 12 bytes
	// either 0...0 ffff or all zero) — extract the embedded IPv4 and delegate.
	bool mapped = true;
	foreach (k; 0 .. 10)
		if (b[k] != 0)
		{
			mapped = false;
			break;
		}
	if (mapped && ((b[10] == 0xFF && b[11] == 0xFF) || (b[10] == 0 && b[11] == 0)))
		return isUnsafeIpv4Octets(b[12], b[13], b[14], b[15]);

	return false;
}

/// Range-check four IPv4 octets for the private/link-local/loopback/this-host
/// ranges that the SSRF guard rejects. Mirrors `isPrivateIpv4Literal` but also
/// rejects 127/8 (loopback), since an embedded IPv4 inside an IPv6 literal has
/// no legitimate dev-loopback meaning. `@safe pure nothrow @nogc`.
private bool isUnsafeIpv4Octets(ubyte a, ubyte b, ubyte c, ubyte d) @safe pure nothrow @nogc
{
	if (a == 127) // 127.0.0.0/8 loopback
		return true;
	if (a == 10) // 10.0.0.0/8
		return true;
	if (a == 172 && b >= 16 && b <= 31) // 172.16.0.0/12
		return true;
	if (a == 192 && b == 168) // 192.168.0.0/16
		return true;
	if (a == 169 && b == 254) // 169.254.0.0/16 link-local (incl. metadata 169.254.169.254)
		return true;
	if (a == 0) // 0.0.0.0/8 "this host"
		return true;
	return false;
}

/// Whether `url` is safe to fetch for OAuth/discovery: it MUST use the `https`
/// scheme, OR target an explicit loopback host (`localhost`, `127.0.0.1`,
/// `[::1]`) over `http` for local development. Plaintext `http` to any other
/// host is rejected, as are URLs whose host is a private/link-local IPv4 or
/// IPv6 literal — including alternate numeric IPv4 encodings (decimal/octal/hex
/// and inet_aton short forms) and IPv4-mapped/compatible IPv6 (SSRF / DNS-
/// rebinding mitigation, e.g. 169.254.169.254 / RFC 1918, fc00::/7, fe80::/10).
///
/// This guard is purely lexical: it inspects the host as written and does not
/// perform DNS resolution, and it parses the authority independently of the HTTP
/// connector. It is therefore only a coarse pre-filter (used on the WWW-
/// Authenticate metadata URL). The authoritative, TOCTOU-safe SSRF guard for an
/// actual fetch is `secureRequestHTTP`, which parses with vibe's own URL parser
/// (no parser differential), resolves the host once, vets every returned
/// address, and PINS the connection to a vetted address.
bool isSecureFetchUrl(string url) @safe pure nothrow @nogc
{
	import std.string : indexOf;

	const schemeEnd = url.indexOf("://");
	if (schemeEnd < 0)
		return false;
	auto scheme = url[0 .. schemeEnd];
	auto rest = url[schemeEnd + 3 .. $];
	// Host is everything up to the first '/', '?' or '#'.
	size_t hostEnd = rest.length;
	foreach (k, ch; rest)
	{
		if (ch == '/' || ch == '?' || ch == '#')
		{
			hostEnd = k;
			break;
		}
	}
	auto host = rest[0 .. hostEnd];
	// Drop an optional `userinfo@` prefix so the host checks inspect the real
	// authority host rather than the user component.
	const at = host.indexOf('@');
	if (at >= 0)
		host = host[at + 1 .. $];
	if (host.length == 0)
		return false;

	const loopback = isLoopbackHost(host);

	// Reject internal/link-local IPv6 literals (bracketed host) regardless of
	// scheme, mirroring the IPv4 path. Permits only the explicit [::1] dev case.
	if (host[0] == '[')
	{
		const close = host.indexOf(']');
		if (close < 0)
			return false; // malformed bracketed host -> fail closed
		auto inner = host[1 .. close];
		if (isUnsafeIpv6Literal(inner, loopback))
			return false;
	}
	// Reject private/link-local IPv4 literals (non-loopback) regardless of scheme.
	if (!loopback && isPrivateIpv4Literal(host))
		return false;

	// Case-insensitive scheme compare without allocating.
	bool eqScheme(string sc)
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

	if (eqScheme("https"))
		return true;
	if (eqScheme("http") && loopback)
		return true;
	return false;
}

/// Extract the bare authority host from a fetch URL: everything after `://` up
/// to the first `/`, `?` or `#`, with an optional `userinfo@` prefix dropped and
/// any surrounding brackets/port preserved as written. Returns the empty string
/// when the URL has no `://` or no host. `@safe pure nothrow @nogc`.
private string fetchUrlHost(string url) @safe pure nothrow @nogc
{
	import std.string : indexOf;

	const schemeEnd = url.indexOf("://");
	if (schemeEnd < 0)
		return "";
	auto rest = url[schemeEnd + 3 .. $];
	size_t hostEnd = rest.length;
	foreach (k, ch; rest)
	{
		if (ch == '/' || ch == '?' || ch == '#')
		{
			hostEnd = k;
			break;
		}
	}
	auto host = rest[0 .. hostEnd];
	const at = host.indexOf('@');
	if (at >= 0)
		host = host[at + 1 .. $];
	return host;
}

/// Whether a resolved address, given as its numeric string form (as produced by
/// `std.socket.Address.toAddrString`), falls in a private/link-local/loopback/
/// ULA range that the SSRF guard rejects. Dotted-quad and integer IPv4 forms go
/// through `isUnsafeIpv4Octets`; bracketless IPv6 forms go through the IPv6
/// literal classifier (with `loopback=false` so `::1` from a resolved hostname
/// is treated as unsafe). `@safe pure nothrow @nogc`.
private bool isUnsafeResolvedAddress(string addr) @safe pure nothrow @nogc
{
	import std.string : indexOf;

	// Strip a zone id if the resolver attached one (e.g. fe80::1%en0).
	const pct = addr.indexOf('%');
	if (pct >= 0)
		addr = addr[0 .. pct];
	if (addr.length == 0)
		return true; // fail closed

	// IPv6 addresses contain a ':'; IPv4 (dotted or numeric) never does.
	if (addr.indexOf(':') >= 0)
		return isUnsafeIpv6Literal(addr, false);

	ubyte[4] oct;
	if (!canonicalizeNumericIpv4(addr, oct))
		return true; // unrecognized literal -> fail closed
	return isUnsafeIpv4Octets(oct[0], oct[1], oct[2], oct[3]);
}

/// Resolve a registered hostname, vet EVERY returned A/AAAA address against the
/// private/link-local/loopback/ULA ranges, and return a single vetted numeric
/// address string to connect to so that the value checked is the value the
/// connector uses (TOCTOU close: the caller pins the connection to this address
/// rather than letting the connector re-resolve the name). `ok` is set false —
/// and the empty string returned — when the host cannot be resolved (fail
/// CLOSED) or when any resolved address is unsafe. IP literals and loopback
/// hosts are already vetted lexically; for those `ok` is true and the bare host
/// is returned unchanged so the connector uses it verbatim. `@safe`.
private string vettedConnectAddress(string host, out bool ok) @safe
{
	import std.string : indexOf;
	import std.socket : getAddressInfo, AddressFamily, SocketException;

	ok = false;
	if (host.length == 0)
		return "";

	// Bracketed IPv6 literals and loopback hosts are handled lexically; connect
	// to them verbatim (the lexical guard already vetted IP-literal ranges).
	if (host[0] == '[')
	{
		ok = true;
		return host;
	}
	if (isLoopbackHost(host))
	{
		ok = true;
		return host;
	}

	// Strip an optional `host:port` suffix (a single trailing colon) to obtain the
	// bare hostname; preserve the colons of a bracketless IPv6 literal.
	auto bare = host;
	const colon = bare.indexOf(':');
	if (colon >= 0 && bare.indexOf(':', colon + 1) < 0)
		bare = bare[0 .. colon];

	// A numeric IPv4 literal in any encoding is already vetted lexically; connect
	// to it verbatim.
	ubyte[4] oct;
	if (canonicalizeNumericIpv4(bare, oct))
	{
		ok = true;
		return host;
	}

	try
	{
		auto infos = getAddressInfo(bare);
		string chosen;
		foreach (info; infos)
		{
			if (info.family != AddressFamily.INET && info.family != AddressFamily.INET6)
				continue;
			const addr = info.address.toAddrString();
			if (isUnsafeResolvedAddress(addr))
				return ""; // any unsafe address -> reject the whole host
			if (chosen.length == 0)
				chosen = addr;
		}
		if (chosen.length == 0)
			return ""; // no usable A/AAAA record -> fail closed
		ok = true;
		return chosen;
	}
	catch (SocketException)
	{
		return ""; // unresolved -> fail CLOSED; never fall through to an un-vetted connect
	}
}

/// Whether a registered hostname resolves only to safe (public) addresses.
/// Thin boolean wrapper over `vettedConnectAddress`; fails CLOSED on a
/// resolution error. `@safe`.
private bool resolvedHostIsSafe(string host) @safe
{
	bool ok;
	vettedConnectAddress(host, ok);
	return ok;
}

/// Parse `url` with the SAME parser the connector uses (`vibe.inet.url.URL`) and
/// return its scheme and authority host. This is the single source of truth that
/// closes the parser-differential class of SSRF bypasses: the bytes vetted below
/// are exactly the bytes vibe will connect to, so a guard/connector disagreement
/// over where the authority ends (`?@`, `#@`, control bytes, multiple `@`, etc.)
/// cannot route a vetted request to a different host. `host` is the empty string
/// when the URL is malformed or carries no host. `@safe`.
private void parseFetchUrl(string url, out string scheme, out string host) @safe
{
	import vibe.inet.url : URL;

	scheme = "";
	host = "";
	try
	{
		auto u = URL(url);
		scheme = u.schema;
		host = u.host;
	}
	catch (Exception)
	{
		// Unparseable -> leave both empty; callers fail closed.
	}
}

/// Whether the (scheme, host) pair extracted by `parseFetchUrl` is lexically
/// permitted: https to any host, or http to an explicit loopback host, with
/// private/link-local IP literals rejected in either scheme. Mirrors
/// `isSecureFetchUrl` but operates on the already-separated authority host from
/// vibe's parser, so there is no second, divergent host parse. `@safe`.
private bool schemeHostIsSecure(string scheme, string host) @safe nothrow @nogc
{
	import std.string : indexOf;

	if (host.length == 0)
		return false;

	const loopback = isLoopbackHost(host);

	if (host[0] == '[')
	{
		const close = host.indexOf(']');
		if (close >= 0)
		{
			auto inner = host[1 .. close];
			if (isUnsafeIpv6Literal(inner, loopback))
				return false;
		}
		// A bracketless IPv6 host coming from vibe's parser (it strips brackets)
		// is handled by the no-bracket branch below.
	}
	else if (host.indexOf(':') >= 0 && host.indexOf('.') < 0)
	{
		// vibe stores IPv6 hosts without brackets; classify them too.
		if (isUnsafeIpv6Literal(host, loopback))
			return false;
	}
	if (!loopback && isPrivateIpv4Literal(host))
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

	if (eqScheme("https"))
		return true;
	if (eqScheme("http") && loopback)
		return true;
	return false;
}

/// Throw `invalidRequest` when `url` is not safe to fetch. Parses the URL with
/// vibe's own parser (the single source of truth), applies the scheme +
/// IP-literal guard. This is a check-time scheme/host gate (no DNS resolution),
/// suitable for paths that VALIDATE a URL without fetching it (e.g. building the
/// authorization-request URL the host will open). Because the host is taken from
/// vibe's own parser, the `?@` / `#@` authority differential cannot route past
/// it. The TOCTOU-safe resolve-and-pin connect for an actual fetch is performed
/// by `secureRequestHTTP`, which every outbound OAuth/discovery request uses.
void requireSecureUrl(string url) @safe
{
	import mcp.protocol.errors : invalidRequest;

	string scheme, host;
	parseFetchUrl(url, scheme, host);

	if (!schemeHostIsSecure(scheme, host))
		throw invalidRequest(
				"Refusing to fetch insecure OAuth/discovery URL (must be https, or http to an "
				~ "explicit loopback host; private/link-local addresses are rejected): " ~ url);
}

/// Non-throwing scheme/host + resolution gate. Returns true only when the
/// vibe-parsed scheme/host pass the lexical guard AND the host resolves only to
/// safe addresses (fail CLOSED on a resolution error). Loopback and IP-literal
/// hosts short-circuit without resolving. `@safe`.
bool isSecureFetchUrlResolved(string url) @safe
{
	string scheme, host;
	parseFetchUrl(url, scheme, host);
	if (!schemeHostIsSecure(scheme, host))
		return false;
	return resolvedHostIsSafe(host);
}

/// Consolidated SSRF-safe HTTP fetch used by every outbound OAuth/discovery
/// request. This is the one place that closes the SSRF class for good:
///
/// 1. Parse `url` with vibe's `URL` — the exact parser the connector uses — so
///    the host vetted is the host connected to (no parser differential).
/// 2. Reject by scheme + IP-literal ranges (`schemeHostIsSecure`).
/// 3. Resolve the host ONCE, vet every returned address, and pick a vetted IP
///    (`vettedConnectAddress`); fail CLOSED on a resolution error.
/// 4. Rewrite the request URL's host to that vetted IP literal and pin the
///    connection to it, while preserving the original hostname for the `Host`
///    header and TLS SNI (`tlsPeerName`). The connector therefore connects to
///    the address we vetted rather than re-resolving the name (no TOCTOU).
///
/// Throws `invalidRequest` when the URL is unsafe (insecure scheme, an IP-literal
/// or resolved address in a private/link-local range, or an unresolvable host —
/// fail CLOSED). `@trusted` because the vibe HTTP client API is `@system`; the
/// requester/responder run inside the same trusted boundary as the existing call
/// sites did.
void secureRequestHTTP(string url, scope void delegate(scope HTTPClientRequest) requester,
		scope void delegate(scope HTTPClientResponse) responder) @trusted
{
	import mcp.protocol.errors : invalidRequest;
	import std.string : indexOf;
	import vibe.inet.url : URL;
	import vibe.http.client : requestHTTP, HTTPClientSettings;

	string scheme, host;
	parseFetchUrl(url, scheme, host);
	if (!schemeHostIsSecure(scheme, host))
		throw invalidRequest(
				"Refusing to fetch insecure OAuth/discovery URL (must be https, or http to an "
				~ "explicit loopback host; private/link-local addresses are rejected): " ~ url);

	bool ok;
	const connectAddr = vettedConnectAddress(host, ok);
	if (!ok)
		throw invalidRequest("Refusing to fetch OAuth/discovery URL whose host resolves to a "
				~ "private/link-local address (or could not be resolved): " ~ url);

	// Build the pinned URL: same scheme/path/port/userinfo, host replaced by the
	// vetted numeric address so the connector cannot re-resolve to a different
	// (internal) target. Preserve the original host for Host header + SNI.
	const originalHost = host;
	auto u = URL(url);
	// Strip a port suffix from the chosen address before assigning to the URL
	// host (the URL keeps its own port).
	string connHost = connectAddr;
	if (connHost.length && connHost[0] != '[')
	{
		const c = connHost.indexOf(':');
		// Only IPv4/host:port carries a single ':'; an unbracketed IPv6 literal
		// has many. Keep IPv6 (many colons) intact; trim host:port.
		if (c >= 0 && connHost.indexOf(':', c + 1) < 0)
			connHost = connHost[0 .. c];
	}
	u.host = connHost;

	auto settings = new HTTPClientSettings;
	settings.tlsPeerName = originalHost;

	// vibe derives the Host header from u.host; restore the original host so the
	// server sees the intended virtual host, not the pinned IP.
	string hostHeader = originalHost;
	if (u.port && u.port != u.defaultPort)
	{
		import std.conv : to;

		hostHeader = (originalHost.indexOf(':') >= 0 ? "[" ~ originalHost ~ "]" : originalHost)
			~ ":" ~ u.port.to!string;
	}

	requestHTTP(u, (scope HTTPClientRequest req) {
		req.headers["Host"] = hostHeader;
		if (requester !is null)
			requester(req);
	}, (scope HTTPClientResponse res) {
		if (responder !is null)
			responder(res);
	}, settings);
}

unittest  // parseFetchUrl uses vibe's authority parse so '?@' does not hide an internal host
{
	// vibe treats '?' and '#' as plain authority bytes (not terminators), so the
	// real host after the first '@' is the internal address — the guard must see
	// the SAME host vibe will connect to and reject it.
	string scheme, host;
	parseFetchUrl("https://public?@169.254.169.254/jwks", scheme, host);
	assert(host == "169.254.169.254");
	assert(!schemeHostIsSecure(scheme, host));
}

unittest  // parseFetchUrl uses vibe's authority parse so '#@' does not hide an internal host
{
	string scheme, host;
	parseFetchUrl("https://public#@10.0.0.5/jwks", scheme, host);
	assert(host == "10.0.0.5");
	assert(!schemeHostIsSecure(scheme, host));
}

unittest  // isSecureFetchUrlResolved rejects the '?@' / '#@' authority differential (SSRF)
{
	// The end-to-end gate (parse + scheme/host check) must reject both forms; the
	// old lexical guard parsed the host as the benign prefix and let them through.
	assert(!isSecureFetchUrlResolved("https://public?@169.254.169.254/jwks"));
	assert(!isSecureFetchUrlResolved("https://public#@10.0.0.5/jwks"));
}

unittest  // vettedConnectAddress fails CLOSED for an unresolvable hostname (no fail-open)
{
	// RFC 6761 reserves `.invalid` to always fail resolution. The guard must
	// report ok=false (and never fall through to an un-vetted connect).
	bool ok = true;
	const addr = vettedConnectAddress("nonexistent-host.invalid", ok);
	assert(!ok);
	assert(addr.length == 0);
}

unittest  // vettedConnectAddress returns loopback/IP-literal hosts verbatim as safe
{
	bool ok;
	assert(vettedConnectAddress("127.0.0.1", ok) == "127.0.0.1" && ok);
	assert(vettedConnectAddress("localhost", ok) == "localhost" && ok);
	assert(vettedConnectAddress("[::1]", ok) == "[::1]" && ok);
}

unittest  // schemeHostIsSecure mirrors the scheme + IP-literal policy on a pre-split host
{
	assert(schemeHostIsSecure("https", "as.example.com"));
	assert(schemeHostIsSecure("http", "localhost"));
	assert(schemeHostIsSecure("http", "127.0.0.1"));
	assert(!schemeHostIsSecure("http", "internal.local"));
	assert(!schemeHostIsSecure("https", "169.254.169.254"));
	assert(!schemeHostIsSecure("https", "10.0.0.5"));
	assert(!schemeHostIsSecure("", ""));
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
	// A non-loopback host over http is rejected.
	assert(!isSecureFetchUrl("http://internal.local/jwks"));
}

unittest  // isSecureFetchUrl rejects private/link-local IPv4 literals (SSRF)
{
	// Cloud metadata endpoint and RFC 1918 ranges must be rejected even over https.
	assert(!isSecureFetchUrl("https://169.254.169.254/latest/meta-data"));
	assert(!isSecureFetchUrl("https://10.0.0.5/x"));
	assert(!isSecureFetchUrl("https://192.168.1.1/x"));
	assert(!isSecureFetchUrl("https://172.16.0.1/x"));
	assert(!isSecureFetchUrl("http://169.254.169.254/x"));
}

unittest  // isSecureFetchUrl rejects private/ULA/link-local IPv6 literals (SSRF)
{
	// ULA fc00::/7 and link-local fe80::/10 must be rejected even over https.
	assert(!isSecureFetchUrl("https://[fd00::1]/x"));
	assert(!isSecureFetchUrl("https://[fc00::1]/x"));
	assert(!isSecureFetchUrl("https://[fe80::1]/x"));
	// Unspecified.
	assert(!isSecureFetchUrl("https://[::]/x"));
	// IPv4-mapped/compatible embedding internal addresses.
	assert(!isSecureFetchUrl("https://[::ffff:169.254.169.254]/latest/meta-data"));
	assert(!isSecureFetchUrl("https://[::ffff:10.0.0.5]/x"));
	assert(!isSecureFetchUrl("https://[::ffff:127.0.0.1]/x"));
	// IPv4-mapped written as hex hextets (::ffff:0a00:0001 == ::ffff:10.0.0.1).
	assert(!isSecureFetchUrl("https://[::ffff:0a00:0001]/x"));
	// IPv6 loopback over https stays dev-only-safe but is harmless; over a
	// non-loopback scheme path it is permitted (loopback). A malformed bracketed
	// host fails closed.
	assert(!isSecureFetchUrl("https://[fe80::1]:443/x"));
	assert(!isSecureFetchUrl("https://[not-an-ipv6/x"));
}

unittest  // isSecureFetchUrl accepts a public/global-unicast IPv6 literal
{
	// Positive control: a public address (2606:4700::/.. Cloudflare) is allowed.
	assert(isSecureFetchUrl("https://[2606:4700:4700::1111]/x"));
	assert(isSecureFetchUrl("https://[2606:4700::1]/x"));
	// Explicit IPv6 loopback over http is still permitted for dev.
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
	// 127.0.0.0/8 is loopback in any encoding: https is always allowed, and so is
	// plaintext http (the dev-loopback exception), matching plain 127.0.0.1.
	assert(isSecureFetchUrl("https://2130706433/x")); // 127.0.0.1
	assert(isSecureFetchUrl("https://127.1/x")); // short form of 127.0.0.1
	assert(isSecureFetchUrl("https://0x7f000001/x")); // hex 127.0.0.1
	assert(isSecureFetchUrl("https://0177.0.0.1/x")); // octal-leading 127.0.0.1
}

unittest  // isSecureFetchUrl rejects numeric encodings of the cloud metadata address (SSRF)
{
	assert(!isSecureFetchUrl("https://0xa9fea9fe/latest/meta-data")); // 169.254.169.254
	assert(!isSecureFetchUrl("https://2852039166/latest/meta-data")); // 169.254.169.254
	assert(!isSecureFetchUrl("https://169.254.169.254/latest/meta-data"));
}

unittest  // isSecureFetchUrl rejects octal/hex encodings of RFC1918 ranges (SSRF)
{
	assert(!isSecureFetchUrl("https://0xa000005/x")); // 10.0.0.5
	assert(!isSecureFetchUrl("https://192.0xa8.0.1/x")); // 192.168.0.1 mixed
	assert(!isSecureFetchUrl("https://10.0/x")); // short form 10.0.0.0
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

unittest  // canonicalizeNumericIpv4 rejects non-numeric / malformed hosts (treated as hostnames)
{
	ubyte[4] oct;
	assert(!canonicalizeNumericIpv4("metadata.attacker.example", oct));
	assert(!canonicalizeNumericIpv4("example.com", oct));
	assert(!canonicalizeNumericIpv4("1.2.3.4.5", oct)); // too many parts
	assert(!canonicalizeNumericIpv4("256.0.0.1", oct)); // octet overflow in 4-part form
	assert(!canonicalizeNumericIpv4("0x", oct)); // empty hex
	assert(!canonicalizeNumericIpv4("1..2", oct)); // empty part
	assert(!canonicalizeNumericIpv4("0192.168.0.1", oct)); // 9 is not an octal digit
}

unittest  // canonicalizeNumericIpv4 decodes the documented inet_aton forms
{
	ubyte[4] oct;
	assert(canonicalizeNumericIpv4("2130706433", oct) && oct == cast(ubyte[4])[
		127, 0, 0, 1
	]);
	assert(canonicalizeNumericIpv4("0x7f000001", oct) && oct == cast(ubyte[4])[
		127, 0, 0, 1
	]);
	assert(canonicalizeNumericIpv4("0177.0.0.1", oct) && oct == cast(ubyte[4])[
		127, 0, 0, 1
	]);
	assert(canonicalizeNumericIpv4("127.1", oct) && oct == cast(ubyte[4])[
		127, 0, 0, 1
	]);
	assert(canonicalizeNumericIpv4("0xa9fea9fe", oct) && oct == cast(ubyte[4])[
		169, 254, 169, 254
	]);
	assert(canonicalizeNumericIpv4("2852039166", oct) && oct == cast(ubyte[4])[
		169, 254, 169, 254
	]);
	assert(canonicalizeNumericIpv4("8.8.8.8", oct) && oct == cast(ubyte[4])[
		8, 8, 8, 8
	]);
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

unittest  // isSecureFetchUrlResolved rejects what the lexical guard rejects (GET-path SSRF)
{
	// Plaintext http to a remote host, and IP literals in private/link-local
	// ranges, must be refused on the discovery GET paths just as on POST paths.
	assert(!isSecureFetchUrlResolved("http://as.example.com/.well-known/jwks"));
	assert(!isSecureFetchUrlResolved("https://169.254.169.254/latest/meta-data"));
	assert(!isSecureFetchUrlResolved("https://10.0.0.5/jwks"));
}

unittest  // isSecureFetchUrlResolved accepts lexically-safe loopback without resolving (dev)
{
	// Loopback hosts short-circuit DNS resolution, so these are network-independent.
	assert(isSecureFetchUrlResolved("https://127.0.0.1/jwks"));
	assert(isSecureFetchUrlResolved("http://127.0.0.1:8765/jwks"));
	assert(isSecureFetchUrlResolved("http://[::1]:9000/jwks"));
}

unittest  // fetchUrlHost extracts the authority host, dropping userinfo and path
{
	assert(fetchUrlHost("https://as.example.com/.well-known/x") == "as.example.com");
	assert(fetchUrlHost("https://user:pass@as.example.com:8443/token") == "as.example.com:8443");
	assert(fetchUrlHost("https://[2606:4700::1]:443/x") == "[2606:4700::1]:443");
	assert(fetchUrlHost("https://h.example?q=1") == "h.example");
	assert(fetchUrlHost("https://h.example#f") == "h.example");
	assert(fetchUrlHost("no-scheme") == "");
}

unittest  // isUnsafeResolvedAddress rejects private/link-local resolved IPv4 results
{
	assert(isUnsafeResolvedAddress("169.254.169.254"));
	assert(isUnsafeResolvedAddress("10.0.0.5"));
	assert(isUnsafeResolvedAddress("192.168.1.1"));
	assert(isUnsafeResolvedAddress("172.16.0.1"));
	assert(isUnsafeResolvedAddress("127.0.0.1"));
	assert(isUnsafeResolvedAddress("0.0.0.0"));
}

unittest  // isUnsafeResolvedAddress accepts public resolved IPv4 results
{
	assert(!isUnsafeResolvedAddress("8.8.8.8"));
	assert(!isUnsafeResolvedAddress("1.1.1.1"));
	assert(!isUnsafeResolvedAddress("93.184.216.34"));
}

unittest  // isUnsafeResolvedAddress rejects private/link-local resolved IPv6 results
{
	assert(isUnsafeResolvedAddress("fd00::1"));
	assert(isUnsafeResolvedAddress("fe80::1"));
	assert(isUnsafeResolvedAddress("::1"));
	assert(isUnsafeResolvedAddress("::ffff:169.254.169.254"));
	assert(isUnsafeResolvedAddress("fe80::1%en0")); // zone id stripped first
}

unittest  // isUnsafeResolvedAddress accepts a public global-unicast resolved IPv6 result
{
	assert(!isUnsafeResolvedAddress("2606:4700:4700::1111"));
	assert(!isUnsafeResolvedAddress("2001:4860:4860::8888"));
}

unittest  // isUnsafeResolvedAddress fails closed on empty / unparseable results
{
	assert(isUnsafeResolvedAddress(""));
	assert(isUnsafeResolvedAddress("not-an-address"));
}

unittest  // resolvedHostIsSafe short-circuits IP literals and loopback without resolving
{
	assert(resolvedHostIsSafe("[2606:4700::1]:443"));
	assert(resolvedHostIsSafe("localhost"));
	assert(resolvedHostIsSafe("127.0.0.1"));
	assert(resolvedHostIsSafe("8.8.8.8")); // numeric literal, vetted lexically
	assert(!resolvedHostIsSafe("")); // no host -> fail closed
}

unittest  // the resolver path flags a name whose returned address is internal
{
	// Exercise getAddressInfo + toAddrString + the classifier end to end. Any
	// address the local resolver maps the loopback name to must be classified as
	// unsafe, which is precisely what makes a hostname resolving to an internal
	// address get rejected (DNS-rebinding guard).
	import std.socket : getAddressInfo, AddressFamily, SocketException;

	try
	{
		auto infos = getAddressInfo("localhost");
		foreach (info; infos)
		{
			if (info.family != AddressFamily.INET && info.family != AddressFamily.INET6)
				continue;
			assert(isUnsafeResolvedAddress(info.address.toAddrString()));
		}
	}
	catch (SocketException)
	{
	}
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
		if ("expires_in" in j && j["expires_in"].type == Json.Type.int_)
			t.expiresIn = j["expires_in"].get!long;
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
string basicAuthHeader(string clientId, string clientSecret) @safe
{
	import std.base64 : Base64;

	const raw = clientId ~ ":" ~ clientSecret;
	return "Basic " ~ () @trusted {
		return cast(string) Base64.encode(cast(const(ubyte)[]) raw);
	}();
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

/// Extract a query-string parameter value from a URL (URL-decoded), or "".
package string extractQueryParam(string url, string key) @safe
{
	import std.string : indexOf;
	import std.uri : decodeComponent;

	const q = url.indexOf('?');
	auto query = (q < 0) ? url : url[q + 1 .. $];
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
	// Expected state set: the response MUST include a matching state.
	return responseState == expectedState;
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
