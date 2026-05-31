module mcp.auth.oauth;

import std.typecons : Nullable;
import vibe.data.json : Json;

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

/// Build the authorization-server metadata URL for an issuer, per RFC 8414
/// (default `oauth-authorization-server` well-known suffix).
string authorizationServerMetadataUrl(string issuer) @safe
{
	import std.string : endsWith, indexOf;

	auto iss = issuer;
	if (iss.endsWith("/"))
		iss = iss[0 .. $ - 1];
	// RFC 8414: insert the well-known segment after the origin, before any path.
	auto schemeEnd = iss.indexOf("://");
	if (schemeEnd < 0)
		return iss ~ "/.well-known/oauth-authorization-server";
	const afterScheme = schemeEnd + 3;
	const slash = iss[afterScheme .. $].indexOf('/');
	if (slash < 0)
		return iss ~ "/.well-known/oauth-authorization-server";
	const origin = iss[0 .. afterScheme + slash];
	const path = iss[afterScheme + slash .. $];
	return origin ~ "/.well-known/oauth-authorization-server" ~ path;
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
/// URL with a lowercased scheme+host and no fragment.
string canonicalResourceUri(string mcpEndpoint) @safe
{
	import std.string : indexOf, toLower;

	auto frag = mcpEndpoint.indexOf('#');
	auto s = (frag < 0) ? mcpEndpoint : mcpEndpoint[0 .. frag];
	auto schemeEnd = s.indexOf("://");
	if (schemeEnd < 0)
		return s;
	const afterScheme = schemeEnd + 3;
	const slash = s[afterScheme .. $].indexOf('/');
	const hostEnd = (slash < 0) ? s.length : afterScheme + slash;
	return s[0 .. hostEnd].toLower ~ s[hostEnd .. $];
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

unittest  // AS metadata URL inserts well-known after origin, before path
{
	assert(authorizationServerMetadataUrl("https://auth.example.com")
			== "https://auth.example.com/.well-known/oauth-authorization-server");
	assert(authorizationServerMetadataUrl("https://auth.example.com/tenant1")
			== "https://auth.example.com/.well-known/oauth-authorization-server/tenant1");
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

unittest  // canonical resource URI lowercases scheme+host, drops fragment
{
	assert(canonicalResourceUri(
			"HTTPS://MCP.Example.com/Path#frag") == "https://mcp.example.com/Path");
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

/// Build the authorization-request URL for the PKCE auth-code flow.
string buildAuthorizationUrl(string authorizationEndpoint, string clientId,
		string redirectUri, string codeChallenge, string scopeStr, string resource, string state) @safe
{
	import std.string : indexOf;

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
	auto body_ = "grant_type=authorization_code";
	body_ ~= "&code=" ~ enc(code);
	body_ ~= "&redirect_uri=" ~ enc(redirectUri);
	body_ ~= "&code_verifier=" ~ enc(codeVerifier);
	body_ ~= "&client_id=" ~ enc(clientId);
	if (resource.length)
		body_ ~= "&resource=" ~ enc(resource);
	if (clientSecretForPost.length)
		body_ ~= "&client_secret=" ~ enc(clientSecretForPost);
	return body_;
}

/// Build the token-request body for the `client_credentials` grant.
package string buildClientCredentialsForm(string clientId, string scopeStr,
		string resource, string clientSecretForPost = "") @safe
{
	auto body_ = "grant_type=client_credentials";
	body_ ~= "&client_id=" ~ enc(clientId);
	if (scopeStr.length)
		body_ ~= "&scope=" ~ enc(scopeStr);
	if (resource.length)
		body_ ~= "&resource=" ~ enc(resource);
	if (clientSecretForPost.length)
		body_ ~= "&client_secret=" ~ enc(clientSecretForPost);
	return body_;
}

/// Build an RFC 8693 token-exchange request body (used by the cross-app /
/// identity-assertion grant to swap an IdP id_token for an ID-JAG assertion).
package string buildTokenExchangeForm(string subjectToken, string subjectTokenType,
		string requestedTokenType, string audience, string resource, string clientId) @safe
{
	auto body_ = "grant_type=" ~ enc("urn:ietf:params:oauth:grant-type:token-exchange");
	body_ ~= "&subject_token=" ~ enc(subjectToken);
	body_ ~= "&subject_token_type=" ~ enc(subjectTokenType);
	if (requestedTokenType.length)
		body_ ~= "&requested_token_type=" ~ enc(requestedTokenType);
	if (audience.length)
		body_ ~= "&audience=" ~ enc(audience);
	if (resource.length)
		body_ ~= "&resource=" ~ enc(resource);
	if (clientId.length)
		body_ ~= "&client_id=" ~ enc(clientId);
	return body_;
}

/// Build an RFC 7523 JWT-bearer grant request body (exchange an assertion JWT
/// for an access token).
package string buildJwtBearerForm(string assertion, string scopeStr,
		string resource, string clientId) @safe
{
	auto body_ = "grant_type=" ~ enc("urn:ietf:params:oauth:grant-type:jwt-bearer");
	body_ ~= "&assertion=" ~ enc(assertion);
	if (scopeStr.length)
		body_ ~= "&scope=" ~ enc(scopeStr);
	if (resource.length)
		body_ ~= "&resource=" ~ enc(resource);
	if (clientId.length)
		body_ ~= "&client_id=" ~ enc(clientId);
	return body_;
}

/// Build the token-request body for refreshing an access token. When
/// `clientSecretForPost` is non-empty it is appended (for `client_secret_post`
/// upstream authentication); leave it empty for public/PKCE clients or when the
/// secret is carried via the HTTP Basic `Authorization` header instead.
package string buildRefreshTokenForm(string refreshToken, string clientId,
		string resource, string clientSecretForPost = "") @safe
{
	auto body_ = "grant_type=refresh_token";
	body_ ~= "&refresh_token=" ~ enc(refreshToken);
	body_ ~= "&client_id=" ~ enc(clientId);
	if (resource.length)
		body_ ~= "&resource=" ~ enc(resource);
	if (clientSecretForPost.length)
		body_ ~= "&client_secret=" ~ enc(clientSecretForPost);
	return body_;
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
