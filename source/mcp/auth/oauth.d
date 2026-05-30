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

/// Generate a PKCE pair from cryptographic randomness.
PkcePair generatePkce() @safe
{
    import std.random : rndGen, uniform;

    ubyte[32] buf;
    foreach (ref b; buf)
        b = cast(ubyte) uniform(0, 256);
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
        return m;
    }
}

private string strField(Json j, string key) @safe
{
    return (key in j && j[key].type == Json.Type.string) ? j[key].get!string : null;
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
string buildAuthCodeTokenForm(string code, string redirectUri, string codeVerifier,
        string clientId, string resource, string clientSecretForPost = "") @safe
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
string buildClientCredentialsForm(string clientId, string scopeStr,
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

/// Build the token-request body for refreshing an access token.
string buildRefreshTokenForm(string refreshToken, string clientId, string resource) @safe
{
    auto body_ = "grant_type=refresh_token";
    body_ ~= "&refresh_token=" ~ enc(refreshToken);
    body_ ~= "&client_id=" ~ enc(clientId);
    if (resource.length)
        body_ ~= "&resource=" ~ enc(resource);
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

unittest  // basic auth header is base64(client:secret)
{
    // base64("id:secret") = aWQ6c2VjcmV0
    assert(basicAuthHeader("id", "secret") == "Basic aWQ6c2VjcmV0");
}

/// Extract a query-string parameter value from a URL (URL-decoded), or "".
string extractQueryParam(string url, string key) @safe
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
