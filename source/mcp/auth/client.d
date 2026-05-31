module mcp.auth.client;

import vibe.data.json : Json, parseJsonString;
import vibe.http.client : requestHTTP, HTTPClientRequest, HTTPClientResponse;
import vibe.http.common : HTTPMethod;
import vibe.stream.operations : readAllUTF8;

import mcp.protocol.errors;
import mcp.auth.oauth;

@safe:

/// A production OAuth 2.1 client for MCP: drives protected-resource and
/// authorization-server metadata discovery (RFC 9728 / RFC 8414), Dynamic Client
/// Registration (RFC 7591), and the token endpoint (authorization-code + PKCE,
/// client-credentials, refresh) with RFC 8707 resource indicators.
///
/// The interactive authorization-code redirect (opening a browser / running a
/// loopback listener) is supplied by the host application via an
/// `authorizeCallback`; everything else is handled here.
final class OAuthClient
{
    /// The canonical resource indicator (the MCP server URL).
    string resource;
    /// The client's redirect URI for the auth-code flow.
    string redirectUri = "http://localhost:8765/callback";
    /// How to authenticate at the token endpoint.
    TokenEndpointAuthMethod authMethod = TokenEndpointAuthMethod.none;
    /// EC private key (PKCS#8 PEM) for `private_key_jwt` client assertions.
    string privateKeyPem;
    /// SEP-991: this client's OAuth Client ID Metadata Document URL — an
    /// HTTPS URL (with a path component) at which the client hosts its metadata
    /// document. When set and the authorization server advertises
    /// `client_id_metadata_document_supported`, this URL is used directly as the
    /// `client_id` (no Dynamic Client Registration needed).
    string clientIdMetadataUrl;

    /// Build the `client_assertion_type` + `client_assertion` form fields for
    /// `private_key_jwt` token-endpoint authentication (RFC 7523), or "".
    private string clientAssertionParams(string clientId, string audience) @safe
    {
        import std.uri : encodeComponent;
        import std.datetime.systime : Clock;
        import mcp.auth.jwt : makeClientAssertion, jwtBearerAssertionType;

        if (authMethod != TokenEndpointAuthMethod.privateKeyJwt || privateKeyPem.length == 0)
            return "";
        const now = () @trusted { return Clock.currTime().toUnixTime(); }();
        const jwt = makeClientAssertion(clientId, audience, privateKeyPem, now);
        return "&client_assertion_type=" ~ encodeComponent(
                jwtBearerAssertionType) ~ "&client_assertion=" ~ encodeComponent(jwt);
    }

    /// Discover the protected-resource metadata for an MCP endpoint, using the
    /// `resource_metadata` URL from a `WWW-Authenticate` header when present, else
    /// the RFC 9728 well-known URLs in order.
    ProtectedResourceMetadata discoverProtectedResource(string mcpEndpoint,
            string wwwAuthenticateHeader = "") @safe
    {
        string[] urls;
        if (wwwAuthenticateHeader.length)
        {
            const w = parseWwwAuthenticate(wwwAuthenticateHeader);
            if (w.resourceMetadata.length)
                urls ~= w.resourceMetadata;
        }
        urls ~= protectedResourceMetadataUrls(mcpEndpoint);

        foreach (u; urls)
        {
            Json j;
            if (tryGetJson(u, j))
                return ProtectedResourceMetadata.fromJson(j);
        }
        throw internalError("Could not discover protected-resource metadata");
    }

    /// Discover authorization-server metadata for an issuer, trying the RFC 8414
    /// and OpenID Connect Discovery well-known locations in order.
    AuthorizationServerMetadata discoverAuthServer(string issuer) @safe
    {
        foreach (u; authServerMetadataCandidates(issuer))
        {
            Json j;
            if (tryGetJson(u, j))
            {
                auto m = AuthorizationServerMetadata.fromJson(j);
                if (m.issuer.length == 0)
                    m.issuer = issuer;
                return m;
            }
        }
        // 2025-03-26 fallback: no metadata document — use default endpoints
        // derived from the issuer.
        import std.string : endsWith;

        auto base = issuer.endsWith("/") ? issuer[0 .. $ - 1] : issuer;
        AuthorizationServerMetadata m;
        m.issuer = issuer;
        m.authorizationEndpoint = base ~ "/authorize";
        m.tokenEndpoint = base ~ "/token";
        m.registrationEndpoint = base ~ "/register";
        return m;
    }

    /// Discover protected-resource metadata, falling back to treating the MCP
    /// server's origin as the issuer when no PRM document exists (the pre-RFC-9728
    /// 2025-03-26 behavior). Returns the issuer to use for AS discovery.
    string resolveIssuer(string mcpEndpoint, string wwwAuthenticateHeader = "") @safe
    {
        try
        {
            auto prm = discoverProtectedResource(mcpEndpoint, wwwAuthenticateHeader);
            if (prm.authorizationServers.length)
                return prm.authorizationServers[0];
        }
        catch (Exception)
        {
        }
        // Backcompat: no PRM -> the MCP server origin is the authorization server.
        return originOf(mcpEndpoint);
    }

    private static string originOf(string url) @safe
    {
        import std.string : indexOf;

        const schemeEnd = url.indexOf("://");
        if (schemeEnd < 0)
            return url;
        const afterScheme = schemeEnd + 3;
        const slash = url[afterScheme .. $].indexOf('/');
        return (slash < 0) ? url : url[0 .. afterScheme + slash];
    }

    /// Register a client dynamically (RFC 7591) at the AS registration endpoint.
    RegisteredClient register(AuthorizationServerMetadata as_, string clientName,
            string scopeStr = "") @safe
    {
        if (as_.registrationEndpoint.length == 0)
            throw internalError("Authorization server does not support Dynamic Client Registration");
        ClientRegistration reg;
        reg.redirectUris = [redirectUri];
        reg.clientName = clientName;
        reg.scope_ = scopeStr;
        reg.tokenEndpointAuthMethod = cast(string) authMethod;
        auto resp = postJson(as_.registrationEndpoint, reg.toJson());
        return RegisteredClient.fromJson(resp);
    }

    /// Select the client-registration approach for an authorization server,
    /// per the spec priority order ("Client Registration Approaches"):
    /// pre-registration, then Client ID Metadata Documents (SEP-991), then
    /// Dynamic Client Registration, then prompting the user. `havePreRegistered`
    /// indicates the caller already holds a `client_id` for this AS.
    ClientRegistrationApproach registrationApproach(AuthorizationServerMetadata as_,
            bool havePreRegistered = false) @safe
    {
        return selectClientRegistrationApproach(as_, havePreRegistered, clientIdMetadataUrl);
    }

    /// Use this client's configured OAuth Client ID Metadata Document URL
    /// (SEP-991) as the `client_id` for the authorization and token requests.
    /// The returned `RegisteredClient` carries the HTTPS-URL `client_id` and no
    /// secret, so it can be passed to `authorizationUrl`, `exchangeCode`,
    /// `refresh`, etc. exactly like a registered or pre-registered client.
    ///
    /// Throws when the authorization server does not advertise
    /// `client_id_metadata_document_supported`, or when no valid HTTPS-URL
    /// `client_id` (with a path component) is configured.
    RegisteredClient clientIdMetadataClient(AuthorizationServerMetadata as_) @safe
    {
        if (!as_.clientIdMetadataDocumentSupported)
            throw internalError(
                    "Authorization server does not support OAuth Client ID Metadata Documents");
        if (!isValidClientIdMetadataUrl(clientIdMetadataUrl))
            throw internalError("clientIdMetadataUrl must be an https URL with a path component");
        return RegisteredClient(clientIdMetadataUrl, "");
    }

    /// Build the OAuth Client ID Metadata Document (SEP-991) this client should
    /// host at its `clientIdMetadataUrl`. The document's `client_id` is the URL
    /// itself and `redirect_uris` is the configured `redirectUri`.
    ClientIdMetadataDocument clientIdMetadataDocument(string clientName = "", string scopeStr = "") @safe
    {
        ClientIdMetadataDocument d;
        d.clientId = clientIdMetadataUrl;
        d.clientName = clientName;
        d.redirectUris = [redirectUri];
        d.tokenEndpointAuthMethod = cast(string) authMethod;
        d.scope_ = scopeStr;
        return d;
    }

    /// Exchange an authorization code for tokens (PKCE auth-code grant).
    TokenSet exchangeCode(AuthorizationServerMetadata as_,
            RegisteredClient client, string code, string codeVerifier) @safe
    {
        requirePkceSupport(as_);
        const post = authMethod == TokenEndpointAuthMethod.clientSecretPost;
        auto form = buildAuthCodeTokenForm(code, redirectUri, codeVerifier,
                client.clientId, resource, post ? client.clientSecret : "") ~ clientAssertionParams(client.clientId,
                as_.issuer.length ? as_.issuer : as_.tokenEndpoint);
        return TokenSet.fromJson(postForm(as_.tokenEndpoint, form, client));
    }

    /// Obtain a token via the client-credentials grant (service-to-service).
    TokenSet clientCredentials(AuthorizationServerMetadata as_,
            RegisteredClient client, string scopeStr = "") @safe
    {
        const post = authMethod == TokenEndpointAuthMethod.clientSecretPost;
        auto form = buildClientCredentialsForm(client.clientId, scopeStr,
                resource, post ? client.clientSecret : "") ~ clientAssertionParams(client.clientId,
                as_.issuer.length ? as_.issuer : as_.tokenEndpoint);
        return TokenSet.fromJson(postForm(as_.tokenEndpoint, form, client));
    }

    /// RFC 8693 token exchange: swap a subject token (e.g. an IdP id_token) for
    /// a requested token type (e.g. an ID-JAG assertion) at `tokenEndpoint`.
    TokenSet tokenExchange(string tokenEndpoint, string subjectToken,
            string subjectTokenType, string requestedTokenType, string audience, string clientId) @safe
    {
        auto form = buildTokenExchangeForm(subjectToken, subjectTokenType,
                requestedTokenType, audience, resource, clientId);
        return TokenSet.fromJson(postForm(tokenEndpoint, form, RegisteredClient(clientId, "")));
    }

    /// RFC 7523 JWT-bearer grant: exchange an assertion JWT for an access token.
    TokenSet jwtBearerGrant(AuthorizationServerMetadata as_,
            RegisteredClient client, string assertion, string scopeStr) @safe
    {
        auto form = buildJwtBearerForm(assertion, scopeStr, resource, client.clientId);
        return TokenSet.fromJson(postForm(as_.tokenEndpoint, form, client));
    }

    /// Refresh an access token.
    TokenSet refresh(AuthorizationServerMetadata as_, RegisteredClient client, string refreshToken) @safe
    {
        auto form = buildRefreshTokenForm(refreshToken, client.clientId, resource);
        return TokenSet.fromJson(postForm(as_.tokenEndpoint, form, client));
    }

    /// Build the authorization-request URL the host should open (browser/loopback).
    string authorizationUrl(AuthorizationServerMetadata as_,
            RegisteredClient client, PkcePair pkce, string scopeStr, string state) @safe
    {
        requirePkceSupport(as_);
        return buildAuthorizationUrl(as_.authorizationEndpoint, client.clientId,
                redirectUri, pkce.challenge, scopeStr, resource, state);
    }

    /// Enforce the MCP authorization MUST: clients MUST verify PKCE support
    /// before proceeding with authorization. Per the spec ("Authorization Code
    /// Protection"), if `code_challenge_methods_supported` is absent (or does
    /// not advertise S256), the authorization server does not support PKCE and
    /// MCP clients MUST refuse to proceed. This guards the public authorization
    /// path (`authorizationUrl`/`exchangeCode`) so a host using the obvious API
    /// cannot silently fall back to a non-PKCE authorization-code flow.
    private static void requirePkceSupport(AuthorizationServerMetadata as_) @safe
    {
        if (!as_.supportsS256())
            throw invalidRequest("Authorization server does not advertise PKCE S256 support "
                    ~ "(code_challenge_methods_supported); MCP clients MUST refuse to proceed");
    }

    /// POST a minimal request to the MCP endpoint (optionally with a bearer
    /// token); if it returns 401, return the `WWW-Authenticate` header value
    /// (else empty). Used to trigger discovery and detect step-up challenges.
    string probeUnauthorized(string mcpEndpoint, string bearer = "") @safe
    {
        string www;
        () @trusted {
            try
            {
                requestHTTP(mcpEndpoint, (scope HTTPClientRequest req) {
                    req.method = HTTPMethod.POST;
                    req.contentType = "application/json";
                    req.headers["Accept"] = "application/json, text/event-stream";
                    if (bearer.length)
                        req.headers["Authorization"] = "Bearer " ~ bearer;
                    req.writeBody(cast(const(ubyte)[]) `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`);
                }, (scope HTTPClientResponse res) {
                    if (res.statusCode == 401 || res.statusCode == 403)
                        www = res.headers.get("WWW-Authenticate", "");
                    res.dropBody();
                });
            }
            catch (Exception)
            {
            }
        }();
        return www;
    }

    /// POST a `tools/list` request with a bearer token; if the server challenges
    /// with 401/403 (insufficient scope), return the `WWW-Authenticate` header.
    /// Used to detect step-up authorization requirements.
    string probeOperation(string mcpEndpoint, string bearer) @safe
    {
        string www;
        () @trusted {
            try
            {
                requestHTTP(mcpEndpoint, (scope HTTPClientRequest req) {
                    req.method = HTTPMethod.POST;
                    req.contentType = "application/json";
                    req.headers["Accept"] = "application/json, text/event-stream";
                    if (bearer.length)
                        req.headers["Authorization"] = "Bearer " ~ bearer;
                    req.writeBody(cast(const(ubyte)[]) `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"step-up","arguments":{}}}`);
                }, (scope HTTPClientResponse res) {
                    if (res.statusCode == 401 || res.statusCode == 403)
                        www = res.headers.get("WWW-Authenticate", "");
                    res.dropBody();
                });
            }
            catch (Exception)
            {
            }
        }();
        return www;
    }

    /// GET an authorization URL (without following redirects) and extract the
    /// `code` query parameter from the `Location` response header.
    ///
    /// When `expectedState` is non-empty, the `state` parameter returned in the
    /// redirect is verified against it (MCP authorization "Open Redirection":
    /// "MCP clients SHOULD use and verify state parameters in the authorization
    /// code flow and discard any results that do not include or have a mismatch
    /// with the original state"). The authorization code is NOT returned (empty
    /// string) when the returned state is missing or does not match. Passing an
    /// empty `expectedState` (the default) skips state verification.
    string authorizeAndGetCode(string authzUrl, string expectedState = "") @safe
    {
        string code, state;
        () @trusted {
            requestHTTP(authzUrl, (scope HTTPClientRequest req) {
                req.method = HTTPMethod.GET;
            }, (scope HTTPClientResponse res) {
                const loc = res.headers.get("Location", "");
                code = extractQueryParam(loc, "code");
                state = extractQueryParam(loc, "state");
                res.dropBody();
            });
        }();
        if (!validateAuthorizationResponseState(state, expectedState))
            return "";
        return code;
    }

    /// GET an authorization URL (without following redirects), extract the
    /// `code` from the redirect `Location` header, and validate the RFC 9207
    /// `iss` authorization-response parameter against the selected authorization
    /// server's recorded issuer (mix-up attack protection required by the MCP
    /// 2025-11-25 / draft authorization spec). Throws when `iss` is missing while
    /// `authorization_response_iss_parameter_supported` is true, or when it does
    /// not match the recorded issuer (simple string comparison, no
    /// normalization). The authorization code is NOT returned on rejection.
    /// When `expectedState` is non-empty, the redirect `state` parameter is also
    /// verified against it and the authorization code is discarded (a throw)
    /// when it is missing or mismatched, per the MCP "Open Redirection" guidance
    /// ("MCP clients SHOULD use and verify state parameters ... and discard any
    /// results that do not include or have a mismatch with the original state").
    /// Passing an empty `expectedState` (the default) skips state verification.
    string authorizeAndGetCode(AuthorizationServerMetadata as_, string authzUrl,
            string expectedState = "") @safe
    {
        string code, iss, state;
        () @trusted {
            requestHTTP(authzUrl, (scope HTTPClientRequest req) {
                req.method = HTTPMethod.GET;
            }, (scope HTTPClientResponse res) {
                const loc = res.headers.get("Location", "");
                code = extractQueryParam(loc, "code");
                iss = extractQueryParam(loc, "iss");
                state = extractQueryParam(loc, "state");
                res.dropBody();
            });
        }();
        if (!validateAuthorizationResponseIss(iss, as_.issuer,
                as_.authorizationResponseIssParameterSupported))
            throw invalidRequest(
                    "Authorization response failed RFC 9207 'iss' validation (possible mix-up attack)");
        if (!validateAuthorizationResponseState(state, expectedState))
            throw invalidRequest(
                    "Authorization response failed 'state' validation (missing or mismatched state)");
        return code;
    }

    // --- HTTP helpers --------------------------------------------------------

    private bool tryGetJson(string url, out Json result) @safe
    {
        bool ok;
        Json parsed;
        () @trusted {
            try
            {
                requestHTTP(url, (scope HTTPClientRequest req) {
                    req.method = HTTPMethod.GET;
                    req.headers["Accept"] = "application/json";
                }, (scope HTTPClientResponse res) {
                    auto body = res.bodyReader.readAllUTF8();
                    if (res.statusCode / 100 == 2 && body.length)
                    {
                        parsed = parseJsonString(body);
                        ok = true;
                    }
                });
            }
            catch (Exception)
                ok = false;
        }();
        result = parsed;
        return ok;
    }

    private Json postJson(string url, Json payload) @safe
    {
        Json result;
        () @trusted {
            requestHTTP(url, (scope HTTPClientRequest req) {
                req.method = HTTPMethod.POST;
                req.contentType = "application/json";
                req.headers["Accept"] = "application/json";
                req.writeBody(cast(const(ubyte)[]) payload.toString());
            }, (scope HTTPClientResponse res) {
                auto body = res.bodyReader.readAllUTF8();
                result = body.length ? parseJsonString(body) : Json.emptyObject;
            });
        }();
        return result;
    }

    private Json postForm(string url, string form, RegisteredClient client) @safe
    {
        Json result;
        const useBasic = authMethod == TokenEndpointAuthMethod.clientSecretBasic
            && client.clientSecret.length;
        const auth = useBasic ? basicAuthHeader(client.clientId, client.clientSecret) : "";
        () @trusted {
            requestHTTP(url, (scope HTTPClientRequest req) {
                req.method = HTTPMethod.POST;
                req.contentType = "application/x-www-form-urlencoded";
                req.headers["Accept"] = "application/json";
                if (auth.length)
                    req.headers["Authorization"] = auth;
                req.writeBody(cast(const(ubyte)[]) form);
            }, (scope HTTPClientResponse res) {
                auto body = res.bodyReader.readAllUTF8();
                result = body.length ? parseJsonString(body) : Json.emptyObject;
            });
        }();
        return result;
    }
}

unittest  // CIMD client uses the configured HTTPS-URL client_id when advertised
{
    auto c = new OAuthClient();
    c.clientIdMetadataUrl = "https://app.example.com/oauth/client.json";
    AuthorizationServerMetadata as_;
    as_.clientIdMetadataDocumentSupported = true;
    auto rc = c.clientIdMetadataClient(as_);
    assert(rc.clientId == "https://app.example.com/oauth/client.json");
    assert(rc.clientSecret.length == 0);
}

unittest  // CIMD client refuses when the AS does not advertise support
{
    import std.exception : assertThrown;

    auto c = new OAuthClient();
    c.clientIdMetadataUrl = "https://app.example.com/oauth/client.json";
    AuthorizationServerMetadata as_; // clientIdMetadataDocumentSupported == false
    assertThrown(c.clientIdMetadataClient(as_));
}

unittest  // CIMD client refuses an invalid (non-https / pathless) client_id URL
{
    import std.exception : assertThrown;

    auto c = new OAuthClient();
    c.clientIdMetadataUrl = "https://app.example.com"; // no path component
    AuthorizationServerMetadata as_;
    as_.clientIdMetadataDocumentSupported = true;
    assertThrown(c.clientIdMetadataClient(as_));
}

unittest  // registrationApproach prefers CIMD over DCR when advertised
{
    auto c = new OAuthClient();
    c.clientIdMetadataUrl = "https://app.example.com/oauth/client.json";
    AuthorizationServerMetadata as_;
    as_.clientIdMetadataDocumentSupported = true;
    as_.registrationEndpoint = "https://as.example.com/register";
    assert(c.registrationApproach(as_) == ClientRegistrationApproach.clientIdMetadataDocument);
    // Pre-registration still wins when the caller already has a client_id.
    assert(c.registrationApproach(as_, true) == ClientRegistrationApproach.preRegistered);
}

unittest  // the CIMD authorization URL carries the URL client_id verbatim
{
    auto c = new OAuthClient();
    c.clientIdMetadataUrl = "https://app.example.com/oauth/client.json";
    c.redirectUri = "http://localhost:8765/callback";
    AuthorizationServerMetadata as_;
    as_.clientIdMetadataDocumentSupported = true;
    as_.authorizationEndpoint = "https://as.example.com/authorize";
    as_.codeChallengeMethodsSupported = ["S256"];
    auto rc = c.clientIdMetadataClient(as_);
    auto pkce = makePkce(new ubyte[32]);
    auto url = c.authorizationUrl(as_, rc, pkce, "mcp:read", "state1");
    import std.algorithm : canFind;
    import std.uri : encodeComponent;

    assert(url.canFind("client_id=" ~ encodeComponent("https://app.example.com/oauth/client.json")));
}

unittest  // clientIdMetadataDocument builds a hostable document for the URL
{
    auto c = new OAuthClient();
    c.clientIdMetadataUrl = "https://app.example.com/oauth/client.json";
    c.redirectUri = "http://localhost:8765/callback";
    auto d = c.clientIdMetadataDocument("dlang-mcp", "mcp:read");
    assert(d.clientId == "https://app.example.com/oauth/client.json");
    assert(d.clientName == "dlang-mcp");
    assert(d.redirectUris == ["http://localhost:8765/callback"]);
    assert(d.tokenEndpointAuthMethod == "none");
    auto j = d.toJson();
    assert(j["client_id"].get!string == "https://app.example.com/oauth/client.json");
}

unittest  // authorizationUrl refuses when the AS advertises no PKCE support
{
    import std.exception : assertThrown;

    auto c = new OAuthClient();
    AuthorizationServerMetadata as_;
    as_.authorizationEndpoint = "https://as.example.com/authorize";
    // No code_challenge_methods_supported -> AS does not support PKCE.
    auto pkce = makePkce(new ubyte[32]);
    assertThrown(c.authorizationUrl(as_, RegisteredClient("cid", ""), pkce, "mcp:read", "st"));
}

unittest  // authorizationUrl refuses when only non-S256 PKCE methods are advertised
{
    import std.exception : assertThrown;

    auto c = new OAuthClient();
    AuthorizationServerMetadata as_;
    as_.authorizationEndpoint = "https://as.example.com/authorize";
    as_.codeChallengeMethodsSupported = ["plain"]; // S256 not offered
    auto pkce = makePkce(new ubyte[32]);
    assertThrown(c.authorizationUrl(as_, RegisteredClient("cid", ""), pkce, "mcp:read", "st"));
}

unittest  // authorizationUrl proceeds when the AS advertises S256 PKCE support
{
    import std.algorithm : canFind;

    auto c = new OAuthClient();
    AuthorizationServerMetadata as_;
    as_.authorizationEndpoint = "https://as.example.com/authorize";
    as_.codeChallengeMethodsSupported = ["S256"];
    auto pkce = makePkce(new ubyte[32]);
    auto url = c.authorizationUrl(as_, RegisteredClient("cid", ""), pkce, "mcp:read", "st");
    assert(url.canFind("code_challenge_method=S256"));
}

unittest  // exchangeCode refuses when the AS advertises no PKCE support
{
    import std.exception : assertThrown;

    auto c = new OAuthClient();
    AuthorizationServerMetadata as_;
    as_.tokenEndpoint = "https://as.example.com/token";
    // No code_challenge_methods_supported -> MUST refuse to proceed.
    assertThrown(c.exchangeCode(as_, RegisteredClient("cid", ""), "code", "verifier"));
}

unittest  // discoverAuthServer no-metadata fallback fails the PKCE guard closed
{
    import std.exception : assertThrown;

    // The 2025-03-26 fallback fabricates default endpoints but advertises no
    // PKCE methods, so the public authorization path MUST refuse to proceed.
    auto c = new OAuthClient();
    AuthorizationServerMetadata as_;
    as_.issuer = "https://as.example.com";
    as_.authorizationEndpoint = "https://as.example.com/authorize";
    // codeChallengeMethodsSupported left empty, mirroring the fallback.
    assert(!as_.supportsS256());
    auto pkce = makePkce(new ubyte[32]);
    assertThrown(c.authorizationUrl(as_, RegisteredClient("cid", ""), pkce, "", ""));
}
