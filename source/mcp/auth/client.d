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

    /// Exchange an authorization code for tokens (PKCE auth-code grant).
    TokenSet exchangeCode(AuthorizationServerMetadata as_,
            RegisteredClient client, string code, string codeVerifier) @safe
    {
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
        return buildAuthorizationUrl(as_.authorizationEndpoint, client.clientId,
                redirectUri, pkce.challenge, scopeStr, resource, state);
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
    string authorizeAndGetCode(string authzUrl) @safe
    {
        string code;
        () @trusted {
            requestHTTP(authzUrl, (scope HTTPClientRequest req) {
                req.method = HTTPMethod.GET;
            }, (scope HTTPClientResponse res) {
                const loc = res.headers.get("Location", "");
                code = extractQueryParam(loc, "code");
                res.dropBody();
            });
        }();
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
