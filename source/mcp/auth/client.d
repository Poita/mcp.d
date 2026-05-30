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

    /// Discover authorization-server metadata for an issuer (RFC 8414).
    AuthorizationServerMetadata discoverAuthServer(string issuer) @safe
    {
        Json j;
        if (!tryGetJson(authorizationServerMetadataUrl(issuer), j))
            throw internalError("Could not discover authorization-server metadata: " ~ issuer);
        auto m = AuthorizationServerMetadata.fromJson(j);
        if (!m.supportsS256)
            throw internalError("Authorization server does not advertise PKCE S256 support");
        return m;
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
                client.clientId, resource, post ? client.clientSecret : "");
        return TokenSet.fromJson(postForm(as_.tokenEndpoint, form, client));
    }

    /// Obtain a token via the client-credentials grant (service-to-service).
    TokenSet clientCredentials(AuthorizationServerMetadata as_,
            RegisteredClient client, string scopeStr = "") @safe
    {
        const post = authMethod == TokenEndpointAuthMethod.clientSecretPost;
        auto form = buildClientCredentialsForm(client.clientId, scopeStr,
                resource, post ? client.clientSecret : "");
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
