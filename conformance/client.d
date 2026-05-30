/**
 * Conformance client target.
 *
 * The `@modelcontextprotocol/conformance` client harness launches this binary
 * with the test server URL appended to the command and the scenario in the
 * `MCP_CONFORMANCE_SCENARIO` environment variable. It connects, initializes,
 * and performs the scenario-appropriate operations.
 */
module conformance_client;

import std.algorithm : canFind, startsWith;
import std.process : environment;
import std.stdio : stderr;

import vibe.core.core : runTask, runEventLoop, exitEventLoop;
import vibe.data.json : Json;

import mcp;

int main(string[] args)
{
    string url;
    foreach (a; args[1 .. $])
        if (a.startsWith("http://") || a.startsWith("https://"))
            url = a;
    if (url.length == 0 && args.length > 1)
        url = args[$ - 1];

    const scenario = environment.get("MCP_CONFORMANCE_SCENARIO", "");

    int rc;
    runTask(() nothrow{
        scope (exit)
            exitEventLoop();
        try
            rc = runScenario(url, scenario);
        catch (Exception e)
        {
            try
                stderr.writeln("conformance-client error: ", e.msg);
            catch (Exception)
            {
            }
            rc = 1;
        }
    });
    runEventLoop();
    return rc;
}

private bool draftRequested() @trusted
{
    import std.process : environment;

    return environment.get("MCP_DRAFT", "").length > 0;
}

private int runScenario(string url, string scenario) @safe
{
    if (scenario.startsWith("auth/"))
        return runAuthScenario(url, scenario);

    auto client = new MCPClient(url);
    client.capabilities.sampling = true;
    client.capabilities.elicitation = true;
    client.capabilities.roots = true;

    // Draft mode (stateless): MCP_DRAFT=1 exercises server/discover + per-request
    // _meta + standard headers against a draft-capable server.
    if (draftRequested())
    {
        client.enableDraft();
        auto d = client.discover();
        () @trusted {
            import std.stdio : stderr;

            stderr.writefln("draft discover: versions=%s server=%s",
                    d.protocolVersions, d.serverInfo.name);
        }();
        auto tools = client.listTools();
        // Exercise a plain request/response tool (the streaming/sampling tools use
        // the older server-initiated mechanism, not draft MRTR).
        foreach (t; tools)
            if (t.name == "test_simple_text")
                client.callTool(t.name, Json.emptyObject);
        () @trusted { import std.stdio : stderr;

        stderr.writeln("draft flow OK"); }();
        return 0;
    }

    client.onSampling = (Json params) @safe => handleSampling(params);
    client.onElicitation = (Json params) @safe => handleElicitation(params);
    client.onListRoots = (Json params) @safe {
        Json roots = Json.emptyArray;
        roots ~= Json([
            "uri": Json("file:///workspace"),
            "name": Json("Workspace")
        ]);
        return Json(["roots": roots]);
    };

    client.initialize();

    // The `initialize` scenario only exercises the handshake. Every other
    // scenario drives behavior by having the client call a tool (which the test
    // server uses to trigger elicitation/sampling/progress, delivered either on
    // the POST response stream or on the standalone GET stream we open here).
    if (scenario != "initialize")
    {
        import core.time : msecs;
        import vibe.core.core : sleep;

        client.startServerStream();
        sleep(150.msecs); // let the GET stream connect before driving tools
        auto tools = client.listTools();
        foreach (t; tools)
            client.callTool(t.name, defaultArgs(t));
    }
    return 0;
}

/// Build minimal arguments for a tool from its input schema (empty unless the
/// schema declares required string properties, which get placeholder values).
private Json defaultArgs(Tool tool) @safe
{
    Json args = Json.emptyObject;
    if (tool.inputSchema.type == Json.Type.object && "properties" in tool.inputSchema)
    {
        auto props = tool.inputSchema["properties"];
        string[] required;
        if ("required" in tool.inputSchema && tool.inputSchema["required"].type == Json.Type.array)
        {
            auto req = tool.inputSchema["required"];
            foreach (i; 0 .. req.length)
                required ~= req[i].get!string;
        }
        foreach (name; required)
            args[name] = "test";
    }
    return args;
}

/// Answer a `sampling/createMessage` request with a canned assistant reply.
private Json handleSampling(Json params) @safe
{
    Json result = Json.emptyObject;
    result["role"] = "assistant";
    result["content"] = Json([
        "type": Json("text"),
        "text": Json("Sampled response")
    ]);
    result["model"] = "dlang-mcp-test-model";
    result["stopReason"] = "endTurn";
    return result;
}

/// Answer an `elicitation/create` request: accept, applying schema defaults.
private Json handleElicitation(Json params) @safe
{
    Json content = Json.emptyObject;
    if ("requestedSchema" in params)
    {
        auto schema = params["requestedSchema"];
        if (schema.type == Json.Type.object && "properties" in schema)
        {
            auto props = schema["properties"];
            () @trusted {
                foreach (string key, Json prop; props)
                    if ("default" in prop)
                        content[key] = prop["default"];
            }();
        }
    }
    Json result = Json.emptyObject;
    result["action"] = "accept";
    result["content"] = content;
    return result;
}

/// Drive the OAuth 2.1 authorization flow for `auth/*` conformance scenarios:
/// 401 probe -> metadata discovery -> Dynamic Client Registration -> (PKCE
/// authorization-code or client-credentials) token acquisition -> retry the MCP
/// request with the bearer token.
private int runAuthScenario(string url, string scenario) @safe
{
    import std.algorithm : canFind;

    auto oauth = new OAuthClient();
    oauth.resource = canonicalResourceUri(url);
    oauth.redirectUri = "http://localhost:8765/callback";

    auto context = readContext();

    const www = oauth.probeUnauthorized(url);
    ProtectedResourceMetadata prm;
    bool havePrm;
    try
    {
        prm = oauth.discoverProtectedResource(url, www);
        havePrm = true;
    }
    catch (Exception)
    {
    }

    // resource-mismatch: the PRM `resource` MUST cover the server we are talking
    // to (equal to, or a prefix of, the canonical server URL); otherwise refuse
    // to proceed with authorization (RFC 9728).
    const prmResource = canonicalResourceUri(prm.resource);
    if (havePrm && prm.resource.length && oauth.resource != prmResource
            && !oauth.resource.startsWith(prmResource))
    {
        () @trusted {
            import std.stdio : stderr;

            stderr.writeln("PRM resource mismatch — refusing to authorize");
        }();
        return 0;
    }

    const issuer = oauth.resolveIssuer(url, www);
    auto as_ = oauth.discoverAuthServer(issuer);

    const w = parseWwwAuthenticate(www);
    auto scopeStr = selectScope(w.scope_, prm.scopesSupported.length
            ? prm.scopesSupported : as_.scopesSupported);

    // Client identity: a pre-registered client supplied via the scenario context,
    // else Dynamic Client Registration.
    RegisteredClient client;
    if ("client_id" in context && context["client_id"].type == Json.Type.string)
    {
        client.clientId = context["client_id"].get!string;
        if ("client_secret" in context && context["client_secret"].type == Json.Type.string)
            client.clientSecret = context["client_secret"].get!string;
    }
    else
    {
        client = oauth.register(as_, "dlang-mcp-client", scopeStr);
    }

    // A private key in the context means private_key_jwt client authentication.
    if ("private_key_pem" in context && context["private_key_pem"].type == Json.Type.string)
    {
        oauth.privateKeyPem = context["private_key_pem"].get!string;
        oauth.authMethod = TokenEndpointAuthMethod.privateKeyJwt;
    }
    else
    {
        // Choose the token-endpoint auth method: if we hold a secret and the AS
        // supports a secret-based method, use it; otherwise prefer "none".
        oauth.authMethod = chooseAuthMethod(as_, client.clientSecret.length > 0);
    }

    TokenSet tokens;
    if ("idp_id_token" in context && context["idp_id_token"].type == Json.Type.string)
    {
        // Cross-app access (identity-assertion grant): exchange the IdP id_token
        // for an ID-JAG assertion, then redeem it via the JWT-bearer grant.
        const idpToken = context["idp_id_token"].get!string;
        const idpEndpoint = ("idp_token_endpoint" in context) ? context["idp_token_endpoint"].get!string
            : "";
        const idpClientId = ("idp_client_id" in context) ? context["idp_client_id"].get!string : "";
        auto jag = oauth.tokenExchange(idpEndpoint, idpToken, "urn:ietf:params:oauth:token-type:id_token",
                "urn:ietf:params:oauth:token-type:id-jag", issuer, idpClientId);
        const assertion = jag.accessToken.length ? jag.accessToken : idpToken;
        tokens = oauth.jwtBearerGrant(as_, client, assertion, scopeStr);
    }
    else if (scenario.canFind("client-credentials"))
        tokens = oauth.clientCredentials(as_, client, scopeStr);
    else
        tokens = authCodeFlow(oauth, as_, client, scopeStr);

    // Step-up: if the resource still challenges us for a broader scope, run the
    // authorization flow again with the escalated scope.
    foreach (attempt; 0 .. 3)
    {
        if (tokens.accessToken.length == 0)
            break;
        const challenge = oauth.probeOperation(url, tokens.accessToken);
        if (challenge.length == 0)
            break; // accepted
        const newScope = parseWwwAuthenticate(challenge).scope_;
        if (newScope.length == 0 || newScope == scopeStr)
            break;
        scopeStr = newScope;
        tokens = authCodeFlow(oauth, as_, client, scopeStr);
    }

    if (tokens.accessToken.length)
    {
        auto mcp = new MCPClient(url);
        mcp.setBearerToken(tokens.accessToken);
        try
            mcp.initialize();
        catch (Exception)
        {
        }
    }
    return 0;
}

/// Run the PKCE authorization-code flow and return the resulting tokens.
private TokenSet authCodeFlow(OAuthClient oauth, AuthorizationServerMetadata as_,
        RegisteredClient client, string scopeStr) @safe
{
    auto pkce = generatePkce();
    auto authzUrl = oauth.authorizationUrl(as_, client, pkce, scopeStr, "state-123");
    const code = oauth.authorizeAndGetCode(authzUrl);
    TokenSet tokens;
    if (code.length)
        tokens = oauth.exchangeCode(as_, client, code, pkce.verifier);
    return tokens;
}

/// Choose the token-endpoint auth method based on AS support and whether we hold
/// a client secret.
private TokenEndpointAuthMethod chooseAuthMethod(AuthorizationServerMetadata as_, bool haveSecret) @safe
{
    import std.algorithm : canFind;

    if (haveSecret)
    {
        if (as_.tokenEndpointAuthMethodsSupported.canFind("client_secret_basic"))
            return TokenEndpointAuthMethod.clientSecretBasic;
        if (as_.tokenEndpointAuthMethodsSupported.canFind("client_secret_post"))
            return TokenEndpointAuthMethod.clientSecretPost;
    }
    if (as_.tokenEndpointAuthMethodsSupported.canFind("client_secret_basic") && haveSecret)
        return TokenEndpointAuthMethod.clientSecretBasic;
    return TokenEndpointAuthMethod.none;
}

/// Parse the `MCP_CONFORMANCE_CONTEXT` environment variable (scenario context).
private Json readContext() @trusted
{
    import std.process : environment;
    import vibe.data.json : parseJsonString;

    const c = environment.get("MCP_CONFORMANCE_CONTEXT", "");
    if (c.length == 0)
        return Json.emptyObject;
    try
        return parseJsonString(c);
    catch (Exception)
        return Json.emptyObject;
}
