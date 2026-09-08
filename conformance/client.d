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
import std.typecons : nullable;
import std.stdio : stderr;

import vibe.core.core : runTask, runEventLoop, exitEventLoop;
import vibe.data.json : Json;

import mcp;
import mcp.auth;

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

/// Whether the harness asked for the modern (2026-07-28) lifecycle. The runner
/// forwards the resolved spec version as `MCP_CONFORMANCE_PROTOCOL_VERSION`
/// (dated revisions through 2025-11-25 use the stateful initialize handshake,
/// 2026-07-28 is stateless with per-request `_meta`); `MCP_MODERN=1` forces it
/// for ad-hoc runs outside the harness.
private bool modernRequested() @trusted
{
	import std.process : environment;

	if (environment.get("MCP_MODERN", "").length > 0)
		return true;
	ProtocolVersion v;
	return tryParseVersion(environment.get("MCP_CONFORMANCE_PROTOCOL_VERSION", ""), v) && v
		.isModern;
}

private int runScenario(string url, string scenario) @safe
{
	if (scenario.startsWith("auth/"))
		return runAuthScenario(url, scenario);

	auto client = McpClient.http(url);
	client.capabilities.sampling = true;
	client.capabilities.elicitation = true;
	client.capabilities.roots = true;
	// The same handlers answer blocking server->client requests on a legacy
	// session and MRTR input requests on a modern one.
	client.onSampling = (CreateMessageRequest request) @safe => handleSampling(request);
	client.onElicitation = (ElicitParams params) @safe => handleElicitation(params);
	client.onListRoots = () @safe {
		ListRootsResult result;
		result.roots = [Root("file:///workspace", nullable("Workspace"))];
		return result;
	};

	if (modernRequested())
		return runModernScenario(client);

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
		auto tools = client.listTools().tools;
		Json schema2020;
		foreach (t; tools)
			if (t.name == "json_schema_2020_12_tool")
				schema2020 = t.inputSchema;
		foreach (t; tools)
		{
			// json-schema-2020-12-preservation: echo the focal tool's inputSchema
			// back verbatim; the focal tool itself is never called.
			if (t.name == "json_schema_2020_12_tool")
				continue;
			if (t.name == "json_schema_echo")
			{
				if (schema2020.type == Json.Type.object)
					tryCall(client, t.name, Json(["schema": schema2020]));
				continue;
			}
			client.callTool(t.name, defaultArgs(t));
		}
	}
	return 0;
}

/// The 2026-07-28 (stateless) flow: per-request `_meta` and standard headers on
/// every POST, MRTR for server input, no handshake. Exercises every listed tool,
/// resource, and prompt so the request-metadata, tools_call, MRTR, and header
/// scenarios all observe the traffic they check.
private int runModernScenario(McpClient client) @safe
{
	client.enableModern();
	auto tools = listToolsRetryingVersion(client);

	// http-custom-headers hands the exact tool calls to make via the scenario
	// context; their argument values are what the header mirroring is checked on.
	auto context = readContext();
	if ("toolCalls" in context && context["toolCalls"].type == Json.Type.array)
	{
		auto calls = context["toolCalls"];
		foreach (i; 0 .. calls.length)
		{
			auto c = calls[i];
			if (c.type != Json.Type.object || "name" !in c)
				continue;
			tryCall(client, c["name"].get!string, ("arguments" in c)
					? c["arguments"] : Json.emptyObject);
		}
		return 0;
	}

	// json-schema-2020-12-preservation: echo the focal tool's inputSchema back
	// verbatim through json_schema_echo; the focal tool itself is never called.
	Json schema2020;
	foreach (t; tools)
		if (t.name == "json_schema_2020_12_tool")
			schema2020 = t.inputSchema;
	foreach (t; tools)
	{
		if (t.name == "json_schema_2020_12_tool")
			continue;
		if (t.name == "json_schema_echo")
		{
			if (schema2020.type == Json.Type.object)
				tryCall(client, t.name, Json(["schema": schema2020]));
			continue;
		}
		tryCall(client, t.name, defaultArgs(t));
	}

	// http-standard-headers checks Mcp-Name on resources/read and prompts/get too.
	try
	{
		foreach (r; client.listResources().resources)
			try
				client.readResource(r.uri);
			catch (Exception)
			{
			}
	}
	catch (Exception)
	{
	}
	try
	{
		foreach (pr; client.listPrompts().prompts)
			try
				client.getPrompt(pr.name, Json.emptyObject);
			catch (Exception)
			{
			}
	}
	catch (Exception)
	{
	}
	return 0;
}

/// `tools/list`, retrying once after an UnsupportedProtocolVersionError. The
/// request-metadata scenario rejects the first request with -32022 to see the
/// client retry with a version from `error.data.supported`; 2026-07-28 is the
/// only modern version this client speaks, so the retry re-sends it.
private Tool[] listToolsRetryingVersion(McpClient client) @safe
{
	try
		return client.listTools().tools;
	catch (McpException e)
	{
		if (e.code != ErrorCode.unsupportedProtocolVersion)
			throw e;
		return client.listTools().tools;
	}
}

/// Call a tool, swallowing a JSON-RPC error: the scenarios judge the requests
/// the client made, and one tool's failure must not stop the others.
private void tryCall(McpClient client, string name, Json args) @safe
{
	try
		client.callTool(name, args);
	catch (Exception)
	{
	}
}

/// Build minimal arguments for a tool from its input schema: every required
/// property gets a placeholder of its declared type (successive integers for
/// numbers, `true` for booleans, "test" otherwise).
private Json defaultArgs(Tool tool) @safe
{
	Json args = Json.emptyObject;
	if (tool.inputSchema.type != Json.Type.object || "properties" !in tool.inputSchema)
		return args;
	auto props = tool.inputSchema["properties"];
	string[] required;
	if ("required" in tool.inputSchema && tool.inputSchema["required"].type == Json.Type.array)
	{
		auto req = tool.inputSchema["required"];
		foreach (i; 0 .. req.length)
			required ~= req[i].get!string;
	}
	int next = 2;
	foreach (name; required)
	{
		string type;
		if (props.type == Json.Type.object && name in props
				&& props[name].type == Json.Type.object && "type" in props[name]
				&& props[name]["type"].type == Json.Type.string)
			type = props[name]["type"].get!string;
		switch (type)
		{
		case "integer":
		case "number":
			args[name] = next++;
			break;
		case "boolean":
			args[name] = true;
			break;
		default:
			args[name] = "test";
		}
	}
	return args;
}

/// Answer a `sampling/createMessage` request with a canned assistant reply.
private CreateMessageResult handleSampling(CreateMessageRequest request) @safe
{
	CreateMessageResult result;
	result.role = "assistant";
	result.content = Content.makeText("Sampled response");
	result.model = "dlang-mcp-test-model";
	result.stopReason = "endTurn";
	return result;
}

/// Answer an `elicitation/create` request: accept, applying schema defaults.
private ElicitResult handleElicitation(ElicitParams params) @safe
{
	Json content = Json.emptyObject;
	auto schema = params.requestedSchema;
	if (schema.type == Json.Type.object && "properties" in schema)
	{
		auto props = schema["properties"];
		() @trusted {
			foreach (string key, Json prop; props)
				if ("default" in prop)
					content[key] = prop["default"];
		}();
	}
	return ElicitResult.accept(content);
}

/// Drive the OAuth 2.1 authorization flow for `auth/*` conformance scenarios:
/// 401 probe -> metadata discovery -> client identity (pre-registered, Client ID
/// Metadata Document, or Dynamic Client Registration) -> (PKCE
/// authorization-code or client-credentials) token acquisition -> handle any
/// re-challenge (scope step-up, or an authorization-server change) -> the MCP
/// requests with the bearer token.
private int runAuthScenario(string url, string scenario) @safe
{
	import std.algorithm : canFind;

	const modern = modernRequested();
	auto oauth = new OAuthClient();
	oauth.resource = canonicalResourceUri(url);
	oauth.redirectUri = "http://localhost:8765/callback";
	// The Client ID Metadata Document this client would host (SEP-991); used as
	// the client_id whenever the authorization server advertises support.
	oauth.clientIdMetadataUrl = "https://conformance-test.local/client-metadata.json";

	auto context = readContext();

	const www = oauth.probeUnauthorized(url, "", modern);
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

	bool issuerFromPrm;
	string issuer = oauth.resolveIssuer(url, issuerFromPrm, www);
	auto as_ = oauth.discoverAuthServer(issuer, issuerFromPrm);

	const w = parseWwwAuthenticate(www);
	auto scopeStr = selectScope(w.scope_, prm.scopesSupported.length
			? prm.scopesSupported : as_.scopesSupported);

	RegisteredClient client = obtainClient(oauth, as_, context, scopeStr);
	configureAuthMethod(oauth, as_, client, context);

	TokenSet tokens;
	if ("idp_id_token" in context && context["idp_id_token"].type == Json.Type.string)
	{
		// Cross-app access (identity-assertion grant): exchange the IdP id_token
		// for an ID-JAG assertion, then redeem it via the JWT-bearer grant.
		const idpToken = context["idp_id_token"].get!string;
		const idpEndpoint = ("idp_token_endpoint" in context) ? context["idp_token_endpoint"]
			.get!string : "";
		const idpClientId = ("idp_client_id" in context) ? context["idp_client_id"].get!string : "";
		auto jag = oauth.tokenExchange(idpEndpoint, idpToken,
				"urn:ietf:params:oauth:token-type:id_token",
				"urn:ietf:params:oauth:token-type:id-jag", issuer, idpClientId);
		const assertion = jag.accessToken.length ? jag.accessToken : idpToken;
		tokens = oauth.jwtBearerGrant(as_, client, assertion, scopeStr);
	}
	else if (scenario.canFind("client-credentials"))
		tokens = oauth.clientCredentials(as_, client, scopeStr);
	else
		tokens = authCodeFlow(oauth, as_, client, scopeStr);

	// Re-challenge loop. A gated read first, then the privileged tools/call; a
	// 401/403 on either is one of two things: the protected resource now names a
	// different authorization server (SEP-2352: credentials are bound to the
	// issuing server, so register afresh at the new one), or a step-up
	// challenge for a broader scope (re-authorize with the union of what was
	// granted and what is now required, so the prior grant is not dropped).
	foreach (attempt; 0 .. 3)
	{
		if (tokens.accessToken.length == 0)
			break;
		auto challenge = oauth.probeUnauthorized(url, tokens.accessToken, modern);
		if (challenge.length == 0)
			challenge = oauth.probeOperation(url, tokens.accessToken, modern, "test-tool");
		if (challenge.length == 0)
			break; // accepted

		bool fromPrm2;
		string issuer2 = issuer;
		try
			issuer2 = oauth.resolveIssuer(url, fromPrm2, challenge);
		catch (Exception)
		{
		}
		if (issuer2 != issuer)
		{
			issuer = issuer2;
			issuerFromPrm = fromPrm2;
			as_ = oauth.discoverAuthServer(issuer, issuerFromPrm);
			client = obtainClient(oauth, as_, Json.emptyObject, scopeStr);
			configureAuthMethod(oauth, as_, client, Json.emptyObject);
			tokens = authCodeFlow(oauth, as_, client, scopeStr);
			continue;
		}

		const newScope = parseWwwAuthenticate(challenge).scope_;
		if (newScope.length == 0)
			break;
		const merged = unionScopes(scopeStr, newScope);
		if (merged == scopeStr)
			break;
		scopeStr = merged;
		tokens = authCodeFlow(oauth, as_, client, scopeStr);
	}

	if (tokens.accessToken.length)
	{
		auto mcp = McpClient.http(url);
		mcp.setBearerToken(tokens.accessToken);
		try
		{
			if (modern)
				mcp.enableModern();
			else
				mcp.initialize();
			mcp.listTools();
			mcp.callTool("test-tool", Json.emptyObject);
		}
		catch (Exception)
		{
		}
	}
	return 0;
}

/// The client identity for `as_`, in the spec's priority order: pre-registered
/// credentials from the scenario context, then a Client ID Metadata Document
/// when the authorization server advertises support, then Dynamic Client
/// Registration.
private RegisteredClient obtainClient(OAuthClient oauth,
		AuthorizationServerMetadata as_, Json context, string scopeStr) @safe
{
	RegisteredClient client;
	if ("client_id" in context && context["client_id"].type == Json.Type.string)
	{
		client.clientId = context["client_id"].get!string;
		if ("client_secret" in context && context["client_secret"].type == Json.Type.string)
			client.clientSecret = context["client_secret"].get!string;
		return client;
	}
	if (oauth.registrationApproach(as_) == ClientRegistrationApproach.clientIdMetadataDocument)
		return oauth.clientIdMetadataClient(as_);
	return oauth.register(as_, "dlang-mcp-client", scopeStr);
}

/// Pick the token-endpoint auth method: private_key_jwt when the context
/// supplies a key, else a secret-based method when we hold a secret and the AS
/// supports one, else "none".
private void configureAuthMethod(OAuthClient oauth,
		AuthorizationServerMetadata as_, RegisteredClient client, Json context) @safe
{
	if ("private_key_pem" in context && context["private_key_pem"].type == Json.Type.string)
	{
		oauth.privateKeyPem = context["private_key_pem"].get!string;
		oauth.authMethod = TokenEndpointAuthMethod.privateKeyJwt;
	}
	else
		oauth.authMethod = chooseAuthMethod(as_, client.clientSecret.length > 0);
}

/// The space-separated union of two scope strings, keeping `granted`'s order
/// and appending the new scopes from `challenged`.
private string unionScopes(string granted, string challenged) @safe
{
	import std.algorithm : canFind;
	import std.array : join, split;

	auto merged = granted.split(" ");
	foreach (sc; challenged.split(" "))
		if (sc.length && !merged.canFind(sc))
			merged ~= sc;
	string[] nonEmpty;
	foreach (sc; merged)
		if (sc.length)
			nonEmpty ~= sc;
	return nonEmpty.join(" ");
}

/// Run the PKCE authorization-code flow and return the resulting tokens.
private TokenSet authCodeFlow(OAuthClient oauth, AuthorizationServerMetadata as_,
		RegisteredClient client, string scopeStr) @safe
{
	auto pkce = generatePkce();
	auto authzUrl = oauth.authorizationUrl(as_, client, pkce, scopeStr, "state-123");
	// The AS-aware overload validates the RFC 9207 `iss` parameter against the
	// recorded issuer (and the echoed `state`), refusing the code on a mismatch.
	const code = oauth.authorizeAndGetCode(as_, authzUrl, "state-123");
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
