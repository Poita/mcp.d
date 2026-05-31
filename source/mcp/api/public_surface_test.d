/// Tests that the public API is tiered (issue #301).
///
/// The bare `import mcp;` must expose a curated, stable surface: protocol
/// types, `McpServer` / `McpClient`, the UDA / reflection API, and the error
/// builders. Transport wiring (`mcp.transport`) and auth plumbing
/// (`mcp.auth`) must require an explicit opt-in submodule import and must NOT
/// be dumped at the top level.
module mcp.api.public_surface_test;

version (unittest)
{
	// Helper: does identifier `sym` resolve when only `mcp` is imported?
	private enum visibleFromMcp(string sym) = __traits(compiles, {
			import mcp;

			mixin("alias _ = " ~ sym ~ ";");
		});

	private enum visibleFromTransport(string sym) = __traits(compiles, {
			import mcp.transport;

			mixin("alias _ = " ~ sym ~ ";");
		});

	private enum visibleFromAuth(string sym) = __traits(compiles, {
			import mcp.auth;

			mixin("alias _ = " ~ sym ~ ";");
		});

	// Helper: is the fully-qualified module member `fqn` reachable by name from
	// this module (`mcp.api.public_surface_test`, in package `mcp.api`)? A
	// symbol demoted to plain `package` visibility lives in package `mcp.auth`
	// and therefore must NOT resolve here, even though the importing module is
	// itself under the `mcp` tree (issue #303).
	private enum reachableHere(string fqn) = __traits(compiles, {
			mixin("import " ~ moduleOf(fqn) ~ ";");
			mixin("alias _ = " ~ fqn ~ ";");
		});

	private string moduleOf(string fqn)
	{
		size_t idx = 0;
		foreach (i, c; fqn)
			if (c == '.')
				idx = i;
		return fqn[0 .. idx];
	}
}

// The curated top-level surface stays reachable from `import mcp;`.
unittest
{
	static assert(visibleFromMcp!"McpServer");
	static assert(visibleFromMcp!"McpClient");
}

// Protocol types and the error builders stay at the top level.
unittest
{
	static assert(visibleFromMcp!"Tool");
	static assert(visibleFromMcp!"McpException");
	static assert(visibleFromMcp!"ErrorCode");
	static assert(visibleFromMcp!"toErrorJson");
	static assert(visibleFromMcp!"makeErrorResponse");
}

// The UDA / reflection API stays at the top level.
unittest
{
	static assert(visibleFromMcp!"tool");
	static assert(visibleFromMcp!"resource");
	static assert(visibleFromMcp!"prompt");
	static assert(visibleFromMcp!"RequestContext");
}

// Auth verifier internals are NOT dumped at the top level (#301).
unittest
{
	static assert(!visibleFromMcp!"jwtVerifier");
	static assert(!visibleFromMcp!"introspectionVerifier");
	static assert(!visibleFromMcp!"verifyJws");
}

// OAuth-proxy plumbing is NOT dumped at the top level (#301).
unittest
{
	static assert(!visibleFromMcp!"mountOAuthProxy");
	static assert(!visibleFromMcp!"buildClientCallbackRedirect");
}

// Transport / SSE helpers are NOT dumped at the top level (#301).
unittest
{
	static assert(!visibleFromMcp!"sseStreamHeaders");
	static assert(!visibleFromMcp!"generateSessionId");
	static assert(!visibleFromMcp!"formatSseEvent");
}

// draft's internal transport helpers are NOT dumped at the top level (#301).
unittest
{
	static assert(!visibleFromMcp!"encodeHeaderValue");
	static assert(!visibleFromMcp!"paramHeaders");
	static assert(!visibleFromMcp!"validateInputSchemaHeaders");
	static assert(!visibleFromMcp!"readRequestState");
}

// Transport wiring is reachable behind the opt-in `mcp.transport` import.
unittest
{
	static assert(visibleFromTransport!"generateSessionId");
	static assert(visibleFromTransport!"mountOAuthProxy");
	static assert(visibleFromTransport!"sseStreamHeaders");
}

// Auth plumbing is reachable behind the opt-in `mcp.auth` import.
unittest
{
	static assert(visibleFromAuth!"jwtVerifier");
	static assert(visibleFromAuth!"introspectionVerifier");
}

// jwt_verifier internals are package-private: not reachable from another
// sub-package of the mcp tree (issue #303). Only jwtVerifier / JwtVerifierConfig
// / TokenInfo are documented entry points.
unittest
{
	static assert(!reachableHere!"mcp.auth.jwt_verifier.verifyJws");
	static assert(!reachableHere!"mcp.auth.jwt_verifier.jwkToPem");
	static assert(!reachableHere!"mcp.auth.jwt_verifier.parseJwks");
	static assert(!reachableHere!"mcp.auth.jwt_verifier.base64UrlDecode");
	static assert(!reachableHere!"mcp.auth.jwt_verifier.validateClaims");
}

// The JWT verifier's key-source machinery is internal too (issue #303).
unittest
{
	static assert(!reachableHere!"mcp.auth.jwt_verifier.Jwk");
	static assert(!reachableHere!"mcp.auth.jwt_verifier.KeySource");
	static assert(!reachableHere!"mcp.auth.jwt_verifier.JwksCache");
	static assert(!reachableHere!"mcp.auth.jwt_verifier.verifyToken");
}

// The documented JWT entry points stay public (issue #303).
unittest
{
	static assert(reachableHere!"mcp.auth.jwt_verifier.jwtVerifier");
	static assert(reachableHere!"mcp.auth.jwt_verifier.JwtVerifierConfig");
}

// OAuth request-form builders + query-param extraction are internal helpers,
// not part of the documented public surface (issue #303).
unittest
{
	static assert(!reachableHere!"mcp.auth.oauth.buildAuthCodeTokenForm");
	static assert(!reachableHere!"mcp.auth.oauth.buildClientCredentialsForm");
	static assert(!reachableHere!"mcp.auth.oauth.buildTokenExchangeForm");
	static assert(!reachableHere!"mcp.auth.oauth.buildJwtBearerForm");
	static assert(!reachableHere!"mcp.auth.oauth.buildRefreshTokenForm");
	static assert(!reachableHere!"mcp.auth.oauth.extractQueryParam");
}

// MCPServer.toolInputSchema is a core->transport hook, not external API: its
// visibility is `package` (package(mcp)), not `public` (issue #303).
unittest
{
	import mcp.server.server : McpServer;

	static assert(__traits(getProtection, __traits(getMember, McpServer,
			"toolInputSchema")) == "package");
}
