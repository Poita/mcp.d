/// Tests that the public API is tiered.
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
	// symbol with plain `package` visibility lives in package `mcp.auth` and
	// therefore must NOT resolve here, even though the importing module is
	// itself under the `mcp` tree.
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

// The schema layer's `elicitationRequest!T` builder is the user-facing entry
// point for deriving an elicitation request from a flat struct, so it stays
// reachable from `import mcp;`.
unittest
{
	static assert(visibleFromMcp!"elicitationRequest");
}

// User-facing draft result/hint types referenced by lean-surface members
// (`McpServer.setListCacheHint(string, CacheHint)` and `McpClient.discover()`
// returning `DiscoverResult`) must be usable with `import mcp;` alone.
unittest
{
	static assert(visibleFromMcp!"DiscoverResult");
	static assert(visibleFromMcp!"CacheHint");
	static assert(visibleFromMcp!"CacheScope");
	static assert(visibleFromMcp!"RequestMeta");
}

// `mcp.protocol.modern` holds only user-facing result/hint types, so it is
// re-exported wholesale. Its cache-hint codec (`withCache`/`parseCacheHint`)
// therefore rides along on the top-level surface.
unittest
{
	static assert(visibleFromMcp!"withCache");
	static assert(visibleFromMcp!"parseCacheHint");
}

// A user with only `import mcp;` can construct a CacheHint to call
// setListCacheHint and name DiscoverResult to hold discover()'s return.
unittest
{
	import mcp;
	import core.time : seconds;

	CacheHint hint = CacheHint(5.seconds, CacheScope.private_);
	assert(hint.ttl == 5.seconds);
	assert(hint.cacheScope == CacheScope.private_);

	DiscoverResult r;
	r.protocolVersions = ["2025-11-25"];
	// Spec wire field is `supportedVersions` (draft DiscoverResult).
	assert(r.toJson()["supportedVersions"][0].get!string == "2025-11-25");
}

// Auth verifier internals are NOT dumped at the top level.
unittest
{
	static assert(!visibleFromMcp!"jwtVerifier");
	static assert(!visibleFromMcp!"introspectionVerifier");
	static assert(!visibleFromMcp!"verifyJws");
}

// OAuth-proxy plumbing is NOT dumped at the top level.
unittest
{
	static assert(!visibleFromMcp!"mountOAuthProxy");
	static assert(!visibleFromMcp!"buildClientCallbackRedirect");
}

// Transport / SSE helpers are NOT dumped at the top level.
unittest
{
	static assert(!visibleFromMcp!"sseStreamHeaders");
	static assert(!visibleFromMcp!"generateSessionId");
	static assert(!visibleFromMcp!"formatSseEvent");
}

// draft's internal transport helpers are NOT dumped at the top level.
unittest
{
	static assert(!visibleFromMcp!"encodeHeaderValue");
	static assert(!visibleFromMcp!"paramHeaders");
	static assert(!visibleFromMcp!"validateInputSchemaHeaders");
	static assert(!visibleFromMcp!"readRequestState");
}

// The MRTR request/response shapes live in `mcp.protocol.mrtr` and are
// transport plumbing, not top-level public surface: they stay out of
// `import mcp;`.
unittest
{
	static assert(!visibleFromMcp!"InputRequest");
	static assert(!visibleFromMcp!"InputRequiredResult");
	static assert(!visibleFromMcp!"InputResponse");
}

// Transport wiring is reachable behind the opt-in `mcp.transport` import.
unittest
{
	static assert(visibleFromTransport!"generateSessionId");
	static assert(visibleFromTransport!"mountOAuthProxy");
	static assert(visibleFromTransport!"sseStreamHeaders");
}

// The MRTR plumbing re-exported by `mcp.transport` (header encoding,
// param-header extraction, `_meta` validation, request-state parsing, and the
// `InputRequest` shape) is reachable behind the same opt-in import.
unittest
{
	static assert(visibleFromTransport!"encodeHeaderValue");
	static assert(visibleFromTransport!"paramHeaders");
	static assert(visibleFromTransport!"validateInputSchemaHeaders");
	static assert(visibleFromTransport!"readRequestState");
	static assert(visibleFromTransport!"InputRequest");
}

// The named server-side transport seam is reachable behind the opt-in
// `mcp.transport` import.
unittest
{
	static assert(visibleFromTransport!"ServerCore");
	static assert(visibleFromTransport!"ServerTransport");
}

// `ServerCore` / `ServerTransport` must NOT appear on the lean top-level surface.
unittest
{
	static assert(!visibleFromMcp!"ServerCore");
	static assert(!visibleFromMcp!"ServerTransport");
}

// Auth plumbing is reachable behind the opt-in `mcp.auth` import.
unittest
{
	static assert(visibleFromAuth!"jwtVerifier");
	static assert(visibleFromAuth!"introspectionVerifier");
}

// jwt_verifier internals are package-private: not reachable from another
// sub-package of the mcp tree. Only jwtVerifier / JwtVerifierConfig / TokenInfo
// are documented entry points.
unittest
{
	static assert(!reachableHere!"mcp.auth.jwt_verifier.verifyJws");
	static assert(!reachableHere!"mcp.auth.jwt_verifier.jwkToPem");
	static assert(!reachableHere!"mcp.auth.jwt_verifier.parseJwks");
	static assert(!reachableHere!"mcp.auth.jwt_verifier.base64UrlDecode");
	static assert(!reachableHere!"mcp.auth.jwt_verifier.validateClaims");
}

// The JWT verifier's key-source machinery is internal too.
unittest
{
	static assert(!reachableHere!"mcp.auth.jwt_verifier.Jwk");
	static assert(!reachableHere!"mcp.auth.jwt_verifier.KeySource");
	static assert(!reachableHere!"mcp.auth.jwt_verifier.JwksCache");
	static assert(!reachableHere!"mcp.auth.jwt_verifier.verifyToken");
}

// The documented JWT entry points stay public.
unittest
{
	static assert(reachableHere!"mcp.auth.jwt_verifier.jwtVerifier");
	static assert(reachableHere!"mcp.auth.jwt_verifier.JwtVerifierConfig");
}

// OAuth request-form builders + query-param extraction are internal helpers,
// not part of the documented public surface.
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
// visibility is `package` (package(mcp)), not `public`.
unittest
{
	import mcp.server.server : McpServer;

	static assert(__traits(getProtection, __traits(getMember, McpServer,
			"toolInputSchema")) == "package");
}
