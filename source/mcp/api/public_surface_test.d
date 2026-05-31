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
