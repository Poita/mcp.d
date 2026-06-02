/**
 * mcp.auth — opt-in authentication / authorization plumbing for the MCP SDK.
 *
 * The bare `import mcp;` does not dump the auth layer at the top level. Token
 * verifiers (JWT, introspection, static), the OAuth client / login helpers,
 * the resource-server helpers, and the OAuth proxy are brought in explicitly
 * with `import mcp.auth;`.
 */
module mcp.auth;

public import mcp.auth.csprng;
public import mcp.auth.oauth;
public import mcp.auth.client;
public import mcp.auth.login;
public import mcp.auth.resource_server;
public import mcp.auth.jwt;
public import mcp.auth.jwt_verifier;
public import mcp.auth.introspection_verifier;
public import mcp.auth.static_verifier;
public import mcp.auth.oauth_proxy;
public import mcp.auth.providers;
