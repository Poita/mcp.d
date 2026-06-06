module mcp.auth.login;

/**
 * Turnkey interactive OAuth login for MCP clients.
 *
 * Wraps the lower-level `OAuthClient` primitives (`mcp.auth.client`) into a
 * single call -- `useOAuth(client, endpoint, opts)` -- that performs
 * protected-resource / authorization-server discovery, selects a
 * client-registration approach (pre-registered / Client ID Metadata Document /
 * Dynamic Client Registration), runs the OAuth 2.1 authorization-code + PKCE
 * flow by opening the system browser and capturing the redirect on a localhost
 * loopback HTTP listener, persists the resulting tokens through a pluggable
 * `TokenStore` (default: file-backed), and transparently refreshes the access
 * token on expiry before each request.
 *
 * Loopback redirect URIs (`http://localhost:<port>/callback`) are explicitly
 * permitted by the MCP authorization spec: "All redirect URIs MUST be either
 * `localhost` or use HTTPS." PKCE S256 is enforced by the underlying
 * `OAuthClient`, and the RFC 8707 `resource` parameter is sent on both the
 * authorization and token requests.
 */

import core.time : Duration, minutes;

import vibe.data.json : Json, parseJsonString;

import mcp.protocol.errors;
import mcp.auth.oauth;
import mcp.auth.client;
import mcp.client.client : McpClient;

@safe:

// ===========================================================================
// Token storage
// ===========================================================================

/// A persisted OAuth token set for a single resource (MCP server). `expiresAt`
/// is an absolute Unix timestamp (seconds) at which the access token expires; 0
/// means "no known expiry" (treated as never auto-refreshed on a timer).
struct StoredToken
{
	string accessToken;
	string tokenType = "Bearer";
	long expiresAt; // absolute unix seconds; 0 == unknown / no expiry
	string refreshToken;
	string scope_;
	string resource;
	/// The OAuth `client_id` used to obtain this token (pre-registered, CIMD, or
	/// DCR-issued). Persisted so a later refresh can authenticate at the token
	/// endpoint even when no `client_id` was statically configured.
	string clientId;

	/// Whether this record holds a usable access token.
	bool hasToken() const @safe pure nothrow @nogc
	{
		return accessToken.length > 0;
	}

	/// Build a `StoredToken` from a freshly issued `TokenSet`, computing the
	/// absolute expiry from `now + expiresIn` (only when `expiresIn` is
	/// positive). A `TokenSet` from a refresh that omits `refresh_token` keeps
	/// `prevRefresh` (RFC 6749 allows the AS to reissue or retain it).
	static StoredToken fromTokenSet(TokenSet ts, string resource, long now, string prevRefresh = "") @safe pure nothrow
	{
		StoredToken s;
		s.accessToken = ts.accessToken;
		s.tokenType = ts.tokenType.length ? ts.tokenType : "Bearer";
		s.expiresAt = ts.expiresIn > 0 ? now + ts.expiresIn : 0;
		s.refreshToken = ts.refreshToken.length ? ts.refreshToken : prevRefresh;
		s.scope_ = ts.scope_;
		s.resource = resource;
		return s;
	}

	Json toJson() const @safe
	{
		auto j = Json.emptyObject;
		j["access_token"] = accessToken;
		j["token_type"] = tokenType;
		j["expires_at"] = Json(expiresAt);
		j["refresh_token"] = refreshToken;
		j["scope"] = scope_;
		j["resource"] = resource;
		j["client_id"] = clientId;
		return j;
	}

	static StoredToken fromJson(Json j) @safe
	{
		StoredToken s;
		if (j.type != Json.Type.object)
			return s;
		if (auto p = "access_token" in j)
			s.accessToken = p.type == Json.Type.string ? p.get!string : "";
		if (auto p = "token_type" in j)
			s.tokenType = p.type == Json.Type.string ? p.get!string : "Bearer";
		if (auto p = "expires_at" in j)
			s.expiresAt = p.type == Json.Type.int_ ? p.get!long : 0;
		if (auto p = "refresh_token" in j)
			s.refreshToken = p.type == Json.Type.string ? p.get!string : "";
		if (auto p = "scope" in j)
			s.scope_ = p.type == Json.Type.string ? p.get!string : "";
		if (auto p = "resource" in j)
			s.resource = p.type == Json.Type.string ? p.get!string : "";
		if (auto p = "client_id" in j)
			s.clientId = p.type == Json.Type.string ? p.get!string : "";
		return s;
	}
}

/// Pluggable persistence for OAuth tokens, keyed by the canonical resource
/// (MCP server) URI. Implementations may encrypt at rest; the default
/// `FileTokenStore` documents an encryption hook.
interface TokenStore
{
	/// Load the stored token for `resource`, or a default-constructed
	/// `StoredToken` (`hasToken == false`) when none is stored.
	StoredToken load(string resource) @safe;

	/// Persist `token` for `resource`, replacing any previous value.
	void save(string resource, StoredToken token) @safe;
}

/// An in-memory `TokenStore` (no persistence across processes). Useful for
/// tests and ephemeral sessions.
final class MemoryTokenStore : TokenStore
{
	private StoredToken[string] tokens_;

	override StoredToken load(string resource) @safe
	{
		if (auto p = resource in tokens_)
			return *p;
		return StoredToken.init;
	}

	override void save(string resource, StoredToken token) @safe
	{
		tokens_[resource] = token;
	}
}

/// A file-backed `TokenStore`. Tokens for all resources are stored as a single
/// JSON object (`{ "<resource>": { ... } }`) at `path`.
///
/// Encryption hook: subclass and override `serialize`/`deserialize` to encrypt
/// the JSON blob at rest (e.g. with a key from the OS keychain). The plaintext
/// implementation writes the file with owner-only (`0600`) permissions on
/// POSIX.
class FileTokenStore : TokenStore
{
	/// The on-disk path of the token file.
	string path;

	this(string path) @safe
	{
		this.path = path;
	}

	/// Serialize the full token map to bytes for writing. Override to encrypt.
	protected const(ubyte)[] serialize(Json all) @safe
	{
		return cast(const(ubyte)[]) all.toString();
	}

	/// Deserialize bytes read from disk into the token map. Override to decrypt.
	protected Json deserialize(const(ubyte)[] data) @safe
	{
		if (data.length == 0)
			return Json.emptyObject;
		return parseJsonString(cast(string) data.idup);
	}

	private Json readAll() @safe
	{
		import std.file : exists, read;

		if (!path.length || !path.exists)
			return Json.emptyObject;
		try
		{
			auto data = () @trusted { return cast(const(ubyte)[]) read(path); }();
			auto j = deserialize(data);
			return j.type == Json.Type.object ? j : Json.emptyObject;
		}
		catch (Exception)
			return Json.emptyObject;
	}

	override StoredToken load(string resource) @safe
	{
		auto all = readAll();
		if (auto p = resource in all)
			return StoredToken.fromJson(*p);
		return StoredToken.init;
	}

	override void save(string resource, StoredToken token) @safe
	{
		import std.file : mkdirRecurse;
		import std.path : dirName;

		auto dir = dirName(path);
		if (dir.length && dir != ".")
		{
			try
				() @trusted { mkdirRecurse(dir); }();
			catch (Exception)
			{
			}
			restrictDirPermissions(dir);
		}
		auto all = readAll();
		all[resource] = token.toJson();
		auto bytes = serialize(all);
		writeSecretFile(bytes);
	}

	/// Persist `bytes` to `path` such that the plaintext secrets they contain are
	/// never present in a group/world-readable file. On POSIX the bytes are
	/// written to a fresh temp file in the same directory, created
	/// `O_CREAT|O_EXCL` with mode `0600`, then atomically `rename`d over the
	/// target; because the secret bytes only ever live in the private temp file
	/// (and rename preserves its `0600` mode), a pre-existing loose-permission
	/// target is never written to before being tightened. Falls back to a plain
	/// write on platforms without POSIX permissions.
	private void writeSecretFile(const(ubyte)[] bytes) @safe
	{
		import std.file : write;

		version (Posix)
		{
			import core.sys.posix.fcntl : open, O_CREAT, O_EXCL, O_WRONLY;
			import core.sys.posix.unistd : close, getpid;
			import core.sys.posix.sys.stat : S_IRUSR, S_IWUSR;
			import core.stdc.stdio : rename;
			import std.digest : toHexString;
			import std.file : remove;
			import std.string : toStringz;
			import std.conv : to;
			import mcp.auth.csprng : cryptoRandomFill;

			if (!path.length)
				return;

			// A unique private temp name in the same directory so the atomic
			// `rename` stays on one filesystem and `O_CREAT|O_EXCL` cannot collide
			// with a concurrent writer or a stale leftover.  The suffix comes
			// from the OS CSPRNG so that concurrent writers cannot predict and
			// pre-create the temp path to win the O_EXCL race.
			ubyte[8] rndBuf;
			cryptoRandomFill(rndBuf[]);
			auto tmp = path ~ ".tmp-" ~ (() @trusted => getpid()
					.to!string)() ~ "-" ~ rndBuf[].toHexString;

			bool wrote = () @trusted {
				int fd = open(tmp.toStringz, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
				if (fd < 0)
					return false;
				scope (exit)
					close(fd);
				import core.sys.posix.unistd : write_ = write;

				size_t off;
				while (off < bytes.length)
				{
					auto n = write_(fd, bytes.ptr + off, bytes.length - off);
					if (n <= 0)
						return false;
					off += cast(size_t) n;
				}
				return true;
			}();

			void discardTmp() @safe nothrow
			{
				() @trusted {
					try
						remove(tmp);
					catch (Exception)
					{
					}
				}();
			}

			if (wrote && ()@trusted {
					return rename(tmp.toStringz, path.toStringz) == 0;
				}())
				return;

			// The atomic path failed (could not create/write the temp file, or the
			// rename failed). Clean up any temp and fall back to an in-place write.
			// Tighten any pre-existing file to owner-only BEFORE writing secrets so
			// they are not exposed through a loose-permission file, and reassert
			// afterwards in case the file had to be created by `write`.
			discardTmp();
			restrictPermissions();
			() @trusted { write(path, bytes); }();
			restrictPermissions();
			return;
		}
		else
		{
			() @trusted { write(path, bytes); }();
			restrictPermissions();
		}
	}

	/// Restrict the token file to owner-only access (POSIX `0600`). No-op on
	/// platforms without POSIX permissions.
	private void restrictPermissions() @safe
	{
		version (Posix)
		{
			import std.file : setAttributes, exists;
			import core.sys.posix.sys.stat : S_IRUSR, S_IWUSR;

			if (path.exists)
			{
				try
					() @trusted { setAttributes(path, S_IRUSR | S_IWUSR); }();
				catch (Exception)
				{
				}
			}
		}
	}

	/// Restrict the token file's parent directory to owner-only access (POSIX
	/// `0700`), so the directory holding the plaintext token file is not
	/// group/other-traversable. No-op on platforms without POSIX permissions.
	private static void restrictDirPermissions(string dir) @safe
	{
		version (Posix)
		{
			import std.file : setAttributes, exists;
			import core.sys.posix.sys.stat : S_IRWXU;

			if (dir.length && dir.exists)
			{
				try
					() @trusted { setAttributes(dir, S_IRWXU); }();
				catch (Exception)
				{
				}
			}
		}
	}
}

// ===========================================================================
// Refresh-on-expiry helpers
// ===========================================================================

/// The default clock skew (seconds) treated as "about to expire": a token is
/// refreshed this many seconds *before* its nominal expiry to avoid using a
/// token that expires mid-flight.
enum long defaultExpirySkewSeconds = 30;

/// Whether the stored access token must be refreshed before use at time `now`
/// (Unix seconds). A token with `expiresAt == 0` (unknown expiry) is never
/// considered expired here. A record with no access token always needs
/// (re)acquisition and returns true.
bool needsRefresh(const StoredToken token, long now, long skew = defaultExpirySkewSeconds) @safe pure nothrow @nogc
{
	if (!token.hasToken)
		return true;
	if (token.expiresAt == 0)
		return false;
	return now + skew >= token.expiresAt;
}

// ===========================================================================
// Loopback redirect capture
// ===========================================================================

/// The outcome of parsing a loopback redirect request target: the captured
/// authorization `code` and `state`, or an `error` (the OAuth `error`
/// parameter) when the authorization server reported a failure.
struct LoopbackCapture
{
	string code;
	string state;
	/// RFC 9207 `iss` authorization-response parameter (empty when absent).
	string iss;
	string error;
	string errorDescription;

	/// Whether a usable authorization code was captured.
	bool ok() const @safe pure nothrow @nogc
	{
		return code.length > 0 && error.length == 0;
	}
}

/// Parse the path+query of an inbound loopback HTTP request (e.g.
/// `/callback?code=abc&state=xyz`) and extract the OAuth authorization response
/// parameters. When `expectedState` is non-empty, a missing or mismatched
/// `state` clears the captured `code` and records an error (MCP "Open
/// Redirection": clients SHOULD verify the state parameter and discard
/// mismatched results).
/// Extract just the path component of an inbound HTTP request target, dropping
/// any `?query` and `#fragment`. An empty target yields an empty path.
string requestTargetPath(string requestTarget) @safe pure nothrow
{
	import std.string : indexOf;

	auto q = requestTarget.indexOf('?');
	auto path = q >= 0 ? requestTarget[0 .. q] : requestTarget;
	auto h = path.indexOf('#');
	if (h >= 0)
		path = path[0 .. h];
	return path;
}

LoopbackCapture parseLoopbackCallback(string requestTarget, string expectedState = "") @safe
{
	LoopbackCapture c;
	c.code = extractQueryParam(requestTarget, "code");
	c.state = extractQueryParam(requestTarget, "state");
	c.iss = extractQueryParam(requestTarget, "iss");
	c.error = extractQueryParam(requestTarget, "error");
	c.errorDescription = extractQueryParam(requestTarget, "error_description");

	if (expectedState.length)
	{
		if (!validateAuthorizationResponseState(c.state, expectedState))
		{
			c.code = "";
			if (c.error.length == 0)
			{
				c.error = "state_mismatch";
				c.errorDescription = "authorization response state missing or mismatched";
			}
		}
	}
	return c;
}

/// The HTML body shown in the user's browser after the loopback listener
/// captures the redirect, so the user knows to return to the application.
string loopbackResponseHtml(bool success) @safe pure nothrow
{
	return success ? "<!doctype html><html><body><h2>Authorization complete</h2>"
		~ "<p>You may close this window and return to the application.</p></body></html>"
		: "<!doctype html><html><body><h2>Authorization failed</h2>"
		~ "<p>You may close this window and return to the application.</p></body></html>";
}

// ===========================================================================
// Configuration
// ===========================================================================

/// Configuration for `useOAuth`: the requested scopes, the loopback callback
/// port (0 = an ephemeral OS-assigned loopback port), the token store
/// (defaults to a `FileTokenStore` under the user's config dir), and the
/// client-registration inputs.
struct OAuthLogin
{
	/// OAuth scopes to request (space-joined into the `scope` parameter).
	string[] scopes;
	/// Loopback listener port for the redirect. 0 selects an ephemeral port.
	ushort callbackPort = 0;
	/// The loopback path the authorization server redirects to.
	string callbackPath = "/callback";
	/// Pluggable token persistence. Null => a default `FileTokenStore`.
	TokenStore store;
	/// The human-readable client name used for Dynamic Client Registration.
	string clientName = "dlang-mcp-client";
	/// A pre-registered `client_id` (skips DCR/CIMD when set).
	string clientId;
	/// A pre-registered `client_secret` (for confidential clients).
	string clientSecret;
	/// SEP-991 OAuth Client ID Metadata Document URL (used as `client_id`
	/// when the AS advertises `client_id_metadata_document_supported`).
	string clientIdMetadataUrl;
	/// How to authenticate at the token endpoint.
	TokenEndpointAuthMethod authMethod = TokenEndpointAuthMethod.none;
	/// Maximum time to wait for the authorization-server redirect to arrive on
	/// the loopback listener before aborting the interactive flow. Bounds the
	/// wait so an abandoned browser or an absent redirect cannot block the
	/// caller indefinitely.
	Duration callbackTimeout = 5.minutes;
	/// Opener for the system browser. Null => the platform default opener.
	/// Supplied explicitly in tests to avoid launching a browser.
	void delegate(string url) @safe openBrowser;

	/// The scopes joined into a single space-delimited OAuth `scope` string.
	string scopeString() const @safe pure nothrow
	{
		string s;
		foreach (i, sc; scopes)
			s ~= (i ? " " : "") ~ sc;
		return s;
	}
}

/// The default loopback redirect URI for a given port and path.
string loopbackRedirectUri(ushort port, string path = "/callback") @safe pure
{
	import std.conv : to;

	auto p = path.length ? path : "/callback";
	if (p[0] != '/')
		p = "/" ~ p;
	return "http://localhost:" ~ port.to!string ~ p;
}

/// The default token-store path under the user's config directory:
/// `$XDG_CONFIG_HOME/dlang-mcp/tokens.json` (or `~/.config/...`), falling back
/// to `./.dlang-mcp-tokens.json` when no home directory is known.
string defaultTokenStorePath() @safe
{
	import std.process : environment;
	import std.path : buildPath;

	string base;
	try
	{
		base = environment.get("XDG_CONFIG_HOME", "");
		if (base.length == 0)
		{
			auto home = environment.get("HOME", "");
			if (home.length)
				base = buildPath(home, ".config");
		}
	}
	catch (Exception)
	{
	}
	if (base.length == 0)
		return ".dlang-mcp-tokens.json";
	return buildPath(base, "dlang-mcp", "tokens.json");
}

/// Generate a random `state` value (base64url, 16 bytes of randomness) for the
/// authorization request (MCP "Open Redirection" mitigation). The bytes come
/// from the OS CSPRNG -- `state` is the CSRF / mix-up defense and MUST be
/// unpredictable. Throws `CsprngException` if the OS CSPRNG is unavailable.
string generateLoginState() @safe
{
	import mcp.auth.csprng : cryptoRandomFill;

	ubyte[16] buf;
	cryptoRandomFill(buf[]);
	return base64UrlNoPad(buf[]);
}

// ===========================================================================
// Session: bearer + auto-refresh
// ===========================================================================

/// A live OAuth session bound to one MCP server. Holds the discovered
/// authorization-server metadata and the registered client so it can refresh
/// the access token automatically when it nears expiry. Created by `useOAuth`;
/// also constructible directly for advanced/test use.
final class OAuthSession
{
	private OAuthClient oauth_;
	private AuthorizationServerMetadata as_;
	private RegisteredClient client_;
	private TokenStore store_;
	private string resource_;
	private StoredToken token_;
	private long skew_ = defaultExpirySkewSeconds;
	// The refresh-token grant. Defaults to the live `OAuthClient.refresh`;
	// overridable (see the secondary constructor) so the refresh-on-expiry path
	// is unit-testable without network access.
	private TokenSet delegate(string refreshToken) @safe refreshFn_;

	/// `oauth` must already carry the canonical `resource`. `token` is the
	/// initial (possibly empty) stored token for `resource`.
	this(OAuthClient oauth, AuthorizationServerMetadata as_,
			RegisteredClient client, TokenStore store, string resource, StoredToken token) @safe
	{
		this.oauth_ = oauth;
		this.as_ = as_;
		this.client_ = client;
		this.store_ = store;
		this.resource_ = resource;
		this.token_ = token;
		this.refreshFn_ = (string rt) @safe => oauth.refresh(as_, client, rt);
	}

	/// Test/advanced constructor: inject a refresh function (the
	/// refresh-token-grant call) directly, bypassing the live HTTP client.
	this(string resource, StoredToken token, TokenStore store,
			TokenSet delegate(string refreshToken) @safe refreshFn) @safe
	{
		this.resource_ = resource;
		this.token_ = token;
		this.store_ = store;
		this.refreshFn_ = refreshFn;
	}

	/// The current stored token (for inspection / persistence).
	StoredToken token() const @safe nothrow
	{
		return token_;
	}

	/// Return a valid bearer access token for use at `now` (Unix seconds),
	/// refreshing via the refresh-token grant first when the current token has
	/// expired (or is within the skew window). The refreshed token is persisted
	/// through the `TokenStore`. Throws when no valid token can be produced
	/// (e.g. expired with no refresh token).
	string bearerForRequest(long now) @safe
	{
		if (needsRefresh(token_, now, skew_))
		{
			if (token_.refreshToken.length == 0)
			{
				if (token_.hasToken && token_.expiresAt == 0)
					return token_.accessToken; // no expiry known, no refresh possible
				throw internalError(
						"OAuth access token expired and no refresh token is available; "
						~ "re-authentication required");
			}
			auto ts = refreshFn_(token_.refreshToken);
			if (ts.accessToken.length == 0)
				throw internalError("OAuth token refresh returned no access token");
			// Carry the registered client_id forward so the persisted record can
			// authenticate a later refresh (the refresh response omits it).
			auto clientId = token_.clientId.length ? token_.clientId : client_.clientId;
			token_ = StoredToken.fromTokenSet(ts, resource_, now, token_.refreshToken);
			token_.clientId = clientId;
			if (store_ !is null)
				store_.save(resource_, token_);
		}
		return token_.accessToken;
	}
}

// ===========================================================================
// Browser opener
// ===========================================================================

/// Open `url` in the user's default browser using the platform launcher
/// (`open` on macOS, `xdg-open` on Linux/BSD, `cmd /c start` on Windows).
void openSystemBrowser(string url) @safe
{
	import std.process : spawnProcess, Config;

	string[] cmd;
	version (OSX)
		cmd = ["open", url];
	else version (Windows)
		cmd = ["cmd", "/c", "start", "", url];
	else
		cmd = ["xdg-open", url];

	() @trusted {
		try
		{
			spawnProcess(cmd, null, Config.detached);
		}
		catch (Exception)
		{
		}
	}();
}

// ===========================================================================
// The one-call flow
// ===========================================================================

/// The `RegisteredClient` to use on the cache fast-path. The `client_id` is
/// read from the persisted token (so DCR/CIMD users, who have no statically
/// configured `client_id`, still carry the AS-issued one needed to refresh),
/// falling back to the configured `opts.clientId` for records that predate
/// persisting it. The secret comes from `opts` (it is not persisted).
RegisteredClient cacheHitClient(StoredToken cached, OAuthLogin opts) @safe pure nothrow
{
	const id = cached.clientId.length ? cached.clientId : opts.clientId;
	return RegisteredClient(id, opts.clientSecret);
}

/// Perform the full interactive OAuth login for `client` and attach the
/// resulting bearer token, refreshing automatically thereafter.
///
/// Steps:
/// 1. Discover protected-resource + authorization-server metadata.
/// 2. If a cached, non-expired token exists in the store, use it (refreshing
///    via the refresh grant when expired). Otherwise:
/// 3. Select a registration approach (pre-registered / CIMD / DCR).
/// 4. Run the authorization-code + PKCE flow: open the browser at the
///    authorization URL and capture the redirect `code` on a localhost loopback
///    listener; verify `state`.
/// 5. Exchange the code for tokens, persist them, and set the bearer on the
///    client.
///
/// Returns the live `OAuthSession` so callers can refresh on later requests via
/// `session.bearerForRequest(now)`.
OAuthSession useOAuth(McpClient client, string mcpEndpoint, OAuthLogin opts) @safe
{
	import std.datetime.systime : Clock;

	auto store = opts.store !is null ? opts.store : new FileTokenStore(defaultTokenStorePath());

	auto oauth = new OAuthClient();
	oauth.resource = canonicalResourceUri(mcpEndpoint);
	oauth.authMethod = opts.authMethod;
	oauth.clientIdMetadataUrl = opts.clientIdMetadataUrl;

	const long now = () @trusted { return Clock.currTime().toUnixTime(); }();

	// Discover the issuer and AS metadata. Enforce the discovered AS document's
	// issuer only on the modern RFC 9728 path (issuer named by a
	// protected-resource-metadata document); stay lenient on the 2025-03-26
	// origin fallback.
	bool issuerFromPrm;
	const issuer = oauth.resolveIssuer(mcpEndpoint, issuerFromPrm);
	auto as_ = oauth.discoverAuthServer(issuer, issuerFromPrm);

	// Reuse a cached, still-valid token when present.
	auto cached = store.load(oauth.resource);
	if (cached.hasToken && !needsRefresh(cached, now))
	{
		client.setBearerToken(cached.accessToken);
		return new OAuthSession(oauth, as_, cacheHitClient(cached, opts),
				store, oauth.resource, cached);
	}

	// Select / obtain a client registration.
	RegisteredClient rc;
	const havePre = opts.clientId.length > 0;
	const approach = oauth.registrationApproach(as_, havePre);
	final switch (approach)
	{
	case ClientRegistrationApproach.preRegistered:
		rc = RegisteredClient(opts.clientId, opts.clientSecret);
		break;
	case ClientRegistrationApproach.clientIdMetadataDocument:
		rc = oauth.clientIdMetadataClient(as_);
		break;
	case ClientRegistrationApproach.dynamicClientRegistration:
		rc = oauth.register(as_, opts.clientName, opts.scopeString());
		break;
	case ClientRegistrationApproach.promptUser:
		throw internalError(
				"Authorization server requires manual client registration; supply OAuthLogin.clientId");
	}

	// If we have a cached refresh token (but no usable access token), try the
	// refresh grant before falling back to the full browser flow.
	if (cached.refreshToken.length)
	{
		try
		{
			auto ts = oauth.refresh(as_, rc, cached.refreshToken);
			if (ts.accessToken.length)
			{
				auto refreshed = StoredToken.fromTokenSet(ts, oauth.resource,
						now, cached.refreshToken);
				refreshed.clientId = rc.clientId;
				store.save(oauth.resource, refreshed);
				client.setBearerToken(refreshed.accessToken);
				return new OAuthSession(oauth, as_, rc, store, oauth.resource, refreshed);
			}
		}
		catch (Exception)
		{
			// Fall through to the interactive flow.
		}
	}

	// Run the interactive authorization-code + PKCE flow on a loopback listener.
	auto pkce = generatePkce();
	const state = generateLoginState();
	const captured = runBrowserLoopbackFlow(oauth, as_, rc, pkce, opts, state);
	if (!captured.ok)
		throw internalError("OAuth loopback capture failed: " ~ (captured.error.length
				? captured.error : "no authorization code received"));

	auto ts = oauth.exchangeCode(as_, rc, captured.code, pkce.verifier);
	if (ts.accessToken.length == 0)
		throw internalError("OAuth token exchange returned no access token");
	auto stored = StoredToken.fromTokenSet(ts, oauth.resource, now);
	stored.clientId = rc.clientId;
	store.save(oauth.resource, stored);
	client.setBearerToken(stored.accessToken);
	return new OAuthSession(oauth, as_, rc, store, oauth.resource, stored);
}

/// Apply the RFC 9207 `iss` authorization-response validation to a captured
/// loopback redirect, given the selected authorization server's metadata.
/// Returns the capture unchanged when `iss` is acceptable; otherwise clears the
/// authorization `code` and records an `invalid_iss` error so the capture's
/// `ok` is false and the caller rejects it. The validation runs regardless of
/// any returned `error`/`error_description`, which are not acted on, mirroring
/// the two-arg `OAuthClient.authorizeAndGetCode(as_, ...)` overload.
LoopbackCapture enforceIssOnCapture(LoopbackCapture cap, AuthorizationServerMetadata as_) @safe
{
	if (validateAuthorizationResponseIss(cap.iss, as_.issuer,
			as_.authorizationResponseIssParameterSupported))
		return cap;
	cap.code = "";
	cap.error = "invalid_iss";
	cap.errorDescription = "authorization response failed RFC 9207 'iss' validation "
		~ "(possible mix-up attack)";
	return cap;
}

/// Open the browser at the authorization URL and run a localhost loopback HTTP
/// listener to capture the redirect. Blocks (on the vibe event loop) until the
/// redirect arrives or `opts.callbackTimeout` elapses, then returns the
/// captured authorization response. On timeout the result carries an
/// `authorization_timeout` error (so the caller rejects it rather than
/// hanging). The listener is stopped and the loopback port released on every
/// exit path.
private LoopbackCapture runBrowserLoopbackFlow(OAuthClient oauth, AuthorizationServerMetadata as_,
		RegisteredClient rc, PkcePair pkce, OAuthLogin opts, string state) @safe
{
	import vibe.http.server : HTTPServerSettings, HTTPServerRequest,
		HTTPServerResponse, HTTPListener, listenHTTP;
	import vibe.core.core : runEventLoop, exitEventLoop, setTimer, Timer;

	// Bind the loopback listener. Port 0 lets the OS pick an ephemeral port,
	// which we then read back to form the exact redirect URI.
	auto settings = new HTTPServerSettings;
	settings.bindAddresses = ["127.0.0.1"];
	settings.port = opts.callbackPort;

	LoopbackCapture result;
	bool done;
	Timer timeoutTimer;

	void handle(scope HTTPServerRequest req, scope HTTPServerResponse res) @safe
	{
		// Only the genuine callback path (or a request actually carrying an OAuth
		// `code`/`error` response parameter) may complete the flow. Stray requests
		// to other paths — favicon probes, prefetch, port scans, a second tab —
		// must not terminate the listener, otherwise they race ahead of the real
		// redirect and abort an otherwise-valid login.
		const reqPath = requestTargetPath(req.requestURI);
		const hasResponseParam = extractQueryParam(req.requestURI, "code").length > 0
			|| extractQueryParam(req.requestURI, "error").length > 0;
		if (reqPath != opts.callbackPath && !hasResponseParam)
		{
			res.statusCode = 404;
			res.contentType = "text/plain; charset=utf-8";
			res.writeBody("Not Found");
			return;
		}

		auto cap = parseLoopbackCallback(req.requestURI, state);
		// RFC 9207 mix-up protection: validate the `iss` authorization-response
		// parameter against the selected AS's recorded issuer BEFORE the token
		// exchange (the spec requires this regardless of whether an error param
		// was returned; the error/error_description are not otherwise acted on).
		cap = enforceIssOnCapture(cap, as_);
		if (!done)
		{
			result = cap;
			done = true;
			() @trusted { timeoutTimer.stop(); }();
		}
		res.contentType = "text/html; charset=utf-8";
		res.writeBody(loopbackResponseHtml(cap.ok));
		() @trusted { exitEventLoop(); }();
	}

	HTTPListener listener;
	ushort boundPort;
	() @trusted {
		listener = listenHTTP(settings, &handle);
		boundPort = listener.bindAddresses[0].port;
	}();
	scope (exit)
		() @trusted { listener.stopListening(); }();

	oauth.redirectUri = loopbackRedirectUri(boundPort, opts.callbackPath);
	const authzUrl = oauth.authorizationUrl(as_, rc, pkce, opts.scopeString(), state);

	void delegate(string) @safe opener = opts.openBrowser;
	if (opener is null)
		opener = (string u) @safe { openSystemBrowser(u); };
	opener(authzUrl);

	void onTimeout() @safe nothrow
	{
		if (!done)
		{
			result = LoopbackCapture.init;
			result.error = "authorization_timeout";
			result.errorDescription
				= "no authorization redirect arrived before the callback timeout";
			done = true;
		}
		() @trusted { exitEventLoop(); }();
	}

	timeoutTimer = () @trusted {
		return setTimer(opts.callbackTimeout, &onTimeout);
	}();
	() @trusted { runEventLoop(); }();
	return result;
}

// ===========================================================================
// Tests
// ===========================================================================

unittest  // loopback capture extracts code and state from the redirect target
{
	auto c = parseLoopbackCallback("/callback?code=abc123&state=xyz");
	assert(c.code == "abc123");
	assert(c.state == "xyz");
	assert(c.ok);
}

unittest  // loopback capture URL-decodes the code parameter
{
	auto c = parseLoopbackCallback("/callback?code=a%20b&state=s");
	assert(c.code == "a b");
}

unittest  // loopback capture rejects a mismatched state (discards the code)
{
	auto c = parseLoopbackCallback("/callback?code=abc&state=wrong", "expected");
	assert(c.code == "");
	assert(!c.ok);
	assert(c.error == "state_mismatch");
}

unittest  // loopback capture accepts a matching state
{
	auto c = parseLoopbackCallback("/callback?code=abc&state=expected", "expected");
	assert(c.code == "abc");
	assert(c.ok);
}

unittest  // loopback capture surfaces an authorization-server error
{
	auto c = parseLoopbackCallback("/callback?error=access_denied&error_description=nope");
	assert(c.error == "access_denied");
	assert(c.errorDescription == "nope");
	assert(!c.ok);
}

unittest  // a fresh token (future expiry) does not need refreshing
{
	StoredToken t;
	t.accessToken = "tok";
	t.expiresAt = 1000;
	assert(!needsRefresh(t, 900)); // 900 + 30 skew < 1000
}

unittest  // a token within the skew window needs refreshing
{
	StoredToken t;
	t.accessToken = "tok";
	t.expiresAt = 1000;
	assert(needsRefresh(t, 980)); // 980 + 30 skew >= 1000
}

unittest  // an expired token needs refreshing
{
	StoredToken t;
	t.accessToken = "tok";
	t.expiresAt = 1000;
	assert(needsRefresh(t, 2000));
}

unittest  // a token with unknown expiry (0) is never auto-refreshed
{
	StoredToken t;
	t.accessToken = "tok";
	t.expiresAt = 0;
	assert(!needsRefresh(t, long.max - 100));
}

unittest  // a record with no access token always needs (re)acquisition
{
	StoredToken t;
	assert(needsRefresh(t, 0));
}

unittest  // fromTokenSet computes the absolute expiry from now + expires_in
{
	TokenSet ts;
	ts.accessToken = "a";
	ts.tokenType = "Bearer";
	ts.expiresIn = 3600;
	ts.refreshToken = "r";
	auto s = StoredToken.fromTokenSet(ts, "https://mcp.example.com", 1000);
	assert(s.expiresAt == 4600);
	assert(s.refreshToken == "r");
	assert(s.resource == "https://mcp.example.com");
}

unittest  // fromTokenSet keeps the previous refresh token when the AS omits one
{
	TokenSet ts;
	ts.accessToken = "a2";
	ts.expiresIn = 60;
	// ts.refreshToken left empty (refresh response without a new RT)
	auto s = StoredToken.fromTokenSet(ts, "https://mcp.example.com", 0, "old-refresh");
	assert(s.refreshToken == "old-refresh");
}

unittest  // StoredToken JSON round-trips
{
	StoredToken t;
	t.accessToken = "tok";
	t.tokenType = "Bearer";
	t.expiresAt = 4600;
	t.refreshToken = "r";
	t.scope_ = "mcp:read";
	t.resource = "https://mcp.example.com";
	auto back = StoredToken.fromJson(t.toJson());
	assert(back == t);
}

unittest  // MemoryTokenStore persists and loads per resource
{
	auto store = new MemoryTokenStore();
	assert(!store.load("https://a").hasToken);
	StoredToken t;
	t.accessToken = "tok";
	t.resource = "https://a";
	store.save("https://a", t);
	assert(store.load("https://a").accessToken == "tok");
	assert(!store.load("https://b").hasToken);
}

unittest  // loopbackRedirectUri formats a localhost URI for the bound port
{
	assert(loopbackRedirectUri(8765) == "http://localhost:8765/callback");
	assert(loopbackRedirectUri(1234, "/cb") == "http://localhost:1234/cb");
	assert(loopbackRedirectUri(1234, "cb") == "http://localhost:1234/cb");
}

unittest  // scopeString space-joins the requested scopes
{
	OAuthLogin o;
	o.scopes = ["mcp:read", "mcp:write"];
	assert(o.scopeString() == "mcp:read mcp:write");
	OAuthLogin empty;
	assert(empty.scopeString() == "");
}

unittest  // OAuthSession returns the cached token without refreshing when valid
{
	auto store = new MemoryTokenStore();
	AuthorizationServerMetadata as_;
	auto rc = RegisteredClient("cid", "");
	StoredToken t;
	t.accessToken = "valid-token";
	t.expiresAt = 10_000;
	auto sess = new OAuthSession(new OAuthClient(), as_, rc, store, "https://mcp.example.com", t);
	assert(sess.bearerForRequest(100) == "valid-token");
}

unittest  // OAuthSession throws when the token is expired and no refresh token exists
{
	import std.exception : assertThrown;

	auto store = new MemoryTokenStore();
	AuthorizationServerMetadata as_;
	auto rc = RegisteredClient("cid", "");
	StoredToken t;
	t.accessToken = "stale";
	t.expiresAt = 1000; // expired relative to the request time below
	auto sess = new OAuthSession(new OAuthClient(), as_, rc, store, "https://mcp.example.com", t);
	assertThrown(sess.bearerForRequest(5000));
}

unittest  // OAuthSession returns an unknown-expiry token even with no refresh token
{
	auto store = new MemoryTokenStore();
	AuthorizationServerMetadata as_;
	auto rc = RegisteredClient("cid", "");
	StoredToken t;
	t.accessToken = "no-expiry-token";
	t.expiresAt = 0;
	auto sess = new OAuthSession(new OAuthClient(), as_, rc, store, "https://mcp.example.com", t);
	assert(sess.bearerForRequest(long.max - 100) == "no-expiry-token");
}

unittest  // loopbackResponseHtml differs for success and failure
{
	import std.algorithm : canFind;

	assert(loopbackResponseHtml(true).canFind("complete"));
	assert(loopbackResponseHtml(false).canFind("failed"));
}

unittest  // generateLoginState produces a non-empty base64url value
{
	auto s = generateLoginState();
	assert(s.length > 0);
}

unittest  // generateLoginState yields unique, unpredictable values from the OS CSPRNG
{
	// Independent draws from a CSPRNG must not collide.
	assert(generateLoginState() != generateLoginState());
}

unittest  // generateLoginState's entropy source is the OS CSPRNG, not the default rndGen
{
	// Build the predictable sequence a default-seeded std.random would produce
	// for the 16 state bytes, and assert the real generator does not match it.
	import std.random : rndGen, uniform;

	auto gen = rndGen;
	ubyte[16] predictable;
	foreach (ref x; predictable)
		x = cast(ubyte) uniform(0, 256, gen);
	const predictableState = base64UrlNoPad(predictable[]);

	assert(generateLoginState() != predictableState);
}

unittest  // OAuthSession refreshes an expired token via the injected refresh fn
{
	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "old-access";
	t.refreshToken = "the-refresh";
	t.expiresAt = 1000; // expired relative to the request time below

	string seenRefresh;
	TokenSet delegate(string) @safe refreshFn = (string rt) @safe {
		seenRefresh = rt;
		TokenSet ts;
		ts.accessToken = "new-access";
		ts.tokenType = "Bearer";
		ts.expiresIn = 3600;
		ts.refreshToken = "rotated-refresh";
		return ts;
	};

	auto sess = new OAuthSession("https://mcp.example.com", t, store, refreshFn);
	auto bearer = sess.bearerForRequest(5000);

	// The expired token was refreshed using the stored refresh token.
	assert(seenRefresh == "the-refresh");
	assert(bearer == "new-access");
	// The new token (with its rotated refresh token and recomputed expiry) was
	// persisted through the store.
	auto saved = store.load("https://mcp.example.com");
	assert(saved.accessToken == "new-access");
	assert(saved.refreshToken == "rotated-refresh");
	assert(saved.expiresAt == 5000 + 3600);
}

unittest  // OAuthSession does not refresh when the cached token is still valid
{
	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "still-good";
	t.refreshToken = "rt";
	t.expiresAt = 1_000_000;

	bool refreshed;
	TokenSet delegate(string) @safe refreshFn = (string rt) @safe {
		refreshed = true;
		TokenSet ts;
		ts.accessToken = "should-not-be-used";
		return ts;
	};

	auto sess = new OAuthSession("https://mcp.example.com", t, store, refreshFn);
	assert(sess.bearerForRequest(100) == "still-good");
	assert(!refreshed);
}

unittest  // a refresh that returns no access token is an error
{
	import std.exception : assertThrown;

	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "old";
	t.refreshToken = "rt";
	t.expiresAt = 1000;

	TokenSet delegate(string) @safe refreshFn = (string rt) @safe {
		return TokenSet.init;
	};
	auto sess = new OAuthSession("https://mcp.example.com", t, store, refreshFn);
	assertThrown(sess.bearerForRequest(5000));
}

unittest  // parseLoopbackCallback extracts the RFC 9207 iss parameter
{
	auto c = parseLoopbackCallback("/callback?code=abc&state=s&iss=https%3A%2F%2Fas.example.com");
	assert(c.iss == "https://as.example.com");
}

unittest  // enforceIssOnCapture rejects a mismatched iss (mix-up attack)
{
	AuthorizationServerMetadata as_;
	as_.issuer = "https://as.example.com";
	as_.authorizationResponseIssParameterSupported = true;

	LoopbackCapture cap;
	cap.code = "good-code";
	cap.iss = "https://evil.example.com";
	auto checked = enforceIssOnCapture(cap, as_);
	assert(checked.code == "");
	assert(!checked.ok);
	assert(checked.error == "invalid_iss");
}

unittest  // enforceIssOnCapture rejects an absent iss when the AS advertises support
{
	AuthorizationServerMetadata as_;
	as_.issuer = "https://as.example.com";
	as_.authorizationResponseIssParameterSupported = true;

	LoopbackCapture cap;
	cap.code = "good-code";
	// cap.iss intentionally empty.
	auto checked = enforceIssOnCapture(cap, as_);
	assert(checked.code == "");
	assert(!checked.ok);
}

unittest  // enforceIssOnCapture accepts a matching iss
{
	AuthorizationServerMetadata as_;
	as_.issuer = "https://as.example.com";
	as_.authorizationResponseIssParameterSupported = true;

	LoopbackCapture cap;
	cap.code = "good-code";
	cap.iss = "https://as.example.com";
	auto checked = enforceIssOnCapture(cap, as_);
	assert(checked.code == "good-code");
	assert(checked.ok);
}

unittest  // enforceIssOnCapture accepts an absent iss when the AS does not advertise support
{
	AuthorizationServerMetadata as_;
	as_.issuer = "https://as.example.com";
	as_.authorizationResponseIssParameterSupported = false;

	LoopbackCapture cap;
	cap.code = "good-code";
	auto checked = enforceIssOnCapture(cap, as_);
	assert(checked.ok);
}

unittest  // enforceIssOnCapture runs even on an error response (does not act on the error)
{
	// The iss check must gate before token exchange regardless of a returned
	// error param: a mismatched iss on an error response is still rejected as an
	// iss failure (the error/error_description are not surfaced/acted on).
	AuthorizationServerMetadata as_;
	as_.issuer = "https://as.example.com";
	as_.authorizationResponseIssParameterSupported = true;

	LoopbackCapture cap;
	cap.error = "access_denied";
	cap.errorDescription = "user said no";
	cap.iss = "https://evil.example.com";
	auto checked = enforceIssOnCapture(cap, as_);
	assert(!checked.ok);
	assert(checked.error == "invalid_iss");
}

version (Posix) unittest  // FileTokenStore.writeSecretFile does not draw from the Mersenne Twister (std.random)
{
	// writeSecretFile MUST obtain its temp-file suffix from the OS CSPRNG
	// (cryptoRandomFill), not from the thread-local Mersenne Twister (rndGen).
	// Detection: snapshot rndGen before and after the save.  If MT were used,
	// the snapshot would differ because uniform(0, int.max) advances rndGen.
	// With the CSPRNG path, rndGen is untouched and the snapshots must match.
	import std.file : tempDir, mkdirRecurse, rmdirRecurse;
	import std.path : buildPath;
	import std.random : rndGen;
	import std.datetime.systime : Clock;
	import std.conv : to;

	auto root = buildPath(tempDir, "mcp-login-mt-" ~ Clock.currTime().toUnixTime().to!string);
	mkdirRecurse(root);
	scope (exit)
		() @trusted { rmdirRecurse(root); }();

	auto before = rndGen; // snapshot the MT state before the save

	auto file = buildPath(root, "tokens.json");
	auto store = new FileTokenStore(file);
	StoredToken t;
	t.accessToken = "secret";
	t.resource = "https://mcp.example.com";
	store.save("https://mcp.example.com", t);

	auto after = rndGen; // snapshot the MT state after the save
	// The two snapshots must be equal: the CSPRNG path must not advance rndGen.
	assert(before == after,
			"writeSecretFile advanced rndGen (Mersenne Twister): OS CSPRNG not used for temp suffix");
}

version (Posix) unittest  // FileTokenStore creates the token file 0600 (never a readable window)
{
	import std.file : tempDir, mkdirRecurse, rmdirRecurse, getAttributes, exists;
	import std.path : buildPath;
	import std.conv : to;
	import core.sys.posix.sys.stat : S_IRWXU, S_IRWXG, S_IRWXO;
	import std.datetime.systime : Clock;

	auto root = buildPath(tempDir, "mcp-login-perm-" ~ Clock.currTime().toUnixTime().to!string);
	mkdirRecurse(root);
	scope (exit)
		() @trusted { rmdirRecurse(root); }();

	auto file = buildPath(root, "sub", "tokens.json");
	auto store = new FileTokenStore(file);
	StoredToken t;
	t.accessToken = "secret-access";
	t.refreshToken = "secret-refresh";
	t.resource = "https://mcp.example.com";
	store.save("https://mcp.example.com", t);

	assert(file.exists);
	// The file must end up owner-only (0600): no group/other bits set.
	const fileMode = getAttributes(file) & (S_IRWXU | S_IRWXG | S_IRWXO);
	assert((fileMode & (S_IRWXG | S_IRWXO)) == 0, "token file is group/other accessible");
}

version (Posix) unittest  // FileTokenStore never writes secrets through a pre-existing loose-perm inode
{
	import std.file : tempDir, mkdirRecurse, rmdirRecurse, getAttributes, write,
		setAttributes, readText;
	import std.path : buildPath;
	import std.conv : to;
	import std.string : indexOf, toStringz;
	import core.sys.posix.sys.stat : S_IRWXU, S_IRWXG, S_IRWXO, S_IRUSR,
		S_IWUSR, S_IRGRP, S_IROTH;
	import core.sys.posix.unistd : link;
	import std.datetime.systime : Clock;

	auto root = buildPath(tempDir, "mcp-login-pre-" ~ Clock.currTime().toUnixTime().to!string);
	mkdirRecurse(root);
	scope (exit)
		() @trusted { rmdirRecurse(root); }();

	auto file = buildPath(root, "tokens.json");
	// Pre-create the target as a world/group-readable (0644) file, as an earlier
	// SDK version, an interrupted run, or an unusual umask might leave it.
	() @trusted {
		write(file, "{}");
		setAttributes(file, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	}();
	assert((getAttributes(file) & (S_IRWXG | S_IRWXO)) != 0);

	// A second name (hard link) onto the same loose-perm inode stands in for any
	// reference an attacker might hold to the pre-existing readable file. If save
	// writes the plaintext secrets in place, they become visible through this
	// still-loose alias; an atomic create-and-rename instead allocates a fresh
	// 0600 inode for the new name, leaving the alias with the old contents.
	auto alias_ = buildPath(root, "tokens.alias");
	auto linked = () @trusted {
		return link(file.toStringz, alias_.toStringz) == 0;
	}();
	assert(linked);

	auto store = new FileTokenStore(file);
	StoredToken t;
	t.accessToken = "secret-access";
	t.refreshToken = "secret-refresh";
	t.resource = "https://mcp.example.com";
	store.save("https://mcp.example.com", t);

	// The new token file must be owner-only and actually contain the secrets.
	const fileMode = getAttributes(file) & (S_IRWXU | S_IRWXG | S_IRWXO);
	assert((fileMode & (S_IRWXG | S_IRWXO)) == 0,
			"token file is group/other accessible after overwriting a loose file");
	assert((() @trusted => readText(file))().indexOf("secret-refresh") >= 0);

	// The loose-perm alias to the old inode must NOT have received the secrets.
	auto aliasContents = () @trusted { return readText(alias_); }();
	assert(aliasContents.indexOf("secret-refresh") < 0,
			"secrets were written through a pre-existing group/world-readable inode");
}

version (Posix) unittest  // FileTokenStore restricts the parent dir to 0700
{
	import std.file : tempDir, mkdirRecurse, rmdirRecurse, getAttributes;
	import std.path : buildPath, dirName;
	import std.conv : to;
	import core.sys.posix.sys.stat : S_IRWXG, S_IRWXO;
	import std.datetime.systime : Clock;

	auto root = buildPath(tempDir, "mcp-login-dir-" ~ Clock.currTime()
			.toUnixTime().to!string ~ "-d");
	mkdirRecurse(root);
	scope (exit)
		() @trusted { rmdirRecurse(root); }();

	auto file = buildPath(root, "sub", "tokens.json");
	auto store = new FileTokenStore(file);
	StoredToken t;
	t.accessToken = "secret";
	store.save("https://mcp.example.com", t);

	// The directory the SDK created must not be group/other-traversable.
	const dirMode = getAttributes(dirName(file)) & (S_IRWXG | S_IRWXO);
	assert(dirMode == 0, "token dir is group/other accessible");
}

version (Posix) unittest  // FileTokenStore.save does not chmod CWD when path has no directory component
{
	import std.file : tempDir, getcwd, chdir, getAttributes, remove, exists;
	import std.path : buildPath;
	import std.conv : to;
	import core.sys.posix.sys.stat : S_IRWXG, S_IRWXO;
	import std.datetime.systime : Clock;

	// Record the CWD permissions before the save call.
	const cwdBefore = getAttributes(".") & (S_IRWXG | S_IRWXO);

	// Use a bare filename (no directory component) so dirName returns ".".
	auto bare = "mcp-bare-token-" ~ Clock.currTime().toUnixTime().to!string ~ ".json";
	scope (exit)
	{
		if (bare.exists)
			remove(bare);
	}

	auto store = new FileTokenStore(bare);
	StoredToken t;
	t.accessToken = "secret";
	store.save("https://mcp.example.com", t);

	// The CWD must retain its original group/other bits — save must not chmod ".".
	const cwdAfter = getAttributes(".") & (S_IRWXG | S_IRWXO);
	assert(cwdAfter == cwdBefore, "save() stripped group/other bits from the CWD");
}

unittest  // the loopback flow aborts with a timeout error when no redirect arrives
{
	import core.time : msecs;

	auto oauth = new OAuthClient();
	oauth.resource = "https://mcp.example.com/mcp";
	AuthorizationServerMetadata as_;
	as_.authorizationEndpoint = "https://as.example.com/authorize";
	as_.codeChallengeMethodsSupported = ["S256"];
	auto rc = RegisteredClient("cid", "");
	auto pkce = generatePkce();

	OAuthLogin opts;
	opts.callbackTimeout = 50.msecs;
	// A no-op opener ensures no redirect is ever delivered, so only the timeout
	// can end the flow.
	opts.openBrowser = (string url) @safe {};

	auto captured = runBrowserLoopbackFlow(oauth, as_, rc, pkce, opts, "state-xyz");

	assert(!captured.ok);
	assert(captured.error == "authorization_timeout");
}

unittest  // requestTargetPath strips the query and fragment from a request target
{
	assert(requestTargetPath("/callback?code=abc&state=xyz") == "/callback");
	assert(requestTargetPath("/favicon.ico") == "/favicon.ico");
	assert(requestTargetPath("/callback") == "/callback");
	assert(requestTargetPath("/cb#frag") == "/cb");
	assert(requestTargetPath("") == "");
}

version (Posix) unittest  // openSystemBrowser does not leave a zombie process after the launcher exits
{
	// openSystemBrowser must spawn the launcher with Config.detached so the OS
	// never keeps a zombie entry after the process exits.  Without Config.detached,
	// discarding the Pid without calling wait() causes the exited child to remain
	// in the process table as a zombie until the parent process exits.
	//
	// Call openSystemBrowser with a URL scheme that the platform launcher cannot
	// handle, causing it to exit within milliseconds with an error — fast enough
	// to reliably produce a zombie before the assertion if Config.detached is absent.
	// With Config.detached the launcher runs as a grandchild (double-fork), so this
	// process has no direct child to reap and waitpid returns ECHILD.
	import core.stdc.errno : errno, ECHILD;
	import core.sys.posix.sys.types : pid_t;
	import core.sys.posix.sys.wait : waitpid, WNOHANG;
	import core.thread : Thread;
	import core.time : msecs;

	openSystemBrowser("mcp-sdk-test-zombie://localhost/verify-detach");

	Thread.sleep(300.msecs); // allow the launcher to exit and become a zombie if not detached

	// Reap any zombie direct children.  With Config.detached, the grandchild is
	// not a direct child of this process, so waitpid returns -1/ECHILD.
	// Without Config.detached the exited launcher is a zombie child and waitpid
	// returns its PID, causing the assertion to fail.
	int status;
	pid_t reaped = () @trusted { return waitpid(-1, &status, WNOHANG); }();

	assert(reaped == -1 && errno == ECHILD,
			"openSystemBrowser left a zombie child process; it must spawn with Config.detached");
}

unittest  // the cache fast-path carries the registered client_id (DCR/CIMD have no static client_id)
{
	OAuthLogin opts; // DCR/CIMD: opts.clientId is empty
	StoredToken cached;
	cached.accessToken = "valid";
	cached.clientId = "abc123"; // issued by the AS on the first run and persisted
	auto rc = cacheHitClient(cached, opts);
	assert(rc.clientId == "abc123");
}

unittest  // the cache fast-path falls back to the pre-registered client_id when none was persisted
{
	OAuthLogin opts;
	opts.clientId = "pre-reg"; // older cache records predate the stored client_id
	StoredToken cached;
	cached.accessToken = "valid";
	auto rc = cacheHitClient(cached, opts);
	assert(rc.clientId == "pre-reg");
}

unittest  // StoredToken persists the registered client_id across JSON round-trips
{
	StoredToken t;
	t.accessToken = "tok";
	t.clientId = "abc123";
	auto back = StoredToken.fromJson(t.toJson());
	assert(back.clientId == "abc123");
}

unittest  // refreshing an expired token preserves the registered client_id for later refreshes
{
	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "old";
	t.refreshToken = "rt";
	t.clientId = "abc123";
	t.expiresAt = 1000; // expired relative to the request time below

	TokenSet delegate(string) @safe refreshFn = (string rt) @safe {
		TokenSet ts;
		ts.accessToken = "new";
		ts.expiresIn = 3600;
		return ts;
	};
	auto sess = new OAuthSession("https://mcp.example.com", t, store, refreshFn);
	sess.bearerForRequest(5000);

	// The persisted token still carries the registered client_id so a subsequent
	// refresh (e.g. after a process restart) can authenticate at the AS.
	assert(store.load("https://mcp.example.com").clientId == "abc123");
}

unittest  // a stray non-callback request does not abort the loopback flow
{
	import core.time : msecs, seconds;
	import vibe.core.core : runTask, sleep;
	import vibe.http.client : requestHTTP;

	auto oauth = new OAuthClient();
	oauth.resource = "https://mcp.example.com/mcp";
	AuthorizationServerMetadata as_;
	as_.authorizationEndpoint = "https://as.example.com/authorize";
	as_.codeChallengeMethodsSupported = ["S256"];
	auto rc = RegisteredClient("cid", "");
	auto pkce = generatePkce();

	OAuthLogin opts;
	opts.callbackTimeout = 5.seconds;

	// The authorization URL carries the bound redirect_uri (with the ephemeral
	// port). Drive a stray /favicon.ico probe first, then the genuine callback;
	// the stray request must NOT terminate the listener.
	opts.openBrowser = (string url) @safe {
		auto redirectUri = extractQueryParam(url, "redirect_uri");
		import std.string : indexOf;

		// redirect_uri looks like http://localhost:<port>/callback
		auto hostStart = redirectUri.indexOf("localhost:");
		assert(hostStart >= 0);
		auto rest = redirectUri[hostStart + "localhost:".length .. $];
		auto slash = rest.indexOf('/');
		auto portStr = slash >= 0 ? rest[0 .. slash] : rest;
		auto baseUrl = "http://127.0.0.1:" ~ portStr;

		() @trusted {
			runTask(() nothrow{
				try
				{
					sleep(50.msecs);
					requestHTTP(baseUrl ~ "/favicon.ico", (scope req) {}, (scope res) {
						res.dropBody();
					});
					sleep(50.msecs);
					requestHTTP(baseUrl ~ "/callback?code=real-code&state=state-xyz", (scope req) {
					}, (scope res) { res.dropBody(); });
				}
				catch (Exception)
				{
				}
			});
		}();
	};

	auto captured = runBrowserLoopbackFlow(oauth, as_, rc, pkce, opts, "state-xyz");

	assert(captured.ok, "genuine callback should be captured despite the stray request");
	assert(captured.code == "real-code");
}
