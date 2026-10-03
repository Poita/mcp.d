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
 * Loopback redirect URIs (`http://127.0.0.1:<port>/callback`) are explicitly
 * permitted by the MCP authorization spec: "All redirect URIs MUST be either
 * `localhost` or use HTTPS." The `127.0.0.1` literal is used rather than
 * `localhost` because that is the address the listener binds (RFC 8252 §8.3).
 * PKCE S256 is enforced by the underlying
 * `OAuthClient`, and the RFC 8707 `resource` parameter is sent on both the
 * authorization and token requests.
 */

import core.time : Duration, minutes;

import vibe.core.sync : TaskMutex;
import vibe.data.json : Json, parseJsonString;

import mcp.protocol.errors;
import mcp.auth.oauth;
import mcp.auth.client;
import mcp.client.client : McpClient;
import mcp.client.transport : BearerProvider;

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
	/// The client secret issued alongside a dynamically registered `clientId`,
	/// persisted so a later refresh can authenticate as that client.
	string clientSecret;
	/// RFC 7591 `client_secret_expires_at` for `clientSecret` (absolute unix
	/// seconds); 0 means it does not expire.
	long clientSecretExpiresAt;
	/// The issuer of the authorization server that issued this token. `useOAuth`
	/// reuses or refreshes the token only with that same server, so a record
	/// with a different or empty issuer is treated as absent.
	string issuer;

	/// Record the client registration this token was obtained under.
	void setClient(RegisteredClient rc) @safe pure nothrow @nogc
	{
		clientId = rc.clientId;
		clientSecret = rc.clientSecret;
		clientSecretExpiresAt = rc.clientSecretExpiresAt;
	}

	/// Whether the recorded client secret has expired at `now`, leaving the
	/// registration unusable for authenticating a refresh.
	bool clientSecretExpired(long now) const @safe pure nothrow @nogc
	{
		return clientSecretExpiresAt != 0 && now >= clientSecretExpiresAt;
	}

	/// Whether this record holds a usable access token.
	bool hasToken() const @safe pure nothrow @nogc
	{
		return accessToken.length > 0;
	}

	/// Whether the token's granted `scope_` includes every scope in `requested`.
	/// A step-up request for a scope the token lacks needs a new authorization:
	/// neither reusing nor refreshing the token can widen it.
	bool grantsScopes(const string[] requested) const @safe pure
	{
		import std.algorithm : canFind, splitter;

		foreach (sc; requested)
			if (!scope_.splitter(' ').canFind(sc))
				return false;
		return true;
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
		j["client_secret"] = clientSecret;
		j["client_secret_expires_at"] = Json(clientSecretExpiresAt);
		j["issuer"] = issuer;
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
		if (auto p = "client_secret" in j)
			s.clientSecret = p.type == Json.Type.string ? p.get!string : "";
		if (auto p = "client_secret_expires_at" in j)
			s.clientSecretExpiresAt = p.type == Json.Type.int_ ? p.get!long : 0;
		if (auto p = "issuer" in j)
			s.issuer = p.type == Json.Type.string ? p.get!string : "";
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

version (Posix)
{
	// BSD `flock(2)`, available on Linux, macOS and the BSDs. Unlike `fcntl`
	// record locks it belongs to the open file description, so it also excludes
	// another thread of this process that opened the lock file separately.
	private extern (C) int flock(int fd, int operation) nothrow @nogc @system;
	private enum int LOCK_EX = 2;
	private enum int LOCK_UN = 8;
}

/// A file-backed `TokenStore`. Tokens for all resources are stored as a single
/// JSON object (`{ "<resource>": { ... } }`) at `path`.
///
/// Encryption hook: subclass and override `serialize`/`deserialize` to encrypt
/// the JSON blob at rest (e.g. with a key from the OS keychain). The plaintext
/// implementation writes the file with owner-only (`0600`) permissions on
/// POSIX.
///
/// `save` holds an exclusive advisory lock on the sidecar file `path ~ ".lock"`
/// across its read-modify-write, so several processes sharing one token file
/// (for example two MCP clients refreshing at once) never drop each other's
/// tokens.
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

	/// Read the on-disk token map. A genuinely absent file yields an empty map
	/// silently (a normal first run). A present-but-unreadable/corrupt file also
	/// yields an empty map (so the caller re-authenticates rather than crashing)
	/// but sets `corrupt` and logs, so the failure is observable instead of looking
	/// like a fresh store.
	private Json tryReadMap(out bool corrupt) @safe
	{
		import std.file : exists, read;
		import vibe.core.log : logWarn;

		corrupt = false;
		if (!path.length || !path.exists)
			return Json.emptyObject;
		try
		{
			auto data = () @trusted { return cast(const(ubyte)[]) read(path); }();
			auto j = deserialize(data);
			return j.type == Json.Type.object ? j : Json.emptyObject;
		}
		catch (Exception e)
		{
			corrupt = true;
			logWarn(
					"FileTokenStore: token file %s is unreadable/corrupt (%s); treating as empty. "
					~ "Re-authentication will be required.", path, e.msg);
			return Json.emptyObject;
		}
	}

	private Json readAll() @safe
	{
		bool corrupt;
		return tryReadMap(corrupt);
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
		import std.file : exists, isDir, mkdirRecurse, rename;
		import std.path : dirName;

		auto dir = dirName(path);
		// Only a directory the store creates is made owner-only; an existing one
		// (e.g. the user's home directory) is the user's to manage.
		if (dir.length && dir != "." && !(dir.exists && dir.isDir))
		{
			try
				() @trusted { mkdirRecurse(dir); }();
			catch (Exception e)
				throw internalError(
						"FileTokenStore: could not create token directory " ~ dir ~ ": " ~ e.msg);
			restrictDirPermissions(dir);
		}

		withFileLock(() @safe {
			bool corrupt;
			auto all = tryReadMap(corrupt);
			// Do not silently overwrite an unparseable token file: preserve its bytes
			// alongside (path~) so any recoverable tokens for other resources are not
			// destroyed by this save.
			if (corrupt)
				() @trusted {
				try
					rename(path, path ~ "~");
				catch (Exception)
				{
				}
			}();
			all[resource] = token.toJson();
			auto bytes = serialize(all);
			writeSecretFile(bytes);
		});
	}

	/// Run `fn` holding an exclusive advisory lock on the sidecar file
	/// `path ~ ".lock"`, so processes (and threads) sharing the token file
	/// serialize their read-modify-write and none loses another's update. The
	/// token file itself is replaced by rename, so it cannot carry the lock.
	private void withFileLock(scope void delegate() @safe fn) @safe
	{
		if (!path.length)
			return fn();
		const lockPath = path ~ ".lock";
		version (Posix)
		{
			import core.stdc.errno : EINTR, errno;
			import core.sys.posix.fcntl : open, O_CREAT, O_RDWR;
			import core.sys.posix.unistd : close;
			import std.string : toStringz;

			const fd = () @trusted {
				return open(lockPath.toStringz, O_CREAT | O_RDWR, 384); // 0600
			}();
			if (fd < 0)
				throw internalError("FileTokenStore: could not open lock file " ~ lockPath);
			// Closing the descriptor releases the lock.
			scope (exit)
				() @trusted { close(fd); }();
			int rc;
			do
				rc = () @trusted { return flock(fd, LOCK_EX); }();
			while (rc != 0 && (()@trusted => errno)() == EINTR);
			if (rc != 0)
				throw internalError("FileTokenStore: could not lock " ~ lockPath);
			fn();
		}
		else version (Windows)
		{
			import core.sys.windows.windows : CloseHandle, CreateFileW,
				FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
				GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
				LOCKFILE_EXCLUSIVE_LOCK, LockFileEx, OPEN_ALWAYS, OVERLAPPED, UnlockFileEx;
			import std.utf : toUTF16z;

			auto h = () @trusted {
				return CreateFileW(lockPath.toUTF16z, GENERIC_READ | GENERIC_WRITE,
						FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
						null, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, null);
			}();
			if (h == INVALID_HANDLE_VALUE)
				throw internalError("FileTokenStore: could not open lock file " ~ lockPath);
			scope (exit)
				() @trusted { CloseHandle(h); }();
			OVERLAPPED ov;
			if (!()@trusted {
					return LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ov);
				}())
				throw internalError("FileTokenStore: could not lock " ~ lockPath);
			scope (exit)
				() @trusted { UnlockFileEx(h, 0, 1, 0, &ov); }();
			fn();
		}
		else
			fn();
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
			// Tighten any pre-existing loose-permission file to owner-only BEFORE
			// writing secrets, and reassert afterwards in case `write` had to create
			// it (so secrets are never exposed through a broadly-readable file).
			restrictPermissions();
			() @trusted { write(path, bytes); }();
			restrictPermissions();
		}
	}

	/// True when `mode` still grants any group or other access, i.e. owner-only
	/// tightening did not take effect (some filesystems accept a chmod but ignore
	/// the mode bits).
	version (Posix) private static bool stillGroupOrOtherAccessible(uint mode) @safe
	{
		import core.sys.posix.sys.stat : S_IRWXG, S_IRWXO;

		return (mode & (S_IRWXG | S_IRWXO)) != 0;
	}

	/// Restrict the token file to owner-only access (POSIX `0600`, or a current-user
	/// only ACL on Windows). No-op on platforms with neither. A failure to tighten
	/// the permissions is non-fatal (it must not abort a save) but is logged, since
	/// it can leave the plaintext OAuth tokens readable by other local users.
	private void restrictPermissions() @safe
	{
		version (Posix)
		{
			import std.file : setAttributes, getAttributes, exists;
			import core.sys.posix.sys.stat : S_IRUSR, S_IWUSR;
			import vibe.core.log : logWarn;

			if (!path.exists)
				return;
			try
				() @trusted { setAttributes(path, S_IRUSR | S_IWUSR); }();
			catch (Exception e)
			{
				logWarn("FileTokenStore: could not restrict token file %s to owner-only (0600); "
						~ "OAuth tokens may be readable by other local users: %s", path, e.msg);
				return;
			}
			const mode = () @trusted { return getAttributes(path); }();
			if (stillGroupOrOtherAccessible(mode))
				logWarn("FileTokenStore: token file %s remains group/other-accessible after "
						~ "chmod; OAuth tokens may be exposed to other local users", path);
		}
		else version (Windows)
		{
			import std.file : exists;

			if (path.length && path.exists)
				restrictWindowsAcl(path, false);
		}
	}

	/// Restrict the token file's parent directory to owner-only access (POSIX
	/// `0700`, or a current-user only ACL on Windows), so the directory holding the
	/// plaintext token file is not group/other-traversable. No-op otherwise.
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
		else version (Windows)
		{
			import std.file : exists;

			if (dir.length && dir.exists)
				restrictWindowsAcl(dir, true);
		}
	}

	/// Set a current-user-only ACL on `p` using `icacls`: `/inheritance:r` drops
	/// inherited ACEs (removing any Everyone / BUILTIN\Users access the parent
	/// directory contributed) and `/grant:r` replaces grants with the current user
	/// alone. A directory additionally gets object/container inheritance so new
	/// children are owner-only too -- matching the POSIX 0600 (file) / 0700 (dir)
	/// intent. Best-effort and never throws, mirroring the POSIX `setAttributes`
	/// path; the OAuth token secrets it protects must not be exposed even if the
	/// ACL change fails to apply, so callers treat failure as non-fatal.
	version (Windows) private static void restrictWindowsAcl(string p, bool isDir) @trusted nothrow
	{
		import std.process : execute, environment;

		try
		{
			// icacls accepts a DOMAIN\user account name; build it from the
			// environment of the running process.
			auto user = environment.get("USERNAME");
			if (user.length == 0)
				return;
			auto domain = environment.get("USERDOMAIN");
			const account = domain.length ? domain ~ "\\" ~ user : user;
			const grant = isDir ? account ~ ":(OI)(CI)F" : account ~ ":F";
			execute(["icacls", p, "/inheritance:r", "/grant:r", grant]);
		}
		catch (Exception)
		{
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

/// Parse the path+query of an inbound loopback HTTP request (e.g.
/// `/callback?code=abc&state=xyz`) and extract the OAuth authorization response
/// parameters. When `expectedState` is non-empty, a missing or mismatched
/// `state` clears the captured `code` and records an error (MCP "Open
/// Redirection": clients SHOULD verify the state parameter and discard
/// mismatched results).
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
	/// OAuth scopes to request (space-joined into the `scope` parameter). When
	/// empty, `useOAuth` requests the scopes named by `wwwAuthenticate`'s
	/// challenge, else the protected-resource metadata's `scopes_supported`.
	string[] scopes;
	/// The `WWW-Authenticate` header of the 401 that prompted the login, if any.
	/// Its `resource_metadata` URL is tried first for discovery and its `scope`
	/// selects the scopes to request when `scopes` is empty.
	string wwwAuthenticate;
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
	/// How to authenticate at the token endpoint. Under `none`, a supplied
	/// `clientSecret` is sent with `client_secret_basic`.
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

/// The scopes a login requests: `opts.scopes` when set, otherwise those chosen
/// by `selectScope` from the `opts.wwwAuthenticate` challenge and the
/// protected-resource metadata `prm`.
package string[] loginScopes(const OAuthLogin opts, const ProtectedResourceMetadata prm) @safe
{
	import std.array : split;

	if (opts.scopes.length)
		return opts.scopes.dup;
	const challengeScope = opts.wwwAuthenticate.length
		? parseWwwAuthenticate(opts.wwwAuthenticate).scope_ : null;
	return selectScope(challengeScope, prm.scopesSupported).split();
}

/// The scopes a cached token must have been granted to be reused: those named
/// explicitly by `opts.scopes` or by the step-up challenge in
/// `opts.wwwAuthenticate`. The `scopes_supported` fallback of `loginScopes` is
/// not required, since an AS may grant a subset of what it advertises.
package string[] requiredScopes(const OAuthLogin opts) @safe
{
	import std.array : split;

	if (opts.scopes.length)
		return opts.scopes.dup;
	if (opts.wwwAuthenticate.length)
		return parseWwwAuthenticate(opts.wwwAuthenticate).scope_.split();
	return null;
}

/// The default loopback redirect URI for a given port and path. It names the
/// `127.0.0.1` literal the callback listener binds (RFC 8252 §8.3): `localhost`
/// may resolve to `::1` first, where nothing is listening.
string loopbackRedirectUri(ushort port, string path = "/callback") @safe pure
{
	import std.conv : to;

	return "http://127.0.0.1:" ~ port.to!string ~ normalizeCallbackPath(path);
}

/// The loopback callback path as it appears in the redirect URI: `/callback`
/// when empty, and always with a leading slash.
package string normalizeCallbackPath(string path) @safe pure nothrow
{
	if (path.length == 0)
		return "/callback";
	return path[0] == '/' ? path : "/" ~ path;
}

/// The default token-store path under the current user's config directory (see
/// `tokenStorePathFor`). Throws `McpException` when the environment names no
/// per-user directory.
string defaultTokenStorePath() @safe
{
	import std.process : environment;

	version (Windows)
		enum windows = true;
	else
		enum windows = false;
	return tokenStorePathFor((string name) @safe {
		try
			return environment.get(name, "");
		catch (Exception)
			return "";
	}, windows);
}

/// The token-store path for an environment read through `getEnv`:
/// `%APPDATA%\dlang-mcp\tokens.json` (else `%LOCALAPPDATA%`) on Windows, and
/// `$XDG_CONFIG_HOME/dlang-mcp/tokens.json` (else `~/.config/...`) elsewhere.
/// Tokens are secrets, so when no per-user directory is known this throws
/// `McpException` rather than writing them into the working directory.
string tokenStorePathFor(scope string delegate(string name) @safe getEnv, bool windows) @safe
{
	import std.path : buildPath;

	string base;
	if (windows)
	{
		base = getEnv("APPDATA");
		if (base.length == 0)
			base = getEnv("LOCALAPPDATA");
	}
	else
	{
		base = getEnv("XDG_CONFIG_HOME");
		if (base.length == 0)
		{
			const home = getEnv("HOME");
			if (home.length)
				base = buildPath(home, ".config");
		}
	}
	if (base.length == 0)
		throw internalError(windows ? "no per-user directory for the OAuth token store: neither APPDATA nor LOCALAPPDATA is set; supply OAuthLogin.store" : "no per-user directory for the OAuth token store: neither XDG_CONFIG_HOME nor HOME is set; supply OAuthLogin.store");
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
	private TaskMutex refreshLock_;
	// `invalidate` discarded a rejected token, so the next refresh replaces it.
	private bool rejectionPending_;
	// The current token came from a refresh that replaced a rejected one.
	private bool refreshedOnRejection_;

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
		this.refreshLock_ = new TaskMutex;
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
		this.refreshLock_ = new TaskMutex;
	}

	/// The current stored token (for inspection / persistence).
	StoredToken token() const @safe nothrow
	{
		return token_;
	}

	/// Record that the resource server rejected `rejectedAccessToken` (an HTTP
	/// 401 whose `WWW-Authenticate` challenge carries `error="invalid_token"`).
	/// When it is still the current access token, it is discarded here and in
	/// the token store, so the next `bearerForRequest` refreshes via the
	/// refresh-token grant, or throws demanding re-authentication when no
	/// refresh token is held, and a later `useOAuth` does not reuse it. This is
	/// the only way a token without a known expiry is ever replaced.
	///
	/// Returns whether a replacement token can be obtained: false when no
	/// refresh token is held, or when the rejected token is itself the
	/// replacement for a rejected one (the server would reject any refresh the
	/// same way, until the token is replaced on expiry), so the rejection (and its `WWW-Authenticate`
	/// challenge, which a re-authenticating `useOAuth` needs) reaches the caller.
	///
	/// Naming the rejected token keeps concurrent rejections idempotent: a
	/// request that failed with a token another request has already replaced
	/// does not discard the replacement.
	///
	/// `useOAuth` installs this as the client's `BearerProvider.onRejected`, so
	/// the HTTP transport calls it with the bearer a rejected request carried and
	/// retries that request once when it returns true.
	bool invalidate(string rejectedAccessToken) @safe
	{
		import mcp.auth.oauth : constantTimeEquals;

		refreshLock_.lock();
		scope (exit)
			refreshLock_.unlock();
		const replaceable = token_.refreshToken.length > 0;
		if (!token_.hasToken || !constantTimeEquals(token_.accessToken, rejectedAccessToken))
			return token_.hasToken || replaceable;
		if (refreshedOnRejection_)
		{
			// The token a rejection-driven refresh produced is rejected too
			// (e.g. an audience mismatch), so another refresh would only be
			// rejected again. Keep sending it, surfacing each 401, and drop it
			// from the store so a later `useOAuth` does not reuse it.
			if (store_ !is null)
			{
				auto discarded = token_;
				discarded.accessToken = "";
				discarded.expiresAt = 0;
				store_.save(resource_, discarded);
			}
			return false;
		}
		token_.accessToken = "";
		token_.expiresAt = 0;
		rejectionPending_ = replaceable;
		if (store_ !is null)
			store_.save(resource_, token_);
		return replaceable;
	}

	/// `bearerForRequest` at the current wall-clock time. `useOAuth` installs this
	/// as the client's bearer provider, so every request carries a fresh token.
	string bearer() @safe
	{
		import std.datetime.systime : Clock;

		return bearerForRequest(() @trusted {
			return Clock.currTime().toUnixTime();
		}());
	}

	/// Return a valid bearer access token for use at `now` (Unix seconds),
	/// refreshing via the refresh-token grant first when the current token has
	/// expired (or is within the skew window). The refreshed token is persisted
	/// through the `TokenStore`. Throws when no valid token can be produced
	/// (e.g. expired with no refresh token).
	///
	/// Refreshes are single-flighted: concurrent callers (fibers or threads) wait
	/// for one in-flight refresh and share its result, so a rotating refresh token
	/// is never presented twice (which an AS answers with `invalid_grant` and may
	/// treat as token theft, revoking the whole token family). Before refreshing,
	/// the session re-reads the `TokenStore`, so a token another process sharing
	/// the store has already refreshed (and the refresh token it rotated to) is
	/// adopted rather than refreshed again with a stale refresh token.
	///
	/// A refresh the AS answers with `invalid_grant` drops the refresh token here
	/// and in the store, so later calls throw demanding re-authentication instead
	/// of presenting the dead refresh token again.
	string bearerForRequest(long now) @safe
	{
		refreshLock_.lock();
		scope (exit)
			refreshLock_.unlock();
		if (!needsRefresh(token_, now, skew_))
			return token_.accessToken;
		if (adoptStoredToken() && !needsRefresh(token_, now, skew_))
			return token_.accessToken;
		if (token_.refreshToken.length == 0)
		{
			if (token_.hasToken && token_.expiresAt == 0)
				return token_.accessToken; // no expiry known, no refresh possible
			throw internalError(
					"OAuth access token has expired or was rejected and no refresh token "
					~ "is available; call useOAuth again to re-authenticate");
		}
		TokenSet ts;
		try
			ts = refreshFn_(token_.refreshToken);
		catch (Exception e)
		{
			// Another process may have rotated the refresh token in the meantime;
			// only a refresh token still current in the store is known dead.
			if (oauthErrorCode(e) == "invalid_grant" && !adoptStoredToken())
			{
				token_.refreshToken = "";
				if (store_ !is null)
					store_.save(resource_, token_);
			}
			throw e;
		}
		if (ts.accessToken.length == 0)
			throw internalError("OAuth token refresh returned no access token");
		// Carry the registered client and the issuer forward so the persisted
		// record can authenticate a later refresh at the same AS (the refresh
		// response carries neither).
		auto prev = token_;
		auto issuer = prev.issuer.length ? prev.issuer : as_.issuer;
		token_ = StoredToken.fromTokenSet(ts, resource_, now, prev.refreshToken);
		refreshedOnRejection_ = rejectionPending_;
		rejectionPending_ = false;
		if (token_.scope_.length == 0)
			token_.scope_ = prev.scope_;
		if (prev.clientId.length)
		{
			token_.clientId = prev.clientId;
			token_.clientSecret = prev.clientSecret;
			token_.clientSecretExpiresAt = prev.clientSecretExpiresAt;
		}
		else
			token_.clientId = client_.clientId;
		token_.issuer = issuer;
		if (store_ !is null)
			store_.save(resource_, token_);
		return token_.accessToken;
	}

	/// Replace the current token with the store's record for this resource when
	/// that record differs and is bound to the same issuer and client (so its
	/// refresh token is one this session's client may present). Returns whether a
	/// record was adopted. The caller holds `refreshLock_`.
	private bool adoptStoredToken() @safe
	{
		if (store_ is null)
			return false;
		auto stored = store_.load(resource_);
		if (!stored.hasToken && stored.refreshToken.length == 0)
			return false;
		if (stored.issuer != token_.issuer || stored.clientId != token_.clientId)
			return false;
		if (stored.accessToken == token_.accessToken && stored.refreshToken == token_.refreshToken)
			return false;
		token_ = stored;
		rejectionPending_ = false;
		refreshedOnRejection_ = false;
		return true;
	}
}

// ===========================================================================
// Browser opener
// ===========================================================================

/// A browser-launch sink. The default path spawns the platform launcher; tests
/// inject a stub to exercise the success and failure branches deterministically.
alias BrowserSpawn = void delegate(string[] cmd) @safe;

/// The platform families `browserLaunchCommand` knows how to target.
enum LauncherPlatform
{
	macOS,
	windows,
	other, /// Linux/BSD and anything else with `xdg-open`
}

/// The platform this build targets.
enum LauncherPlatform hostLauncherPlatform = () {
	version (OSX)
		return LauncherPlatform.macOS;
	else version (Windows)
		return LauncherPlatform.windows;
	else
		return LauncherPlatform.other;
}();

/// The argv that opens `url` in the default browser on `platform`. The URL is
/// always a single argument and never passes through a shell: on Windows it
/// goes to `rundll32 url.dll,FileProtocolHandler`, because `cmd /c start` would
/// treat the `&` separating query parameters as a command separator.
string[] browserLaunchCommand(string url, LauncherPlatform platform) @safe pure nothrow
{
	final switch (platform)
	{
	case LauncherPlatform.macOS:
		return ["open", url];
	case LauncherPlatform.windows:
		return ["rundll32", "url.dll,FileProtocolHandler", url];
	case LauncherPlatform.other:
		return ["xdg-open", url];
	}
}

/// Open `url` in the user's default browser using the platform launcher
/// (see `browserLaunchCommand`).
/// Returns true if the launcher started. On failure (no launcher on a headless
/// host, spawn error) it does not throw — the loopback flow can still complete
/// if the user opens the URL manually — but it logs the URL so the user is not
/// left staring at a silent multi-minute wait. Pass `spawn` to override the
/// launcher (used by tests).
bool openSystemBrowser(string url, scope BrowserSpawn spawn = null) @safe
{
	import std.process : spawnProcess, Config;

	auto cmd = browserLaunchCommand(url, hostLauncherPlatform);

	try
	{
		if (spawn !is null)
			spawn(cmd);
		else
			() @trusted { spawnProcess(cmd, null, Config.detached); }();
		return true;
	}
	catch (Exception e)
	{
		import vibe.core.log : logWarn;

		logWarn("Could not launch a browser (%s) to open the OAuth authorization URL. "
				~ "Open this URL manually to continue:\n%s", e.msg, url);
		return false;
	}
}

// ===========================================================================
// The one-call flow
// ===========================================================================

/// The `RegisteredClient` to use on the cache fast-path. The `client_id` and
/// secret are read from the persisted token (so DCR/CIMD users, who have no
/// statically configured credentials, still carry the AS-issued ones needed to
/// refresh), falling back to the configured `opts.clientId`/`opts.clientSecret`
/// for the pre-registered client or a record without a client.
RegisteredClient cacheHitClient(StoredToken cached, OAuthLogin opts) @safe pure nothrow
{
	if (cached.clientId.length == 0 || cached.clientId == opts.clientId)
		return RegisteredClient(opts.clientId, opts.clientSecret);
	return RegisteredClient(cached.clientId, cached.clientSecret, cached.clientSecretExpiresAt);
}

/// The client registration to persist with a token: the configured
/// pre-registered secret stays in `opts` and is not written to the store.
RegisteredClient persistedClient(RegisteredClient rc, OAuthLogin opts) @safe pure nothrow
{
	if (rc.clientId.length && rc.clientId == opts.clientId)
		return RegisteredClient(rc.clientId);
	return rc;
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
/// 5. Exchange the code for tokens, persist them, and install the session as
///    the client's bearer provider.
///
/// The client then asks the session for its bearer on every request
/// (`OAuthSession.bearer`), which refreshes the access token when it nears
/// expiry, so refresh is transparent. Returns the live `OAuthSession`.
OAuthSession useOAuth(McpClient client, string mcpEndpoint, OAuthLogin opts) @safe
{
	import std.datetime.systime : Clock;
	import vibe.core.log : logWarn;

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
	const located = oauth.discoverIssuer(mcpEndpoint, opts.wwwAuthenticate);
	// RFC 9728: the protected-resource metadata names the resource the server
	// protects, which may be a parent of the endpoint (`prmResourceMatches`); that
	// is the audience the server checks, so it is the resource indicator to send.
	if (located.fromProtectedResourceMetadata && located.metadata.resource.length)
		oauth.resource = canonicalResourceUri(located.metadata.resource);
	auto as_ = oauth.discoverAuthServer(located.issuer, located.fromProtectedResourceMetadata);
	const required = requiredScopes(opts);
	opts.scopes = loginScopes(opts, located.metadata);

	// Reuse a cached, still-valid token when present. A record from another
	// authorization server (or one that never recorded its issuer) is ignored:
	// its access token is not meant for this AS, and its refresh token and
	// client credentials must never be sent to a server that did not issue them.
	auto cached = store.load(oauth.resource);
	if (cached.issuer.length == 0 || cached.issuer != as_.issuer)
		cached = StoredToken.init;
	// An expired client secret can no longer authenticate a refresh, so the
	// registration (and the tokens bound to it) must be replaced.
	if (cached.clientSecretExpired(now))
		cached = StoredToken.init;
	// A token lacking an explicitly required scope (a step-up after
	// `insufficient_scope`) cannot be reused or refreshed into one that has it.
	const scopesGranted = cached.grantsScopes(required);
	if (scopesGranted && cached.hasToken && !needsRefresh(cached, now))
	{
		return attachSession(client, new OAuthSession(oauth, as_,
				cacheHitClient(cached, opts), store, oauth.resource, cached));
	}

	// A refresh token is bound to the client that obtained it (RFC 6749 §6), so
	// try it under that client id — persisted from the first login, or the
	// pre-registered one — before registering anything new.
	auto prior = cacheHitClient(cached, opts);
	if (scopesGranted && cached.refreshToken.length && prior.clientId.length)
	{
		try
		{
			auto ts = oauth.refresh(as_, prior, cached.refreshToken);
			if (ts.accessToken.length)
			{
				auto refreshed = StoredToken.fromTokenSet(ts, oauth.resource,
						now, cached.refreshToken);
				if (refreshed.scope_.length == 0)
					refreshed.scope_ = cached.scope_;
				refreshed.setClient(persistedClient(prior, opts));
				refreshed.issuer = as_.issuer;
				store.save(oauth.resource, refreshed);
				return attachSession(client, new OAuthSession(oauth, as_, prior,
						store, oauth.resource, refreshed));
			}
			logWarn(
					"OAuth refresh for %s returned no access token; " ~ "starting an interactive login",
					oauth.resource);
		}
		catch (Exception e)
			logWarn("OAuth refresh for %s failed (%s); starting an interactive login",
					oauth.resource, e.msg);
	}

	// Select / obtain a client registration. Runs once the loopback listener
	// is bound, so a dynamic registration names the real redirect URI.
	RegisteredClient resolveClient(string redirectUri) @safe
	{
		const havePre = opts.clientId.length > 0;
		final switch (oauth.registrationApproach(as_, havePre))
		{
		case ClientRegistrationApproach.preRegistered:
			return RegisteredClient(opts.clientId, opts.clientSecret);
		case ClientRegistrationApproach.clientIdMetadataDocument:
			return oauth.clientIdMetadataClient(as_);
		case ClientRegistrationApproach.dynamicClientRegistration:
			return oauth.register(as_, opts.clientName, opts.scopeString());
		case ClientRegistrationApproach.promptUser:
			throw internalError(
					"Authorization server requires manual client registration; supply OAuthLogin.clientId");
		}
	}

	auto pkce = generatePkce();
	const state = generateLoginState();
	RegisteredClient rc;
	const captured = runBrowserLoopbackFlow(oauth, as_, &resolveClient, rc, pkce, opts, state);
	if (!captured.ok)
		throw internalError("OAuth loopback capture failed: " ~ (captured.error.length
				? captured.error : "no authorization code received"));

	auto ts = oauth.exchangeCode(as_, rc, captured.code, pkce.verifier);
	if (ts.accessToken.length == 0)
		throw internalError("OAuth token exchange returned no access token");
	// Capture a fresh timestamp immediately after the exchange so that
	// expiresAt = issuedAt + expiresIn reflects the actual token-issuance
	// wall time, not the time useOAuth was entered (which predates the
	// interactive browser wait by however long the user took to authenticate).
	const long issuedAt = () @trusted { return Clock.currTime().toUnixTime(); }();
	auto stored = StoredToken.fromTokenSet(ts, oauth.resource, issuedAt);
	// An omitted `scope` means the requested scope was granted (RFC 6749 §5.1).
	if (stored.scope_.length == 0)
		stored.scope_ = opts.scopeString();
	stored.setClient(persistedClient(rc, opts));
	stored.issuer = as_.issuer;
	store.save(oauth.resource, stored);
	return attachSession(client, new OAuthSession(oauth, as_, rc, store, oauth.resource, stored));
}

/// Install `session` as `client`'s bearer provider, so each request carries a
/// token refreshed on demand and a token the server rejects is discarded, and
/// return it.
private OAuthSession attachSession(McpClient client, OAuthSession session) @safe
{
	client.setBearerProvider(BearerProvider(&session.bearer, &session.invalidate));
	return session;
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

/// Returns true when `reqPath` matches the normalized `callbackPath` (the path
/// the redirect URI names) exactly, meaning the request should be processed as
/// an OAuth callback. Requests on any other path are always rejected with 404,
/// regardless of query parameters — a request carrying `code=` or `error=` on
/// the wrong path must not abort the flow.
private bool isLoopbackCallbackPath(string reqPath, string callbackPath) @safe pure nothrow
{
	return reqPath == normalizeCallbackPath(callbackPath);
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
	RegisteredClient used;
	return runBrowserLoopbackFlow(oauth, as_, (string redirectUri) @safe => rc,
			used, pkce, opts, state);
}

/// As above, but the client registration is resolved by `resolveClient` only
/// once the listener is bound and `oauth.redirectUri` names the actual loopback
/// port, so a Dynamic Client Registration carries the redirect URI the
/// authorization request will use. The resolved client is returned in `rc`.
/// May run from inside a vibe task (the wait then yields to that task's loop)
/// or from a plain thread context (the wait drives the event loop).
private LoopbackCapture runBrowserLoopbackFlow(OAuthClient oauth,
		AuthorizationServerMetadata as_, RegisteredClient delegate(
			string redirectUri) @safe resolveClient,
		out RegisteredClient rc, PkcePair pkce, OAuthLogin opts, string state) @safe
{
	import core.time : msecs;
	import vibe.http.server : HTTPServerSettings, HTTPServerRequest,
		HTTPServerResponse, HTTPListener, listenHTTP;
	import vibe.core.core : runEventLoop, exitEventLoop, setTimer, sleep, Timer;
	import vibe.core.task : Task;

	// Inside a task, a nested runEventLoop() is not allowed; the wait below
	// yields instead, and the handlers must not tear down the host's loop.
	const inTask = Task.getThis() != Task.init;

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
		// Only requests on the exact callback path proceed. Stray requests
		// — favicon probes, prefetch, port scans, or any request carrying
		// code=/error= on a wrong path — are rejected with 404 so they cannot
		// race ahead of the genuine AS redirect and abort the flow.
		const reqPath = requestTargetPath(req.requestURI);
		if (!isLoopbackCallbackPath(reqPath, opts.callbackPath))
		{
			res.statusCode = 404;
			res.contentType = "text/plain; charset=utf-8";
			res.writeBody("Not Found");
			return;
		}

		auto cap = parseLoopbackCallback(req.requestURI, state);
		// A response without this flow's state did not come from the authorization
		// request this flow made (any web page can make the browser hit the
		// loopback port), so it neither completes nor aborts the login.
		if (!validateAuthorizationResponseState(cap.state, state))
		{
			res.statusCode = 400;
			res.contentType = "text/plain; charset=utf-8";
			res.writeBody("Unknown authorization state");
			return;
		}
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
		if (!inTask)
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
	rc = resolveClient(oauth.redirectUri);
	const authzUrl = oauth.authorizationUrl(as_, rc, pkce, opts.scopeString(), state);

	void delegate(string) @safe opener = opts.openBrowser;
	if (opener is null)
		opener = (string u) @safe { cast(void) openSystemBrowser(u); };
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
		if (!inTask)
			() @trusted { exitEventLoop(); }();
	}

	timeoutTimer = () @trusted {
		return setTimer(opts.callbackTimeout, &onTimeout);
	}();
	scope (exit)
		() @trusted { timeoutTimer.stop(); }();
	if (inTask)
		while (!done)
			sleep(10.msecs);
	else
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

unittest  // fromTokenSet expiresAt is anchored to the timestamp passed in, not an earlier one
{
	// useOAuth must pass a timestamp captured AFTER exchangeCode() returns, not
	// one captured at function entry. A stale entry-time timestamp (nowBefore)
	// produces an expiresAt that is earlier than the correct post-exchange value
	// (nowAfter + expiresIn), shortening the effective token lifetime by the
	// duration of the interactive browser wait.
	TokenSet ts;
	ts.accessToken = "tok";
	ts.expiresIn = 300;
	const long nowBefore = 1_000_000; // simulates now captured before browser wait
	const long nowAfter = nowBefore + 180; // simulates 3 minutes of browser interaction
	const long expiresIn = 300;

	auto stalePaths = StoredToken.fromTokenSet(ts, "https://mcp.example.com", nowBefore);
	auto freshPath = StoredToken.fromTokenSet(ts, "https://mcp.example.com", nowAfter);

	// The stale path expires 180 seconds earlier than the fresh path.
	assert(freshPath.expiresAt == nowAfter + expiresIn);
	assert(stalePaths.expiresAt == nowBefore + expiresIn);
	assert(freshPath.expiresAt - stalePaths.expiresAt == 180);
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

unittest  // loopbackRedirectUri names the 127.0.0.1 literal the listener binds (RFC 8252 §8.3)
{
	assert(loopbackRedirectUri(8765) == "http://127.0.0.1:8765/callback");
	assert(loopbackRedirectUri(1234, "/cb") == "http://127.0.0.1:1234/cb");
	assert(loopbackRedirectUri(1234, "cb") == "http://127.0.0.1:1234/cb");
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

unittest  // a token the server rejected is refreshed on the next request even with no known expiry
{
	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "rejected-access";
	t.refreshToken = "the-refresh";
	t.expiresAt = 0;

	string seenRefresh;
	TokenSet delegate(string) @safe refreshFn = (string rt) @safe {
		seenRefresh = rt;
		TokenSet ts;
		ts.accessToken = "new-access";
		return ts;
	};

	auto sess = new OAuthSession("https://mcp.example.com", t, store, refreshFn);
	sess.invalidate("rejected-access");
	assert(sess.bearerForRequest(5000) == "new-access");
	assert(seenRefresh == "the-refresh");
	assert(store.load("https://mcp.example.com").accessToken == "new-access");
}

unittest  // a rejected token with no refresh token demands re-authentication and leaves the store
{
	import std.exception : assertThrown;

	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "rejected-access";
	store.save("https://mcp.example.com", t);

	int refreshes;
	auto sess = new OAuthSession("https://mcp.example.com", t, store, (string rt) @safe {
		++refreshes;
		return TokenSet.init;
	});
	sess.invalidate("rejected-access");
	assertThrown(sess.bearerForRequest(5000));
	assert(refreshes == 0);
	// A later useOAuth must not reuse the rejected token from the store.
	assert(!store.load("https://mcp.example.com").hasToken);
}

unittest  // invalidating a token that has already been replaced keeps the current one
{
	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "current-access";

	int refreshes;
	auto sess = new OAuthSession("https://mcp.example.com", t, store, (string rt) @safe {
		++refreshes;
		return TokenSet.init;
	});
	sess.invalidate("stale-access");
	assert(sess.bearerForRequest(5000) == "current-access");
	assert(refreshes == 0);
}

version (unittest) private string delegate(string) @safe fakeEnv(string[string] vars) @safe
{
	return (string name) @safe => vars.get(name, "");
}

unittest  // the Windows token store lives under %APPDATA%
{
	import std.path : buildPath;

	assert(tokenStorePathFor(fakeEnv(["APPDATA": `C:\Users\u\AppData\Roaming`]),
			true) == buildPath(`C:\Users\u\AppData\Roaming`, "dlang-mcp", "tokens.json"));
}

unittest  // the Windows token store falls back to %LOCALAPPDATA%
{
	import std.path : buildPath;

	assert(tokenStorePathFor(fakeEnv([
		"LOCALAPPDATA": `C:\Users\u\AppData\Local`
	]), true) == buildPath(`C:\Users\u\AppData\Local`, "dlang-mcp", "tokens.json"));
}

unittest  // the Windows token store ignores HOME-style variables and never uses the working directory
{
	import std.exception : assertThrown;

	assertThrown!McpException(tokenStorePathFor(fakeEnv(["HOME": "/home/u"]), true));
}

unittest  // the POSIX token store lives under XDG_CONFIG_HOME, else ~/.config
{
	import std.path : buildPath;

	assert(tokenStorePathFor(fakeEnv([
		"XDG_CONFIG_HOME": "/xdg",
		"HOME": "/home/u"
	]), false) == buildPath("/xdg", "dlang-mcp", "tokens.json"));
	assert(tokenStorePathFor(fakeEnv(["HOME": "/home/u"]),
			false) == buildPath("/home/u", ".config", "dlang-mcp", "tokens.json"));
}

unittest  // with no per-user directory the token store path is refused, not put in the working directory
{
	import std.exception : assertThrown;

	assertThrown!McpException(tokenStorePathFor(fakeEnv(null), false));
}

unittest  // login scopes default to the WWW-Authenticate challenge's scope
{
	OAuthLogin opts;
	opts.wwwAuthenticate = `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", scope="files:read files:write"`;
	ProtectedResourceMetadata prm;
	prm.scopesSupported = ["other"];
	assert(loginScopes(opts, prm) == ["files:read", "files:write"]);
}

unittest  // login scopes fall back to the resource metadata's scopes_supported
{
	OAuthLogin opts;
	ProtectedResourceMetadata prm;
	prm.scopesSupported = ["mcp:read", "mcp:write"];
	assert(loginScopes(opts, prm) == ["mcp:read", "mcp:write"]);
}

unittest  // explicitly configured login scopes win over discovered ones
{
	OAuthLogin opts;
	opts.scopes = ["mine"];
	opts.wwwAuthenticate = `Bearer scope="theirs"`;
	ProtectedResourceMetadata prm;
	prm.scopesSupported = ["supported"];
	assert(loginScopes(opts, prm) == ["mine"]);
}

unittest  // the scopes a cached token must cover exclude the scopes_supported fallback
{
	OAuthLogin opts;
	assert(requiredScopes(opts).length == 0);
	opts.wwwAuthenticate = `Bearer error="insufficient_scope", scope="files:write"`;
	assert(requiredScopes(opts) == ["files:write"]);
	opts.scopes = ["mine"];
	assert(requiredScopes(opts) == ["mine"]);
}

unittest  // with nothing configured or discovered no scope is requested
{
	assert(loginScopes(OAuthLogin.init, ProtectedResourceMetadata.init).length == 0);
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

unittest  // a session adopts a still-valid token another process saved to the shared store
{
	auto store = new MemoryTokenStore();
	StoredToken mine;
	mine.accessToken = "old-access";
	mine.refreshToken = "stale-refresh";
	mine.expiresAt = 1000;
	StoredToken theirs;
	theirs.accessToken = "their-access";
	theirs.refreshToken = "rotated-refresh";
	theirs.expiresAt = 10_000;
	store.save("https://mcp.example.com", theirs);

	int calls;
	TokenSet delegate(string) @safe refreshFn = (string rt) @safe {
		++calls;
		return TokenSet.init;
	};
	auto sess = new OAuthSession("https://mcp.example.com", mine, store, refreshFn);
	assert(sess.bearerForRequest(5000) == "their-access");
	assert(calls == 0);
	assert(sess.token.refreshToken == "rotated-refresh");
}

unittest  // a session refreshes with the rotated refresh token another process saved
{
	auto store = new MemoryTokenStore();
	StoredToken mine;
	mine.accessToken = "old-access";
	mine.refreshToken = "stale-refresh";
	mine.expiresAt = 1000;
	StoredToken theirs;
	theirs.accessToken = "their-access";
	theirs.refreshToken = "rotated-refresh";
	theirs.expiresAt = 4000;
	store.save("https://mcp.example.com", theirs);

	string seenRefresh;
	TokenSet delegate(string) @safe refreshFn = (string rt) @safe {
		seenRefresh = rt;
		TokenSet ts;
		ts.accessToken = "new-access";
		ts.expiresIn = 3600;
		return ts;
	};
	auto sess = new OAuthSession("https://mcp.example.com", mine, store, refreshFn);
	assert(sess.bearerForRequest(5000) == "new-access");
	assert(seenRefresh == "rotated-refresh");
}

unittest  // a session ignores a stored token bound to another client
{
	auto store = new MemoryTokenStore();
	StoredToken mine;
	mine.accessToken = "old-access";
	mine.refreshToken = "my-refresh";
	mine.expiresAt = 1000;
	mine.clientId = "client-a";
	StoredToken theirs = mine;
	theirs.accessToken = "their-access";
	theirs.refreshToken = "their-refresh";
	theirs.expiresAt = 10_000;
	theirs.clientId = "client-b";
	store.save("https://mcp.example.com", theirs);

	string seenRefresh;
	TokenSet delegate(string) @safe refreshFn = (string rt) @safe {
		seenRefresh = rt;
		TokenSet ts;
		ts.accessToken = "new-access";
		ts.expiresIn = 3600;
		return ts;
	};
	auto sess = new OAuthSession("https://mcp.example.com", mine, store, refreshFn);
	assert(sess.bearerForRequest(5000) == "new-access");
	assert(seenRefresh == "my-refresh");
}

unittest  // an invalid_grant refresh drops the dead refresh token so later requests fail fast
{
	import std.exception : assertThrown;

	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "old-access";
	t.refreshToken = "dead-refresh";
	t.expiresAt = 1000;
	store.save("https://mcp.example.com", t);

	int calls;
	TokenSet delegate(string) @safe refreshFn = (string rt) @safe {
		++calls;
		auto data = Json.emptyObject;
		data["error"] = "invalid_grant";
		throw invalidRequest("token endpoint returned HTTP 400", data);
	};
	auto sess = new OAuthSession("https://mcp.example.com", t, store, refreshFn);
	assertThrown(sess.bearerForRequest(5000));
	assertThrown(sess.bearerForRequest(5001));
	assert(calls == 1, "a refresh token the AS rejected is never presented again");
	assert(store.load("https://mcp.example.com").refreshToken.length == 0);
}

unittest  // a transient refresh failure keeps the refresh token for a retry
{
	import std.exception : assertThrown;

	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "old-access";
	t.refreshToken = "good-refresh";
	t.expiresAt = 1000;

	int calls;
	TokenSet delegate(string) @safe refreshFn = (string rt) @safe {
		if (++calls == 1)
			throw new Exception("network down");
		TokenSet ts;
		ts.accessToken = "new-access";
		ts.expiresIn = 3600;
		return ts;
	};
	auto sess = new OAuthSession("https://mcp.example.com", t, store, refreshFn);
	assertThrown(sess.bearerForRequest(5000));
	assert(sess.bearerForRequest(5001) == "new-access");
}

unittest  // concurrent bearerForRequest calls share a single refresh (rotating refresh tokens)
{
	import core.time : msecs;
	import vibe.core.core : runTask, sleep;

	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "old-access";
	t.refreshToken = "single-use-refresh";
	t.expiresAt = 1000;

	int calls;
	TokenSet delegate(string) @safe refreshFn = (string rt) @safe {
		++calls;
		// A rotating AS rejects a second use of the same refresh token.
		assert(rt == "single-use-refresh", "refresh token replayed");
		sleep(30.msecs); // the token request yields to other tasks
		TokenSet ts;
		ts.accessToken = "new-access";
		ts.expiresIn = 3600;
		ts.refreshToken = "rotated-refresh";
		return ts;
	};
	auto sess = new OAuthSession("https://mcp.example.com", t, store, refreshFn);

	string a, b;
	auto ta = runTask(() nothrow{
		try
			a = sess.bearerForRequest(5000);
		catch (Exception)
		{
		}
	});
	auto tb = runTask(() nothrow{
		try
			b = sess.bearerForRequest(5000);
		catch (Exception)
		{
		}
	});
	ta.join();
	tb.join();

	assert(calls == 1);
	assert(a == "new-access" && b == "new-access");
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

unittest  // isLoopbackCallbackPath accepts the exact callback path
{
	assert(isLoopbackCallbackPath("/callback", "/callback"));
}

unittest  // isLoopbackCallbackPath rejects a different path even when it carries a code= parameter
{
	// A wrong-path request with code= must not be treated as a valid callback —
	// a local process racing the real AS redirect could otherwise abort the flow
	// by setting done=true with a state_mismatch error before the genuine redirect.
	assert(!isLoopbackCallbackPath("/evil", "/callback"));
}

unittest  // isLoopbackCallbackPath rejects a different path even with an error= parameter
{
	assert(!isLoopbackCallbackPath("/favicon.ico", "/callback"));
}

unittest  // isLoopbackCallbackPath matches a callback path configured without a leading slash
{
	assert(isLoopbackCallbackPath("/callback", "callback"));
}

unittest  // isLoopbackCallbackPath matches the default path when the configured path is empty
{
	assert(isLoopbackCallbackPath("/callback", ""));
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

version (Posix) unittest  // FileTokenStore leaves the permissions of an existing directory it did not create alone
{
	import std.file : tempDir, mkdirRecurse, rmdirRecurse, getAttributes, setAttributes;
	import std.path : buildPath;
	import std.conv : octal, to;
	import core.sys.posix.sys.stat : S_IRWXU, S_IRWXG, S_IRWXO;
	import std.datetime.systime : Clock;

	// e.g. a token file placed directly in the user's home directory.
	auto root = buildPath(tempDir, "mcp-login-owndir-" ~ Clock.currTime().toUnixTime().to!string);
	mkdirRecurse(root);
	scope (exit)
		() @trusted { rmdirRecurse(root); }();
	() @trusted { setAttributes(root, octal!755); }();

	auto store = new FileTokenStore(buildPath(root, "tokens.json"));
	StoredToken t;
	t.accessToken = "secret-access";
	store.save("https://mcp.example.com", t);

	assert((getAttributes(root) & (S_IRWXU | S_IRWXG | S_IRWXO)) == octal!755,
			"an existing directory must not be chmod-ed by the token store");
}

version (Posix) unittest  // FileTokenStore makes a directory it creates owner-only
{
	import std.file : tempDir, mkdirRecurse, rmdirRecurse, getAttributes;
	import std.path : buildPath;
	import std.conv : to;
	import core.sys.posix.sys.stat : S_IRWXU, S_IRWXG, S_IRWXO;
	import std.datetime.systime : Clock;

	auto root = buildPath(tempDir, "mcp-login-newdir-" ~ Clock.currTime().toUnixTime().to!string);
	mkdirRecurse(root);
	scope (exit)
		() @trusted { rmdirRecurse(root); }();

	auto dir = buildPath(root, "dlang-mcp");
	auto store = new FileTokenStore(buildPath(dir, "tokens.json"));
	StoredToken t;
	t.accessToken = "secret-access";
	store.save("https://mcp.example.com", t);

	assert((getAttributes(dir) & (S_IRWXU | S_IRWXG | S_IRWXO)) == S_IRWXU);
}

version (Windows) unittest  // FileTokenStore restricts the token file to the current user (no inherited broad ACEs)
{
	import std.file : tempDir, mkdirRecurse, rmdirRecurse, exists;
	import std.path : buildPath;
	import std.conv : to;
	import std.process : execute;
	import std.algorithm.searching : canFind;
	import std.datetime.systime : Clock;

	auto root = buildPath(tempDir, "mcp-login-acl-" ~ Clock.currTime().toUnixTime().to!string);
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
	// After `/inheritance:r` the inherited broad ACEs the temp directory contributes
	// (Everyone / BUILTIN\Users) must be gone, so the plaintext token file is not
	// readable by other accounts -- the Windows analogue of POSIX 0600.
	auto res = () @trusted { return execute(["icacls", file]); }();
	assert(res.status == 0, "icacls failed: " ~ res.output);
	assert(!res.output.canFind("Everyone"), "token file grants Everyone: " ~ res.output);
	assert(!res.output.canFind("BUILTIN\\Users"), "token file grants BUILTIN\\Users: " ~ res.output);
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
		foreach (f; [bare, bare ~ ".lock"])
			if (f.exists)
				remove(f);
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

version (Posix) unittest  // openSystemBrowser leaves no direct child process behind
{
	// openSystemBrowser must spawn the launcher with Config.detached: the
	// launcher then runs as a grandchild and spawnProcess reaps the intermediate
	// fork itself, so the call leaves this process no new direct child. Without
	// it the discarded launcher stays a direct child, running or as a zombie.
	//
	// The check compares this process's direct children before and after the
	// call, so children other tests leave behind (running, or exited and
	// unreaped) neither fail it nor get reaped by it, and it does not depend on
	// how quickly the launcher exits.
	import std.algorithm : canFind, filter;
	import std.array : array;
	import std.process : spawnProcess, wait;

	// An unrelated child that has exited but is not yet reaped, as another test
	// can leave behind.
	auto unrelated = spawnProcess(["true"]);
	scope (exit)
		wait(unrelated);

	const before = directChildPids();
	cast(void) openSystemBrowser("mcp-sdk-test-zombie://localhost/verify-detach");
	const added = directChildPids().filter!(p => !before.canFind(p)).array;

	assert(added.length == 0,
			"openSystemBrowser left a direct child process; it must spawn with Config.detached");
}

/// The PIDs of this process's direct children, zombies included (`pgrep -P`
/// omits zombies on macOS, so `ps` is used), excluding the `ps` run itself.
version (Posix) version (unittest) private int[] directChildPids() @trusted
{
	import core.sys.posix.unistd : getpid;
	import std.algorithm : filter, splitter;
	import std.array : array;
	import std.conv : to;
	import std.process : pipeProcess, Redirect, wait;
	import std.string : strip;

	auto ps = pipeProcess(["ps", "-A", "-o", "pid=,ppid="], Redirect.stdout);
	const psPid = ps.pid.processID;
	const output = ps.stdout.byLineCopy.array;
	wait(ps.pid);

	const self = getpid();
	int[] pids;
	foreach (line; output)
	{
		auto cols = line.strip.splitter(' ').filter!(c => c.length);
		const pid = cols.front.to!int;
		cols.popFront();
		if (cols.front.to!int == self && pid != psPid)
			pids ~= pid;
	}
	return pids;
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

unittest  // the cache fast-path carries the persisted DCR client_secret
{
	OAuthLogin opts; // DCR: no static client credentials
	StoredToken cached;
	cached.accessToken = "valid";
	cached.clientId = "abc123";
	cached.clientSecret = "dcr-secret";
	auto rc = cacheHitClient(cached, opts);
	assert(rc.clientId == "abc123");
	assert(rc.clientSecret == "dcr-secret");
}

unittest  // the cache fast-path uses the configured secret for the pre-registered client
{
	OAuthLogin opts;
	opts.clientId = "pre-reg";
	opts.clientSecret = "configured";
	StoredToken cached;
	cached.accessToken = "valid";
	cached.clientId = "pre-reg";
	auto rc = cacheHitClient(cached, opts);
	assert(rc.clientSecret == "configured");
}

unittest  // the configured pre-registered secret is not persisted with the token
{
	OAuthLogin opts;
	opts.clientId = "pre-reg";
	opts.clientSecret = "configured";
	assert(persistedClient(RegisteredClient("pre-reg", "configured"), opts).clientSecret.length == 0);
	assert(persistedClient(RegisteredClient("dcr-id", "dcr-secret"), opts)
			.clientSecret == "dcr-secret");
}

unittest  // StoredToken persists the DCR client_secret and its expiry across JSON round-trips
{
	StoredToken t;
	t.accessToken = "tok";
	t.setClient(RegisteredClient("abc123", "dcr-secret", 1_900_000_000));
	auto back = StoredToken.fromJson(t.toJson());
	assert(back.clientId == "abc123");
	assert(back.clientSecret == "dcr-secret");
	assert(back.clientSecretExpiresAt == 1_900_000_000);
}

unittest  // a stored client secret past its client_secret_expires_at is reported expired
{
	StoredToken t;
	t.setClient(RegisteredClient("abc123", "dcr-secret", 100));
	assert(t.clientSecretExpired(100));
	assert(!t.clientSecretExpired(99));
	t.clientSecretExpiresAt = 0; // RFC 7591: 0 means the secret never expires
	assert(!t.clientSecretExpired(long.max));
}

unittest  // StoredToken persists the registered client_id across JSON round-trips
{
	StoredToken t;
	t.accessToken = "tok";
	t.clientId = "abc123";
	auto back = StoredToken.fromJson(t.toJson());
	assert(back.clientId == "abc123");
}

unittest  // StoredToken persists the issuing authorization server across JSON round-trips
{
	StoredToken t;
	t.accessToken = "tok";
	t.issuer = "https://as.example.com";
	assert(StoredToken.fromJson(t.toJson()).issuer == "https://as.example.com");
}

version (unittest)
{
	import vibe.http.server : HTTPListener;

	/// A loopback MCP authorization setup for `useOAuth`: PRM naming the
	/// loopback AS, AS metadata (issuer = `base`), DCR, and a token endpoint
	/// that counts every refresh-token grant it receives.
	private final class IssuerTestAuthServer
	{
		HTTPListener listener;
		string base;
		int refreshCalls;
		bool failRefresh;
		/// The PRM `resource`; empty selects `base ~ "/mcp"`.
		string prmResource;
		/// The PRM `scopes_supported`; empty omits it.
		string[] prmScopes;

		void stop() @trusted
		{
			listener.stopListening();
		}
	}

	/// ditto
	private IssuerTestAuthServer startIssuerTestAuthServer() @trusted
	{
		import std.algorithm : canFind;
		import std.conv : to;
		import vibe.http.server : HTTPServerRequest, HTTPServerResponse,
			HTTPServerSettings, listenHTTP;

		auto srv = new IssuerTestAuthServer;
		auto settings = new HTTPServerSettings;
		settings.bindAddresses = ["127.0.0.1"];
		settings.port = 0;
		srv.listener = listenHTTP(settings, (scope HTTPServerRequest req,
				scope HTTPServerResponse res) @safe {
			const b = srv.base;
			if (req.path.canFind("oauth-protected-resource"))
			{
				auto prm = Json.emptyObject;
				prm["resource"] = srv.prmResource.length ? srv.prmResource : b ~ "/mcp";
				prm["authorization_servers"] = Json([Json(b)]);
				if (srv.prmScopes.length)
				{
					Json[] scopes;
					foreach (sc; srv.prmScopes)
						scopes ~= Json(sc);
					prm["scopes_supported"] = Json(scopes);
				}
				res.writeBody(prm.toString(), "application/json");
			}
			else if (req.path.canFind("authorization-server"))
				res.writeBody(`{"issuer":"` ~ b ~ `","authorization_endpoint":"` ~ b
					~ `/authorize","token_endpoint":"` ~ b ~ `/token","registration_endpoint":"`
					~ b ~ `/register","code_challenge_methods_supported":["S256"]}`,
					"application/json");
			else if (req.path == "/register")
				res.writeBody(
					`{"client_id":"fresh-id","redirect_uris":["http://localhost:8765/callback"]}`,
					"application/json");
			else if (req.path == "/token")
			{
				if (req.form.get("grant_type", "") == "refresh_token")
				{
					srv.refreshCalls++;
					if (srv.failRefresh)
					{
						res.statusCode = 400;
						res.writeBody(`{"error":"invalid_grant"}`, "application/json");
						return;
					}
				}
				res.writeBody(
					`{"access_token":"new-access","token_type":"Bearer","expires_in":3600}`,
					"application/json");
			}
			else
			{
				res.statusCode = 404;
				res.writeBody("", "text/plain");
			}
		});
		srv.base = "http://127.0.0.1:" ~ srv.listener.bindAddresses[0].port.to!string;
		return srv;
	}
}

unittest  // useOAuth requests the resource the protected-resource metadata names
{
	import core.time : msecs;
	import std.algorithm : canFind;
	import std.exception : assertThrown;
	import std.uri : encodeComponent;

	auto srv = startIssuerTestAuthServer();
	scope (exit)
		srv.stop();
	// The server protects its whole origin; the MCP endpoint is a path beneath it.
	srv.prmResource = srv.base;
	const endpoint = srv.base ~ "/mcp";

	string authUrl;
	OAuthLogin opts;
	opts.store = new MemoryTokenStore();
	opts.callbackTimeout = 50.msecs;
	opts.openBrowser = (string url) @safe { authUrl = url; };

	assertThrown(useOAuth(McpClient.http(endpoint), endpoint, opts));
	assert((authUrl ~ "&").canFind("resource=" ~ encodeComponent(srv.base) ~ "&"), authUrl);
}

unittest  // useOAuth never sends a refresh token to an authorization server other than its issuer
{
	import core.time : msecs;
	import std.exception : assertThrown;
	import mcp.auth.oauth : canonicalResourceUri;

	auto srv = startIssuerTestAuthServer();
	scope (exit)
		srv.stop();
	const endpoint = srv.base ~ "/mcp";
	const resource = canonicalResourceUri(endpoint);

	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "old";
	t.refreshToken = "rt-from-old-as";
	t.clientId = "abc123";
	t.expiresAt = 1; // expired, so a refresh would be attempted
	t.resource = resource;
	t.issuer = "https://old-as.example.com";
	store.save(resource, t);

	OAuthLogin opts;
	opts.store = store;
	opts.callbackTimeout = 50.msecs;
	opts.openBrowser = (string url) @safe {};

	// The interactive flow runs (and times out) instead of the refresh.
	assertThrown(useOAuth(McpClient.http(endpoint), endpoint, opts));
	assert(srv.refreshCalls == 0, "a refresh token must only ever go to the AS that issued it");
}

unittest  // useOAuth does not reuse a cached access token issued by another authorization server
{
	import core.time : msecs;
	import std.exception : assertThrown;
	import mcp.auth.oauth : canonicalResourceUri;

	auto srv = startIssuerTestAuthServer();
	scope (exit)
		srv.stop();
	const endpoint = srv.base ~ "/mcp";
	const resource = canonicalResourceUri(endpoint);

	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "token-for-old-as";
	t.resource = resource;
	t.issuer = "https://old-as.example.com";
	store.save(resource, t);

	OAuthLogin opts;
	opts.store = store;
	opts.callbackTimeout = 50.msecs;
	opts.openBrowser = (string url) @safe {};

	assertThrown(useOAuth(McpClient.http(endpoint), endpoint, opts));
}

unittest  // useOAuth treats a stored token that records no issuer as absent
{
	import core.time : msecs;
	import std.exception : assertThrown;
	import mcp.auth.oauth : canonicalResourceUri;

	auto srv = startIssuerTestAuthServer();
	scope (exit)
		srv.stop();
	const endpoint = srv.base ~ "/mcp";
	const resource = canonicalResourceUri(endpoint);

	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "unbound";
	t.refreshToken = "rt-unbound";
	t.clientId = "abc123";
	t.expiresAt = 1;
	t.resource = resource;
	store.save(resource, t);

	OAuthLogin opts;
	opts.store = store;
	opts.callbackTimeout = 50.msecs;
	opts.openBrowser = (string url) @safe {};

	assertThrown(useOAuth(McpClient.http(endpoint), endpoint, opts));
	assert(srv.refreshCalls == 0);
}

unittest  // useOAuth reuses a cached token whose issuer matches the discovered authorization server
{
	import mcp.auth.oauth : canonicalResourceUri;

	auto srv = startIssuerTestAuthServer();
	scope (exit)
		srv.stop();
	const endpoint = srv.base ~ "/mcp";
	const resource = canonicalResourceUri(endpoint);

	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "still-valid";
	t.resource = resource;
	t.issuer = srv.base;
	store.save(resource, t);

	OAuthLogin opts;
	opts.store = store;
	opts.openBrowser = (string url) @safe {
		assert(0, "no interactive login expected");
	};

	assert(useOAuth(McpClient.http(endpoint), endpoint, opts).token.accessToken == "still-valid");
}

unittest  // useOAuth re-authorizes instead of reusing a valid cached token that lacks a requested scope
{
	import core.time : msecs;
	import std.exception : assertThrown;
	import mcp.auth.oauth : canonicalResourceUri;

	auto srv = startIssuerTestAuthServer();
	scope (exit)
		srv.stop();
	const endpoint = srv.base ~ "/mcp";
	const resource = canonicalResourceUri(endpoint);

	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "narrow";
	t.scope_ = "files:read";
	t.resource = resource;
	t.issuer = srv.base;
	store.save(resource, t);

	OAuthLogin opts;
	opts.store = store;
	opts.wwwAuthenticate = `Bearer error="insufficient_scope", scope="files:read files:write"`;
	opts.callbackTimeout = 50.msecs;
	bool browserOpened;
	opts.openBrowser = (string url) @safe { browserOpened = true; };

	assertThrown(useOAuth(McpClient.http(endpoint), endpoint, opts));
	assert(browserOpened, "a step-up must run a new authorization");
}

unittest  // a failed cached refresh is logged before useOAuth falls back to the browser
{
	import core.time : msecs;
	import std.algorithm : any, canFind;
	import std.exception : assertThrown;
	import vibe.core.log : deregisterLogger, LogLevel, Logger, LogLine, registerLogger;
	import mcp.auth.oauth : canonicalResourceUri;

	static final class CaptureLogger : Logger
	{
		string[] lines;
		this() @safe
		{
			minLevel = LogLevel.warn;
		}

		override void log(ref LogLine line) @safe
		{
			lines ~= line.text;
		}
	}

	auto logger = new CaptureLogger;
	auto shared_ = () @trusted { return cast(shared) logger; }();
	() @trusted { registerLogger(shared_); }();
	scope (exit)
		() @trusted { deregisterLogger(shared_); }();

	auto srv = startIssuerTestAuthServer();
	scope (exit)
		srv.stop();
	srv.failRefresh = true;
	const endpoint = srv.base ~ "/mcp";
	const resource = canonicalResourceUri(endpoint);

	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "old";
	t.refreshToken = "rt";
	t.clientId = "abc123";
	t.expiresAt = 1;
	t.resource = resource;
	t.issuer = srv.base;
	store.save(resource, t);

	OAuthLogin opts;
	opts.store = store;
	opts.callbackTimeout = 50.msecs;
	opts.openBrowser = (string url) @safe {};

	assertThrown(useOAuth(McpClient.http(endpoint), endpoint, opts));
	assert(srv.refreshCalls == 1);
	auto lines = () @trusted { return (cast() logger).lines; }();
	assert(lines.any!(l => l.canFind("refresh")), "a failed refresh must not be silent");
}

unittest  // useOAuth does not refresh a cached token that lacks a requested scope
{
	import core.time : msecs;
	import std.exception : assertThrown;
	import mcp.auth.oauth : canonicalResourceUri;

	auto srv = startIssuerTestAuthServer();
	scope (exit)
		srv.stop();
	const endpoint = srv.base ~ "/mcp";
	const resource = canonicalResourceUri(endpoint);

	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "narrow";
	t.refreshToken = "rt";
	t.clientId = "abc123";
	t.expiresAt = 1;
	t.scope_ = "files:read";
	t.resource = resource;
	t.issuer = srv.base;
	store.save(resource, t);

	OAuthLogin opts;
	opts.store = store;
	opts.scopes = ["files:read", "files:write"];
	opts.callbackTimeout = 50.msecs;
	opts.openBrowser = (string url) @safe {};

	assertThrown(useOAuth(McpClient.http(endpoint), endpoint, opts));
	assert(srv.refreshCalls == 0, "a refresh cannot widen the granted scope");
}

unittest  // useOAuth reuses a cached token whose scope covers the requested scopes
{
	import mcp.auth.oauth : canonicalResourceUri;

	auto srv = startIssuerTestAuthServer();
	scope (exit)
		srv.stop();
	const endpoint = srv.base ~ "/mcp";
	const resource = canonicalResourceUri(endpoint);

	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "wide";
	t.scope_ = "files:write files:read";
	t.resource = resource;
	t.issuer = srv.base;
	store.save(resource, t);

	OAuthLogin opts;
	opts.store = store;
	opts.scopes = ["files:read"];
	opts.openBrowser = (string url) @safe {
		assert(0, "no interactive login expected");
	};

	assert(useOAuth(McpClient.http(endpoint), endpoint, opts).token.accessToken == "wide");
}

unittest  // useOAuth reuses a cached token granted a subset of the discovered scopes_supported
{
	import mcp.auth.oauth : canonicalResourceUri;

	auto srv = startIssuerTestAuthServer();
	scope (exit)
		srv.stop();
	srv.prmScopes = ["files:read", "files:write"];
	const endpoint = srv.base ~ "/mcp";
	const resource = canonicalResourceUri(endpoint);

	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "subset";
	t.scope_ = "files:read";
	t.resource = resource;
	t.issuer = srv.base;
	store.save(resource, t);

	OAuthLogin opts;
	opts.store = store;
	opts.openBrowser = (string url) @safe {
		assert(0, "no interactive login expected");
	};

	assert(useOAuth(McpClient.http(endpoint), endpoint, opts).token.accessToken == "subset");
}

unittest  // useOAuth does not reuse a cached token lacking a step-up challenge's scope
{
	import core.time : msecs;
	import std.exception : assertThrown;
	import mcp.auth.oauth : canonicalResourceUri;

	auto srv = startIssuerTestAuthServer();
	scope (exit)
		srv.stop();
	const endpoint = srv.base ~ "/mcp";
	const resource = canonicalResourceUri(endpoint);

	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "narrow";
	t.scope_ = "files:read";
	t.resource = resource;
	t.issuer = srv.base;
	store.save(resource, t);

	bool browserOpened;
	OAuthLogin opts;
	opts.store = store;
	opts.wwwAuthenticate = `Bearer error="insufficient_scope", scope="files:write"`;
	opts.callbackTimeout = 50.msecs;
	opts.openBrowser = (string url) @safe { browserOpened = true; };

	assertThrown(useOAuth(McpClient.http(endpoint), endpoint, opts));
	assert(browserOpened);
}

unittest  // a refresh response that omits scope keeps the previously granted scope
{
	StoredToken t;
	t.accessToken = "old";
	t.refreshToken = "rt";
	t.expiresAt = 1000;
	t.scope_ = "files:read";
	auto sess = new OAuthSession("https://mcp.example.com", t,
			new MemoryTokenStore(), (string rt) @safe {
		TokenSet ts;
		ts.accessToken = "new";
		return ts;
	});
	sess.bearerForRequest(5000);
	assert(sess.token.scope_ == "files:read");
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

unittest  // refreshing an expired token keeps the issuer it is bound to
{
	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "old";
	t.refreshToken = "rt";
	t.expiresAt = 1000;
	t.issuer = "https://as.example.com";

	TokenSet delegate(string) @safe refreshFn = (string rt) @safe {
		TokenSet ts;
		ts.accessToken = "new";
		ts.expiresIn = 3600;
		return ts;
	};
	auto sess = new OAuthSession("https://mcp.example.com", t, store, refreshFn);
	sess.bearerForRequest(5000);

	assert(store.load("https://mcp.example.com").issuer == "https://as.example.com");
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

		// redirect_uri looks like http://127.0.0.1:<port>/callback
		auto hostStart = redirectUri.indexOf("127.0.0.1:");
		assert(hostStart >= 0);
		auto rest = redirectUri[hostStart + "127.0.0.1:".length .. $];
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

unittest  // a callback with the wrong state is refused (400) and the flow keeps waiting for the real one
{
	import core.time : msecs, seconds;
	import std.string : indexOf;
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
	int forgedStatus;
	opts.openBrowser = (string url) @safe {
		auto redirectUri = extractQueryParam(url, "redirect_uri");
		auto rest = redirectUri[redirectUri.indexOf("127.0.0.1:") + "127.0.0.1:".length .. $];
		auto baseUrl = "http://127.0.0.1:" ~ rest[0 .. rest.indexOf('/')];
		() @trusted {
			runTask(() nothrow{
				try
				{
					// Any web page can make the browser hit the loopback callback; one
					// without the flow's state must not end the login.
					sleep(50.msecs);
					requestHTTP(baseUrl ~ "/callback?error=access_denied&state=forged", (scope req) {
					}, (scope res) {
						forgedStatus = res.statusCode;
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

	assert(forgedStatus == 400);
	assert(captured.ok, "the genuine callback must still be captured");
	assert(captured.code == "real-code");
}

version (Posix) unittest  // save() throws a typed error when the token directory cannot be created
{
	import std.file : tempDir, mkdirRecurse, rmdirRecurse, write;
	import std.path : buildPath;
	import std.conv : to;
	import std.datetime.systime : Clock;

	auto root = buildPath(tempDir, "mcp-login-mkdir-" ~ Clock.currTime().toUnixTime().to!string);
	mkdirRecurse(root);
	scope (exit)
		() @trusted { rmdirRecurse(root); }();

	// A regular file standing where the token file's parent directory must be, so
	// mkdirRecurse cannot create the directory.
	auto blocker = buildPath(root, "blocker");
	() @trusted { write(blocker, "x"); }();
	auto store = new FileTokenStore(buildPath(blocker, "tokens.json"));
	StoredToken t;
	t.accessToken = "secret";

	bool threw;
	try
		store.save("https://mcp.example.com", t);
	catch (McpException)
		threw = true;
	assert(threw,
			"save must surface a directory-creation failure rather than silently dropping the token");
}

version (Posix) @system unittest  // save() waits for the token file's lock, so concurrent writers never lose updates
{
	import core.atomic : atomicLoad, atomicStore;
	import core.sys.posix.fcntl : open, O_CREAT, O_RDWR;
	import core.sys.posix.unistd : close;
	import core.thread : Thread;
	import core.time : msecs;
	import std.conv : to;
	import std.datetime.systime : Clock;
	import std.file : tempDir, mkdirRecurse, rmdirRecurse;
	import std.path : buildPath;
	import std.string : toStringz;

	auto root = buildPath(tempDir, "mcp-login-lock-" ~ Clock.currTime().stdTime.to!string);
	mkdirRecurse(root);
	scope (exit)
		() @trusted { rmdirRecurse(root); }();
	auto file = buildPath(root, "tokens.json");

	// Another process holds the lock mid read-modify-write.
	const fd = () @trusted {
		return open((file ~ ".lock").toStringz, O_CREAT | O_RDWR, 384);
	}();
	assert(fd >= 0);
	assert(() @trusted { return flock(fd, LOCK_EX); }() == 0);

	shared bool saved;
	auto writer = new Thread(() {
		auto store = new FileTokenStore(file);
		StoredToken t;
		t.accessToken = "from-writer";
		store.save("https://b.example.com", t);
		atomicStore(saved, true);
	});
	writer.start();
	Thread.sleep(300.msecs);
	assert(!atomicLoad(saved), "save must wait for the lock");

	assert(() @trusted { return flock(fd, LOCK_UN); }() == 0);
	assert(() @trusted { return close(fd); }() == 0);
	writer.join();
	assert(atomicLoad(saved));
	assert(new FileTokenStore(file).load("https://b.example.com").accessToken == "from-writer");
}

version (Posix) unittest  // save() backs up an unparseable token file instead of silently destroying it
{
	import std.file : tempDir, mkdirRecurse, rmdirRecurse, write, readText, exists;
	import std.path : buildPath;
	import std.conv : to;
	import std.datetime.systime : Clock;

	auto root = buildPath(tempDir, "mcp-login-corrupt-" ~ Clock.currTime().toUnixTime().to!string);
	mkdirRecurse(root);
	scope (exit)
		() @trusted { rmdirRecurse(root); }();

	auto file = buildPath(root, "tokens.json");
	() @trusted { write(file, "{ this is not valid json"); }();

	auto store = new FileTokenStore(file);
	StoredToken t;
	t.accessToken = "new-secret";
	store.save("https://mcp.example.com", t);

	// The corrupt file's bytes are preserved alongside, not overwritten away.
	assert(exists(file ~ "~"));
	assert((() @trusted => readText(file ~ "~"))() == "{ this is not valid json");
	// The fresh store holds the new token.
	assert(store.load("https://mcp.example.com").accessToken == "new-secret");
}

version (Posix) unittest  // stillGroupOrOtherAccessible flags any lingering group/other permission bit
{
	import core.sys.posix.sys.stat : S_IRUSR, S_IWUSR, S_IRGRP, S_IROTH;

	assert(!FileTokenStore.stillGroupOrOtherAccessible(S_IRUSR | S_IWUSR));
	assert(FileTokenStore.stillGroupOrOtherAccessible(S_IRUSR | S_IWUSR | S_IRGRP));
	assert(FileTokenStore.stillGroupOrOtherAccessible(S_IRUSR | S_IWUSR | S_IROTH));
}

unittest  // browserLaunchCommand on Windows hands the URL to rundll32, never to a cmd shell
{
	const url = "https://idp.example/authorize?client_id=c&state=s&code_challenge=x";
	const cmd = browserLaunchCommand(url, LauncherPlatform.windows);
	assert(cmd == ["rundll32", "url.dll,FileProtocolHandler", url]);
}

unittest  // browserLaunchCommand uses open on macOS and xdg-open elsewhere, URL as one argument
{
	const url = "https://idp.example/authorize?a=1&b=2";
	assert(browserLaunchCommand(url, LauncherPlatform.macOS) == ["open", url]);
	assert(browserLaunchCommand(url, LauncherPlatform.other) == [
		"xdg-open", url
	]);
}

unittest  // openSystemBrowser reports a launcher failure instead of swallowing it into a hang
{
	bool called;
	const ok = openSystemBrowser("https://example.com/authz?state=s", (string[] cmd) @safe {
		called = true;
		throw new Exception("no launcher");
	});
	assert(called);
	assert(!ok, "a launcher failure must be surfaced, not swallowed");
}

unittest  // openSystemBrowser reports success and passes the URL to the launcher
{
	string[] seen;
	const ok = openSystemBrowser("https://example.com/x", (string[] cmd) @safe {
		seen = cmd;
	});
	assert(ok);
	assert(seen.length && seen[$ - 1] == "https://example.com/x");
}

unittest  // useOAuth refreshes under the stored client_id before registering anything
{
	import core.time : seconds;
	import std.algorithm : canFind;
	import vibe.http.server : HTTPServerSettings, HTTPServerRequest,
		HTTPServerResponse, HTTPListener, listenHTTP;
	import mcp.auth.oauth : canonicalResourceUri;

	// A loopback AS: PRM + metadata for discovery, a /register that must not be
	// hit, and a /token that only honours the refresh token under the client
	// that obtained it (refresh tokens are bound to their client, RFC 6749 §6).
	int registerCalls;
	HTTPListener listener;
	string base;
	auto settings = new HTTPServerSettings;
	settings.bindAddresses = ["127.0.0.1"];
	settings.port = 0;
	listener = () @trusted {
		return listenHTTP(settings, (scope HTTPServerRequest req, scope HTTPServerResponse res) @safe {
			if (req.path.canFind("oauth-protected-resource"))
				res.writeBody(
					`{"resource":"` ~ base ~ `/mcp","authorization_servers":["` ~ base ~ `"]}`,
					"application/json");
			else if (req.path.canFind("authorization-server"))
				res.writeBody(`{"issuer":"http://` ~ req.host ~ `","authorization_endpoint":"` ~ base
					~ `/authorize","token_endpoint":"` ~ base ~ `/token","registration_endpoint":"`
					~ base ~ `/register","code_challenge_methods_supported":["S256"]}`,
					"application/json");
			else if (req.path == "/register")
			{
				registerCalls++;
				res.writeBody(
					`{"client_id":"fresh-id","redirect_uris":["http://localhost:8765/callback"]}`,
					"application/json");
			}
			else if (req.path == "/token")
			{
				if (req.form.get("grant_type", "") == "refresh_token"
					&& req.form.get("refresh_token", "") == "rt"
					&& req.form.get("client_id", "") == "abc123")
					res.writeBody(`{"access_token":"new-access","token_type":"Bearer","expires_in":3600,"refresh_token":"rt2"}`,
						"application/json");
				else
				{
					res.statusCode = 400;
					res.writeBody(`{"error":"invalid_grant"}`, "application/json");
				}
			}
			else
			{
				res.statusCode = 404;
				res.writeBody("", "text/plain");
			}
		});
	}();
	scope (exit)
		() @trusted { listener.stopListening(); }();
	import std.conv : to;

	base = "http://127.0.0.1:" ~ listener.bindAddresses[0].port.to!string;
	const endpoint = base ~ "/mcp";
	const resource = canonicalResourceUri(endpoint);

	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "old";
	t.refreshToken = "rt";
	t.clientId = "abc123"; // registered on the first run and persisted
	t.expiresAt = 1; // long expired
	t.resource = resource;
	t.issuer = base; // issued by this AS
	store.save(resource, t);

	OAuthLogin opts;
	opts.store = store;
	opts.callbackTimeout = 1.seconds;
	bool browserOpened;
	opts.openBrowser = (string url) @safe { browserOpened = true; };

	auto client = McpClient.http(endpoint);
	auto sess = useOAuth(client, endpoint, opts);
	assert(registerCalls == 0, "a stored refresh token must be tried before re-registering");
	assert(!browserOpened);
	assert(sess.token.accessToken == "new-access");
	assert(store.load(resource).clientId == "abc123");
	assert(store.load(resource).refreshToken == "rt2");
}

unittest  // the loopback flow completes when invoked from inside a vibe task
{
	import core.time : msecs, seconds;
	import std.datetime.stopwatch : StopWatch, AutoStart;
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
	opts.openBrowser = (string url) @safe {
		auto redirectUri = extractQueryParam(url, "redirect_uri");
		import std.string : indexOf;

		auto hostStart = redirectUri.indexOf("127.0.0.1:");
		assert(hostStart >= 0);
		auto rest = redirectUri[hostStart + "127.0.0.1:".length .. $];
		auto slash = rest.indexOf('/');
		auto baseUrl = "http://127.0.0.1:" ~ (slash >= 0 ? rest[0 .. slash] : rest);
		() @trusted {
			runTask(() nothrow{
				try
				{
					sleep(50.msecs);
					requestHTTP(baseUrl ~ "/callback?code=in-task-code&state=state-xyz", (scope req) {
					}, (scope res) { res.dropBody(); });
				}
				catch (Exception)
				{
				}
			});
		}();
	};

	// Hosts such as a worker loop call the login from a task; the wait must
	// yield to that loop rather than nest an event loop (which asserts).
	bool finished;
	LoopbackCapture captured;
	() @trusted {
		runTask(() nothrow{
			try
				captured = runBrowserLoopbackFlow(oauth, as_, rc, pkce, opts, "state-xyz");
			catch (Exception)
			{
			}
			finished = true;
		});
	}();
	auto sw = StopWatch(AutoStart.yes);
	while (!finished && sw.peek < 8.seconds)
		sleep(10.msecs);
	assert(finished, "the in-task loopback flow never completed");
	assert(captured.ok);
	assert(captured.code == "in-task-code");
}

unittest  // the client is registered with the redirect URI the listener actually bound
{
	import core.time : msecs, seconds;
	import vibe.core.core : runTask, sleep;
	import vibe.http.client : requestHTTP;

	auto oauth = new OAuthClient();
	oauth.resource = "https://mcp.example.com/mcp";
	AuthorizationServerMetadata as_;
	as_.authorizationEndpoint = "https://as.example.com/authorize";
	as_.codeChallengeMethodsSupported = ["S256"];
	auto pkce = generatePkce();

	OAuthLogin opts;
	opts.callbackTimeout = 5.seconds;
	string registeredWith;
	string openedWith;
	bool registeredBeforeOpen;
	opts.openBrowser = (string url) @safe {
		openedWith = extractQueryParam(url, "redirect_uri");
		registeredBeforeOpen = registeredWith.length > 0;
		import std.string : indexOf;

		auto hostStart = openedWith.indexOf("127.0.0.1:");
		assert(hostStart >= 0);
		auto rest = openedWith[hostStart + "127.0.0.1:".length .. $];
		auto slash = rest.indexOf('/');
		auto baseUrl = "http://127.0.0.1:" ~ (slash >= 0 ? rest[0 .. slash] : rest);
		() @trusted {
			runTask(() nothrow{
				try
				{
					sleep(50.msecs);
					requestHTTP(baseUrl ~ "/callback?code=c&state=state-xyz", (scope req) {
					}, (scope res) { res.dropBody(); });
				}
				catch (Exception)
				{
				}
			});
		}();
	};

	RegisteredClient rc;
	auto captured = runBrowserLoopbackFlow(oauth, as_, (string redirectUri) @safe {
		registeredWith = redirectUri;
		return RegisteredClient("registered-id", "");
	}, rc, pkce, opts, "state-xyz");

	assert(captured.ok);
	assert(rc.clientId == "registered-id");
	assert(registeredBeforeOpen, "registration must precede the browser hand-off");
	assert(registeredWith == openedWith,
			"registered redirect_uri must match the authorization request");
	assert(registeredWith == oauth.redirectUri);
}

version (unittest)
{
	/// A loopback MCP server that answers `initialize` and accepts `tools/list`
	/// only with the bearer `accepted`, answering any other with a 401
	/// `invalid_token` challenge. Records the `Authorization` header of every
	/// `tools/list`.
	private final class RejectingMcpServer
	{
		import vibe.http.server : HTTPListener;

		HTTPListener listener;
		string endpoint;
		string accepted;
		string[] toolsAuth;

		void stop() @trusted
		{
			listener.stopListening();
		}
	}

	/// ditto
	private RejectingMcpServer startRejectingMcpServer(string accepted) @trusted
	{
		import std.conv : to;
		import vibe.http.server : HTTPServerRequest, HTTPServerResponse,
			HTTPServerSettings, listenHTTP;
		import vibe.stream.operations : readAllUTF8;

		auto srv = new RejectingMcpServer;
		srv.accepted = accepted;
		auto settings = new HTTPServerSettings;
		settings.bindAddresses = ["127.0.0.1"];
		settings.port = 0;
		srv.listener = listenHTTP(settings, (scope HTTPServerRequest req,
				scope HTTPServerResponse res) @safe {
			auto j = parseJsonString(() @trusted {
				return req.bodyReader.readAllUTF8();
			}());
			if ("id" !in j)
			{
				res.statusCode = 202;
				res.writeBody("", "text/plain");
				return;
			}
			auto reply = Json.emptyObject;
			reply["jsonrpc"] = "2.0";
			reply["id"] = j["id"];
			if (j["method"].get!string == "initialize")
				reply["result"] = parseJsonString(`{"protocolVersion":"2025-11-25",`
					~ `"capabilities":{"tools":{}},"serverInfo":{"name":"fake","version":"1"}}`);
			else
			{
				const auth = req.headers.get("Authorization", "");
				srv.toolsAuth ~= auth;
				if (auth != "Bearer " ~ srv.accepted)
				{
					res.statusCode = 401;
					res.headers["WWW-Authenticate"] = `Bearer error="invalid_token"`;
					res.writeBody("", "text/plain");
					return;
				}
				reply["result"] = parseJsonString(`{"tools":[]}`);
			}
			res.writeBody(reply.toString(), "application/json");
		});
		srv.endpoint = "http://127.0.0.1:" ~ srv.listener.bindAddresses[0].port.to!string ~ "/mcp";
		return srv;
	}
}

unittest  // a 401 invalid_token replaces a token with no known expiry and retries the request once
{
	auto srv = startRejectingMcpServer("new-access");
	scope (exit)
		srv.stop();

	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "old-access";
	t.refreshToken = "the-refresh";
	auto sess = new OAuthSession(srv.endpoint, t, store, (string rt) @safe {
		TokenSet ts;
		ts.accessToken = "new-access";
		return ts;
	});
	auto client = McpClient.http(srv.endpoint);
	scope (exit)
		client.close();
	cast(void) attachSession(client, sess);
	client.initialize("2025-11-25");
	client.listTools();
	assert(srv.toolsAuth == ["Bearer old-access", "Bearer new-access"]);
	assert(store.load(srv.endpoint).accessToken == "new-access");
}

unittest  // a rejected token with no refresh token surfaces the server's 401 challenge
{
	import mcp.client.http_transport : HttpStatusException;

	auto srv = startRejectingMcpServer("never-sent");
	scope (exit)
		srv.stop();

	StoredToken t;
	t.accessToken = "old-access";
	auto sess = new OAuthSession(srv.endpoint, t, new MemoryTokenStore(), (string rt) @safe {
		assert(0, "no refresh token to present");
		return TokenSet.init;
	});
	auto client = McpClient.http(srv.endpoint);
	scope (exit)
		client.close();
	cast(void) attachSession(client, sess);
	client.initialize("2025-11-25");
	HttpStatusException failure;
	try
		client.listTools();
	catch (HttpStatusException e)
		failure = e;
	assert(failure !is null, "the caller needs the 401 and its challenge to re-authenticate");
	assert(failure.status == 401);
	assert(failure.wwwAuthenticate == `Bearer error="invalid_token"`);
	assert(srv.toolsAuth == ["Bearer old-access"], "nothing new to retry with");
}

unittest  // a refreshed token the server also rejects is not refreshed again on every request
{
	import mcp.client.http_transport : HttpStatusException;

	auto srv = startRejectingMcpServer("never-issued");
	scope (exit)
		srv.stop();

	auto store = new MemoryTokenStore();
	StoredToken t;
	t.accessToken = "old-access";
	t.refreshToken = "the-refresh";
	int refreshes;
	auto sess = new OAuthSession(srv.endpoint, t, store, (string rt) @safe {
		++refreshes;
		TokenSet ts;
		ts.accessToken = "new-access";
		return ts;
	});
	auto client = McpClient.http(srv.endpoint);
	scope (exit)
		client.close();
	cast(void) attachSession(client, sess);
	client.initialize("2025-11-25");
	foreach (_; 0 .. 3)
	{
		bool rejected;
		try
			client.listTools();
		catch (HttpStatusException e)
			rejected = e.status == 401;
		assert(rejected);
	}
	assert(refreshes == 1, "the authorization server must not be hit on every request");
	assert(srv.toolsAuth == [
		"Bearer old-access", "Bearer new-access", "Bearer new-access",
		"Bearer new-access"
	]);
	assert(!store.load(srv.endpoint).hasToken, "a later useOAuth must not reuse the token");
}
