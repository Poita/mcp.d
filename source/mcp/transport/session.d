module mcp.transport.session;

import core.time : Duration, MonoTime, minutes;

import mcp.protocol.errors : McpException, internalError;
import mcp.server.connection : ConnectionState;

/// Tracks active Streamable HTTP sessions for a server mount.
///
/// When session management is enabled (the server was built with
/// `McpServer.stateful`, i.e. `server.mode == ServerMode.stateful`), the server
/// assigns a cryptographically-secure `Mcp-Session-Id` on the response
/// carrying the `InitializeResult`, requires that id on every subsequent request
/// (HTTP 400 when absent, HTTP 404 when unknown/terminated), and supports
/// client-driven termination via HTTP DELETE.
///
/// Concurrency: the SDK ships and is supported only on vibe.d's default
/// single-threaded event loop, where requests are dispatched cooperatively on
/// fibers of one thread and `create`/`isActive`/`terminate` are each a single
/// synchronous associative-array operation with no intervening yield -- so they
/// are race-free among fibers without locking, matching the single-fiber model
/// the coordinators document (see `mcp.transport.sse_context`). Running the
/// router with `HTTPServerOption.distribute` or worker threads is unsupported;
/// all shared coordinator/session state would then need fiber-and-thread-aware
/// locking.
final class SessionManager
{
	// The manager OWNS one `ConnectionState` per active
	// session, keyed by `Mcp-Session-Id`. Presence in this map is the liveness
	// signal: an entry means the session is
	// active, its absence means unknown/terminated. Storing the per-session state
	// here is what makes stateful HTTP truly session-isolated — the request path
	// resolves a request's `ConnectionState` by its session id, so one session's
	// negotiated version / logLevel / subscriptions / in-flight ids can never be
	// observed through another's.
	private ConnectionState[string] states;

	/// Last-activity timestamp per session, updated on `create` and on every
	/// `stateFor` that resolves the session. Drives the idle TTL sweep.
	private MonoTime[string] lastActivity;

	/// Idle time-to-live: a session not touched (created or resolved via
	/// `stateFor`) within this window is eligible for eviction by the lazy sweep
	/// run on `create`. `Duration.zero` disables idle eviction.
	private Duration idleTtl;

	/// Maximum number of concurrently-active sessions. When a `create` would push
	/// the table past this, the least-recently-active session is evicted first so
	/// a never-DELETE client cannot grow the table without bound. `0` disables the
	/// cap (unbounded, the historical behaviour).
	private size_t maxActive;

	/// Default idle TTL applied when none is configured: a stateful session left
	/// untouched for this long is swept on the next `create`.
	enum Duration defaultIdleTtl = 30.minutes;

	/// Default cap on concurrently-active sessions, bounding worst-case
	/// `ConnectionState` residency for a server whose clients never issue DELETE.
	enum size_t defaultMaxActive = 10_000;

	/// Construct a session manager with the default idle TTL and active-session
	/// cap, both bounding `ConnectionState` residency for abandoned sessions.
	this() @safe
	{
		this(defaultIdleTtl, defaultMaxActive);
	}

	/// Construct with an explicit idle TTL and active-session cap. `idleTtl`
	/// `Duration.zero` disables the idle sweep; `maxActive` `0` disables the cap.
	this(Duration idleTtl, size_t maxActive) @safe
	{
		this.idleTtl = idleTtl;
		this.maxActive = maxActive;
	}

	/// Generate a new cryptographically-secure session id, create and store the
	/// per-session `ConnectionState` it owns, record it as active, and return the
	/// id. The id is a 256-bit value rendered as lowercase hex, which satisfies the
	/// spec requirement that the id "MUST only contain visible ASCII characters
	/// (ranging from 0x21 to 0x7E)".
	///
	/// Before minting the new session the idle TTL sweep runs lazily and, if the
	/// active-session cap would be exceeded, the least-recently-active session is
	/// evicted — so a client that connects, initializes, and walks away without
	/// DELETE cannot grow the table without bound.
	///
	/// Throws: `McpException` (`internalError`) when the host OS CSPRNG is
	/// unavailable. This is fail-closed (see `generateSessionId`/`fillSecureRandom`),
	/// so callers on the request path (e.g. `streamable_http.handlePost`'s
	/// `initialize` branch) must be prepared for it to throw rather than always
	/// returning an id. vibe.d converts an escaping `McpException` to an HTTP 500;
	/// `handlePost` additionally maps it to a JSON-RPC error response so the wire
	/// shape matches every other error path.
	string create() @safe
	{
		sweepIdle();
		enforceCap();
		const id = generateSessionId();
		states[id] = new ConnectionState;
		lastActivity[id] = MonoTime.currTime;
		return id;
	}

	/// Whether `id` names a currently-active (non-terminated) session.
	bool isActive(string id) @safe
	{
		if (id.length == 0)
			return false;
		return (id in states) !is null;
	}

	/// The `ConnectionState` this manager owns for the active session `id`, or
	/// `null` when the id is empty, unknown, or already terminated. The request
	/// path puts this on the request context so dispatch reads/writes only this
	/// session's per-connection state. Resolving a session refreshes its
	/// last-activity timestamp so an in-use session is never swept as idle.
	ConnectionState stateFor(string id) @safe
	{
		if (id.length == 0)
			return null;
		if (auto p = id in states)
		{
			lastActivity[id] = MonoTime.currTime;
			return *p;
		}
		return null;
	}

	/// Terminate `id`. Returns true if the session existed (and was removed,
	/// dropping its `ConnectionState`), false if it was unknown/already terminated.
	bool terminate(string id) @safe
	{
		if (id.length == 0)
			return false;
		if ((id in states) is null)
			return false;
		drop(id);
		return true;
	}

	/// Number of currently-active sessions.
	size_t activeCount() @safe
	{
		return states.length;
	}

	/// Remove a session and its bookkeeping. Shared by `terminate` and the
	/// eviction paths so the two parallel maps never drift apart.
	private void drop(string id) @safe
	{
		states.remove(id);
		lastActivity.remove(id);
	}

	/// Evict every session whose last activity is older than `idleTtl`. A no-op
	/// when the TTL is disabled. Runs lazily on `create`, so on the single-fiber
	/// vibe.d loop it needs no timer or locking: an abandoned session is reclaimed
	/// the next time any client initializes.
	private void sweepIdle() @safe
	{
		if (idleTtl <= Duration.zero || states.length == 0)
			return;
		const now = MonoTime.currTime;
		string[] expired;
		foreach (id, ts; lastActivity)
			if (now - ts >= idleTtl)
				expired ~= id;
		foreach (id; expired)
			drop(id);
	}

	/// Evict least-recently-active sessions until creating one more stays within
	/// `maxActive`. A no-op when the cap is disabled. This guarantees a never-DELETE
	/// client cannot grow the table past the cap regardless of the idle sweep.
	private void enforceCap() @safe
	{
		if (maxActive == 0)
			return;
		while (states.length >= maxActive)
		{
			string oldest;
			MonoTime oldestTs;
			bool found;
			foreach (id, ts; lastActivity)
				if (!found || ts < oldestTs)
				{
					oldest = id;
					oldestTs = ts;
					found = true;
				}
			if (!found)
				break;
			drop(oldest);
		}
	}
}

unittest  // a created session owns a non-null ConnectionState
{
	auto mgr = new SessionManager;
	const id = mgr.create();
	auto cs = mgr.stateFor(id);
	assert(cs !is null);
	assert(mgr.stateFor("unknown") is null);
	assert(mgr.stateFor("") is null);
}

unittest  // create() past the active-session cap evicts the oldest rather than growing unbounded
{
	// A never-DELETE client looping initialize cannot grow the table without
	// bound: once the cap is reached, the least-recently-active session is
	// evicted so activeCount() stays at the cap.
	import core.thread : Thread;
	import core.time : msecs;

	auto mgr = new SessionManager(Duration.zero, 3);
	const a = mgr.create();
	Thread.sleep(2.msecs);
	const b = mgr.create();
	Thread.sleep(2.msecs);
	const c = mgr.create();
	assert(mgr.activeCount() == 3);
	const d = mgr.create();
	assert(mgr.activeCount() == 3, "cap must bound the table");
	assert(!mgr.isActive(a), "least-recently-active session must be evicted past the cap");
	assert(mgr.isActive(b) && mgr.isActive(c) && mgr.isActive(d));
}

unittest  // resolving a session via stateFor refreshes its activity so it is not the eviction victim
{
	// stateFor updates last-activity, so an in-use session survives a cap-driven
	// eviction in favour of a genuinely older idle one.
	import core.thread : Thread;
	import core.time : msecs;

	auto mgr = new SessionManager(Duration.zero, 2);
	const a = mgr.create();
	Thread.sleep(2.msecs);
	const b = mgr.create();
	Thread.sleep(2.msecs);
	// Touch a so b becomes the least-recently-active.
	assert(mgr.stateFor(a) !is null);
	const c = mgr.create();
	assert(mgr.isActive(a), "recently-touched session must survive eviction");
	assert(!mgr.isActive(b), "least-recently-active session must be evicted");
	assert(mgr.isActive(c));
}

unittest  // an idle session past the TTL is swept on the next create()
{
	// A short idle TTL plus a real sleep longer than it makes the first session
	// idle; the lazy sweep on the next create() then reclaims it. A zero cap keeps
	// the cap path out of the assertion so only the idle sweep is exercised.
	import core.thread : Thread;
	import core.time : msecs;

	auto mgr = new SessionManager(5.msecs, 0);
	const stale = mgr.create();
	assert(mgr.isActive(stale));
	Thread.sleep(20.msecs);
	const fresh = mgr.create();
	assert(!mgr.isActive(stale), "an idle session past the TTL must be swept");
	assert(mgr.isActive(fresh));
}

unittest  // a disabled idle TTL and disabled cap leave sessions resident (historical behaviour)
{
	auto mgr = new SessionManager(Duration.zero, 0);
	string[] ids;
	foreach (_; 0 .. 5)
		ids ~= mgr.create();
	assert(mgr.activeCount() == 5);
	foreach (id; ids)
		assert(mgr.isActive(id));
}

unittest  // two sessions on one manager get INDEPENDENT ConnectionStates (no cross-talk)
{
	import mcp.protocol.versions : ProtocolVersion;
	import mcp.server.context : CancellationToken;

	auto mgr = new SessionManager;
	const a = mgr.create();
	const b = mgr.create();
	auto csA = mgr.stateFor(a);
	auto csB = mgr.stateFor(b);
	assert(csA !is csB, "each session must own a distinct ConnectionState");

	// Mutate session A's negotiated version, log level, a subscription, and an
	// in-flight id; NONE may be visible through session B's state.
	csA.negotiated = ProtocolVersion.v2025_03_26;
	csA.logLevel = "error";
	csA.subscriptions["res://a"] = true;
	csA.inFlight["i:1"] = new CancellationToken;

	assert(csB.negotiated != ProtocolVersion.v2025_03_26,
			"session B saw session A's negotiated version");
	assert(csB.logLevel != "error", "session B saw session A's log level");
	assert(("res://a" in csB.subscriptions) is null, "session B saw session A's subscription");
	assert(("i:1" in csB.inFlight) is null, "session B saw session A's in-flight id");
}

unittest  // terminating a session drops its ConnectionState
{
	auto mgr = new SessionManager;
	const id = mgr.create();
	assert(mgr.stateFor(id) !is null);
	assert(mgr.terminate(id));
	assert(mgr.stateFor(id) is null);
}

/// Produce a cryptographically-secure, hex-encoded 256-bit session id.
///
/// Throws: `McpException` (`internalError`) when no OS CSPRNG can be read. There is
/// deliberately no non-cryptographic fallback, so this is a fallible path; callers
/// must handle the throw.
string generateSessionId() @safe
{
	import std.format : format;

	ubyte[32] buf;
	fillSecureRandom(buf[]);
	string s;
	foreach (b; buf[])
		s ~= format("%02x", b);
	return s;
}

/// Fill `dst` with cryptographically-secure random bytes drawn from the host
/// OS's CSPRNG (`/dev/urandom` on Posix, `BCryptGenRandom` on Windows). There is
/// deliberately NO `std.random` fallback: a Mersenne-Twister-derived id would be
/// predictable and would weaken session-hijacking protection. If no OS crypto
/// source can be read, this fails closed by throwing rather than emitting a
/// non-cryptographic id.
private void fillSecureRandom(ubyte[] dst) @trusted
{
	if (dst.length == 0)
		return;

	// Test seam: a build configured with this version simulates an unavailable OS
	// CSPRNG so the fail-closed contract -- create()/generateSessionId() throw
	// McpException rather than emitting a predictable id -- can be exercised by a
	// regression test. Never defined in normal builds.
	version (McpForceCsprngFailure)
		throw internalError("forced CSPRNG failure (test seam)");

	version (Posix)
	{
		import std.stdio : File;

		try
		{
			auto f = File("/dev/urandom", "rb");
			const got = f.rawRead(dst);
			if (got.length == dst.length)
				return;
		}
		catch (Exception)
		{
		}
		throw internalError(
				"unable to read cryptographically-secure random bytes from /dev/urandom");
	}
	else version (Windows)
	{
		// BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG draws from the
		// system-preferred CSPRNG without needing an algorithm handle. NTSTATUS 0
		// (STATUS_SUCCESS) indicates success.
		import core.sys.windows.windows : ULONG, PUCHAR;

		alias NTSTATUS = int;
		enum ULONG BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002;

		extern (Windows) NTSTATUS BCryptGenRandom(void* hAlgorithm,
				PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags) nothrow @nogc;

		const status = BCryptGenRandom(null, cast(PUCHAR) dst.ptr,
				cast(ULONG) dst.length, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		if (status == 0)
			return;
		throw internalError(
				"BCryptGenRandom failed to provide cryptographically-secure random bytes");
	}
	else
	{
		// Fail closed on any platform without a known OS CSPRNG rather than
		// emitting a predictable id.
		throw internalError("no cryptographically-secure random source available on this platform");
	}
}

unittest  // generated ids are visible-ASCII hex of the expected length
{
	const id = generateSessionId();
	assert(id.length == 64);
	foreach (c; id)
		assert((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
}

unittest  // distinct sessions get distinct ids
{
	auto mgr = new SessionManager;
	const a = mgr.create();
	const b = mgr.create();
	assert(a != b);
}

unittest  // the secure source actually fills the buffer (not all zero) and varies
{
	// The id MUST come from an OS CSPRNG, never a std.random Mt19937 fallback. Two
	// consecutive 256-bit draws being distinct, and not all-zero, demonstrates the
	// secure path ran rather than an untouched/constant buffer.
	const a = generateSessionId();
	const b = generateSessionId();
	assert(a != b);
	bool allZero = true;
	foreach (c; a)
		if (c != '0')
		{
			allZero = false;
			break;
		}
	assert(!allZero);
}

unittest  // a freshly-created session is active
{
	auto mgr = new SessionManager;
	const id = mgr.create();
	assert(mgr.isActive(id));
}

unittest  // unknown / empty ids are not active
{
	auto mgr = new SessionManager;
	assert(!mgr.isActive("does-not-exist"));
	assert(!mgr.isActive(""));
}

unittest  // terminate removes an active session
{
	auto mgr = new SessionManager;
	const id = mgr.create();
	assert(mgr.terminate(id));
	assert(!mgr.isActive(id));
}

unittest  // terminating an unknown session reports false
{
	auto mgr = new SessionManager;
	assert(!mgr.terminate("nope"));
	assert(!mgr.terminate(""));
}

version (McpForceCsprngFailure) unittest  // create()/generateSessionId fail closed on CSPRNG failure
{
	// Build with `-version=McpForceCsprngFailure` to exercise the fail-closed
	// contract: when the OS CSPRNG is unavailable, id generation throws
	// McpException(internalError) instead of emitting a predictable id.
	import std.exception : assertThrown;

	assertThrown!McpException(generateSessionId());

	auto mgr = new SessionManager;
	assertThrown!McpException(mgr.create());
}
