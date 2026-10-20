module mcp.transport.session;

import core.time : Duration, MonoTime, minutes;

import mcp.protocol.errors : McpException, internalError;
import mcp.internal.expiring_map : BoundedExpiringMap;
import mcp.server.connection : ConnectionState;

/// The bounds a `SessionManager` keeps its sessions within.
struct SessionLimits
{
	/// A session with no request and no open GET stream for this long is
	/// expired (`Duration.zero` disables expiry).
	Duration idleTtl = 30.minutes;
	/// The most sessions kept at once (`0`: unbounded). Past it, creating a
	/// session evicts the least-recently-active never-used idle session first,
	/// then the least-recently-active idle one; when every session is running a
	/// request or holding a GET stream, the new session is refused instead.
	size_t maxSessions = 10_000;
	/// The most sessions one authenticated principal keeps at once (`0`:
	/// unbounded). Past it, that principal's least-recently-active idle session
	/// is evicted, so one principal cannot push out everyone else's sessions.
	size_t maxPerPrincipal = 100;
	/// The most unauthenticated sessions created from one remote address kept at
	/// once (`0`: unbounded). Past it, that address's least-recently-active idle
	/// anonymous session is evicted, so one anonymous caller cannot push out
	/// everyone else's sessions. Behind a reverse proxy every anonymous caller
	/// shares the proxy's address; raise this, or set it to `0`, there.
	size_t maxAnonymousPerAddress = 100;
}

/// The key a caller's per-client caps count it under: the authenticated
/// `principal` when there is one, else its remote `address` ("" when neither is
/// known). Distinct prefixes keep a principal named like an address out of that
/// address's anonymous bucket.
package string callerBucket(string principal, string address) @safe pure nothrow
{
	return principal.length ? "\x1ep\x1e" ~ principal : address.length ? "\x1ea\x1e" ~ address : "";
}

/// Thrown by `SessionManager.create` when a session cap is reached and every
/// session that could make room is busy. The transport answers 503.
class SessionCapacityException : Exception
{
	this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure nothrow
	{
		super(msg, file, line);
	}
}

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
	// The manager OWNS one `ConnectionState` per active session, keyed by
	// `Mcp-Session-Id`. Presence is the liveness signal: an entry means the
	// session is active, its absence means unknown/terminated. Owning the
	// per-session state here is what makes stateful HTTP truly session-isolated —
	// the request path resolves a request's `ConnectionState` by its session id,
	// so one session's negotiated version / logLevel / subscriptions / in-flight
	// ids can never be observed through another's. The container bounds residency
	// by idle TTL and active-session cap, evicting least-recently-active sessions
	// so a never-DELETE client cannot grow the table without bound.
	private BoundedExpiringMap!Session sessions;
	private size_t maxPerPrincipal;
	private size_t maxAnonymousPerAddress;
	/// Live sessions per non-empty `Session.bucket`.
	private size_t[string] perBucket;

	/// A session's state together with the authenticated principal (token
	/// subject, "" when unauthenticated) that created it.
	private static struct Session
	{
		ConnectionState state;
		string principal;
		/// The key its creator's session cap counts it under: the principal when
		/// authenticated, else a key derived from the remote address ("" when
		/// neither is known).
		string bucket;
		/// The push-channel listener ids of the standalone GET streams open on
		/// the session, oldest first.
		long[] streams;
	}

	/// Construct a session manager with the default `SessionLimits`.
	this() @safe
	{
		this(SessionLimits.init);
	}

	/// Construct with explicit `limits`.
	this(SessionLimits limits) @safe
	{
		sessions = BoundedExpiringMap!Session(limits.idleTtl, limits.maxSessions, null);
		maxPerPrincipal = limits.maxPerPrincipal;
		maxAnonymousPerAddress = limits.maxAnonymousPerAddress;
		sessions.onEvict = &evicted;
		sessions.busy = (ref Session s) @safe => s.state.inFlight.length > 0 || s.streams.length > 0;
	}

	/// Called with a session's id after the idle sweep or the active-session cap
	/// removes it, so the transport can close the session's open streams. Not
	/// called for `terminate`.
	void delegate(string id) @safe onExpire;

	/// Report the end of an expired or evicted session. Only idle sessions
	/// expire or are evicted, so it has no request to cancel.
	private void evicted(string id, Session s) @safe
	{
		forget(s.bucket);
		if (onExpire !is null)
			onExpire(id);
	}

	/// Generate a new cryptographically-secure session id, create and store the
	/// per-session `ConnectionState` it owns, bind it to `principal` (the
	/// authenticated subject of the `initialize` request, "" when unauthenticated),
	/// record it as active, and return the id. The id is a 256-bit value rendered as lowercase hex, which satisfies the
	/// spec requirement that the id "MUST only contain visible ASCII characters
	/// (ranging from 0x21 to 0x7E)".
	///
	/// Before minting the new session the idle TTL sweep runs lazily and, if a
	/// cap would be exceeded, the least-recently-active idle session is evicted:
	/// one of `principal`'s own sessions for the per-principal cap (or, when
	/// unauthenticated, one of `address`'s anonymous sessions for the per-address
	/// cap), any session for the global cap. So a client that connects,
	/// initializes, and walks away without DELETE cannot grow the table without
	/// bound. A session running a request or holding an open GET stream is never
	/// evicted; when only such sessions remain, no session is minted.
	///
	/// Throws: `SessionCapacityException` when a cap is reached and every
	/// candidate session is busy. `McpException` (`internalError`) when the host
	/// OS CSPRNG is unavailable. This is fail-closed (see `generateSessionId`),
	/// so callers on the request path (e.g. `streamable_http.handlePost`'s
	/// `initialize` branch) must be prepared for it to throw rather than always
	/// returning an id. vibe.d converts an escaping `McpException` to an HTTP 500;
	/// `handlePost` additionally maps it to a JSON-RPC error response so the wire
	/// shape matches every other error path.
	string create(string principal = "", string address = "") @safe
	{
		const bucket = callerBucket(principal, address);
		const cap = principal.length ? maxPerPrincipal : maxAnonymousPerAddress;
		if (cap != 0 && bucket.length)
		{
			bool mine(ref Session s) @safe
			{
				return s.bucket == bucket;
			}

			while (perBucket.get(bucket, 0) >= cap)
				if (!sessions.evictOldest(&mine))
					throw new SessionCapacityException(principal.length
							? "too many active sessions for this principal"
							: "too many active sessions for this address");
		}
		const id = generateSessionId();
		// put() runs the lazy idle sweep and cap eviction before inserting, so an
		// abandoned session is reclaimed the next time any client initializes.
		if (!sessions.put(id, Session(new ConnectionState, principal, bucket)))
			throw new SessionCapacityException("too many active sessions");
		if (bucket.length)
			perBucket[bucket] = perBucket.get(bucket, 0) + 1;
		return id;
	}

	/// Release one session's slot in `bucket`.
	private void forget(string bucket) @safe
	{
		if (auto n = bucket in perBucket)
		{
			if (*n <= 1)
				perBucket.remove(bucket);
			else
				(*n)--;
		}
	}

	/// Record that the standalone GET stream fed by push-channel listener
	/// `listener` opened on session `id`. While any is open the session neither
	/// expires nor is evicted to make room.
	void streamOpened(string id, long listener) @safe
	{
		if (auto p = sessions.get(id, true))
			p.streams ~= listener;
	}

	/// Number of standalone GET streams open on session `id`.
	size_t openStreams(string id) @safe
	{
		if (auto p = sessions.get(id, false))
			return p.streams.length;
		return 0;
	}

	/// The listener id of the oldest standalone GET stream open on session `id`,
	/// or 0 when none is.
	long oldestStream(string id) @safe
	{
		if (auto p = sessions.get(id, false))
			if (p.streams.length)
				return p.streams[0];
		return 0;
	}

	/// Record that the standalone GET stream fed by `listener` on session `id`
	/// closed.
	void streamClosed(string id, long listener) @safe
	{
		import std.algorithm : countUntil, remove;

		if (auto p = sessions.get(id, true))
		{
			const at = p.streams.countUntil(listener);
			if (at >= 0)
				p.streams = p.streams.remove(at);
		}
	}

	/// Whether `id` is an active session created by `principal`. A session id
	/// presented under a different principal's token must be treated as unknown,
	/// so possessing another client's session id does not grant use of it.
	bool ownedBy(string id, string principal) @safe
	{
		if (id.length == 0)
			return false;
		if (auto p = sessions.get(id, false))
			return p.principal == principal;
		return false;
	}

	/// Whether `id` names a currently-active (non-terminated) session.
	bool isActive(string id) @safe
	{
		if (id.length == 0)
			return false;
		return sessions.contains(id);
	}

	/// The `ConnectionState` this manager owns for the active session `id`, or
	/// `null` when the id is empty, unknown, or already terminated. The request
	/// path puts this on the request context so dispatch reads/writes only this
	/// session's per-connection state. Resolving a session refreshes its
	/// last-activity timestamp so an in-use session is never swept as idle, and,
	/// unless `countsAsUse` is false (the `initialize` that minted it), marks it
	/// used so cap eviction removes never-used sessions first.
	ConnectionState stateFor(string id, bool countsAsUse = true) @safe
	{
		if (id.length == 0)
			return null;
		if (auto p = sessions.get(id, true))
		{
			if (countsAsUse)
				sessions.markUsed(id);
			return p.state;
		}
		return null;
	}

	/// Terminate `id`, cancelling its in-flight requests so their handlers stop
	/// work nobody will receive. Returns true if the session existed (and was
	/// removed, dropping its `ConnectionState`), false if it was unknown/already
	/// terminated.
	bool terminate(string id) @safe
	{
		if (id.length == 0)
			return false;
		auto p = sessions.get(id, false);
		if (p is null)
			return false;
		foreach (tok; p.state.inFlight)
			tok.cancel();
		forget(p.bucket);
		return sessions.remove(id);
	}

	/// Number of currently-active sessions.
	size_t activeCount() @safe
	{
		return sessions.length;
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

	auto mgr = new SessionManager(SessionLimits(Duration.zero, 3));
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

	auto mgr = new SessionManager(SessionLimits(Duration.zero, 2));
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

	auto mgr = new SessionManager(SessionLimits(5.msecs, 0));
	const stale = mgr.create();
	assert(mgr.isActive(stale));
	Thread.sleep(20.msecs);
	const fresh = mgr.create();
	assert(!mgr.isActive(stale), "an idle session past the TTL must be swept");
	assert(mgr.isActive(fresh));
}

unittest  // a session with an in-flight request is not swept as idle
{
	import core.thread : Thread;
	import core.time : msecs;
	import mcp.server.context : CancellationToken;

	auto mgr = new SessionManager(SessionLimits(5.msecs, 0));
	const busy = mgr.create();
	auto tok = new CancellationToken;
	mgr.stateFor(busy).inFlight["i:1"] = tok;
	Thread.sleep(20.msecs);
	mgr.create();
	assert(mgr.isActive(busy), "a session running a request must outlive the idle TTL");
	assert(!tok.cancelled);
}

unittest  // a session's idle clock restarts when its last in-flight request ends
{
	import core.thread : Thread;
	import core.time : msecs;
	import mcp.server.context : CancellationToken;

	auto mgr = new SessionManager(SessionLimits(30.msecs, 0));
	const id = mgr.create();
	auto state = mgr.stateFor(id);
	state.inFlight["i:1"] = new CancellationToken;
	Thread.sleep(40.msecs);
	assert(mgr.isActive(id));
	state.inFlight.remove("i:1");
	assert(mgr.isActive(id), "a just-finished request leaves the session freshly active");
	Thread.sleep(40.msecs);
	assert(!mgr.isActive(id));
}

unittest  // isActive sweeps expired entries without needing a create() to trigger the sweep
{
	// contains() must call sweep() so that isActive() returns false for a session
	// whose idle TTL has elapsed, even when no new session is created afterward.
	// Without the sweep, the stale entry remains in the map and isActive() returns
	// true, allowing requests to a dead session to proceed past the 404 gate.
	import core.thread : Thread;
	import core.time : msecs;

	auto mgr = new SessionManager(SessionLimits(5.msecs, 0));
	const stale = mgr.create();
	assert(mgr.isActive(stale));
	Thread.sleep(20.msecs);
	// No create() here — isActive() alone must detect expiry.
	assert(!mgr.isActive(stale),
			"isActive must return false for a session past its idle TTL without needing a create()");
}

unittest  // stateFor returns null for an expired session without needing a prior isActive()
{
	// get() must sweep before the lookup so that stateFor() cannot resurrect a
	// session whose idle TTL has elapsed. Without the sweep, get(id, true) finds
	// the expired entry, resets its timestamp to now(), and returns the stale
	// ConnectionState — silently extending the session beyond its intended TTL.
	import core.thread : Thread;
	import core.time : msecs;

	auto mgr = new SessionManager(SessionLimits(5.msecs, 0));
	const stale = mgr.create();
	assert(mgr.isActive(stale));
	Thread.sleep(20.msecs);
	// Call stateFor() directly without a prior isActive() — the session is expired.
	assert(mgr.stateFor(stale) is null, "stateFor must return null for a session past its idle TTL");
	// Confirm it was not resurrected: isActive() must also return false.
	assert(!mgr.isActive(stale),
			"stateFor must not resurrect an expired session by refreshing its timestamp");
}

unittest  // a disabled idle TTL and disabled cap leave sessions resident (historical behaviour)
{
	auto mgr = new SessionManager(SessionLimits(Duration.zero, 0));
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

/// Produce a cryptographically-secure, hex-encoded 256-bit session id, drawn
/// from the OS CSPRNG via `cryptoRandomFill`.
///
/// Throws: `McpException` (`internalError`) when no OS CSPRNG can be read. There is
/// deliberately no non-cryptographic fallback, so this is a fallible path; callers
/// must handle the throw.
string generateSessionId() @safe
{
	import std.format : format;
	import mcp.auth.csprng : CsprngException, cryptoRandomFill;

	// Test seam: a build configured with this version simulates an unavailable OS
	// CSPRNG so the fail-closed contract can be exercised by a regression test.
	// Never defined in normal builds.
	version (McpForceCsprngFailure)
		throw internalError("forced CSPRNG failure (test seam)");

	ubyte[32] buf;
	try
		cryptoRandomFill(buf[]);
	catch (CsprngException e)
		throw internalError("unable to read cryptographically-secure random bytes: " ~ e.msg);
	return format("%(%02x%)", buf[]);
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

unittest  // terminate cancels the session's in-flight requests
{
	import mcp.server.context : CancellationToken;

	auto mgr = new SessionManager;
	const id = mgr.create();
	auto tok = new CancellationToken;
	mgr.stateFor(id).inFlight["i:1"] = tok;
	assert(mgr.terminate(id));
	assert(tok.cancelled, "a terminated session's in-flight request must be cancelled");
}

unittest  // a session evicted past the cap has its end reported
{
	import core.thread : Thread;
	import core.time : msecs;

	auto mgr = new SessionManager(SessionLimits(Duration.zero, 1));
	string[] ended;
	mgr.onExpire = (string id) @safe { ended ~= id; };
	const a = mgr.create();
	Thread.sleep(2.msecs);
	mgr.create();
	assert(!mgr.isActive(a));
	assert(ended == [a], "an evicted session's end must be reported");
}

unittest  // a session swept past its idle TTL has its end reported
{
	import core.thread : Thread;
	import core.time : msecs;

	auto mgr = new SessionManager(SessionLimits(5.msecs, 0));
	string[] ended;
	mgr.onExpire = (string id) @safe { ended ~= id; };
	const a = mgr.create();
	Thread.sleep(20.msecs);
	assert(!mgr.isActive(a));
	assert(ended == [a], "an expired session's end must be reported");
}

unittest  // terminate is not reported as an expiry
{
	auto mgr = new SessionManager;
	string[] ended;
	mgr.onExpire = (string id) @safe { ended ~= id; };
	assert(mgr.terminate(mgr.create()));
	assert(ended.length == 0);
}

unittest  // a session is bound to the principal that created it
{
	auto mgr = new SessionManager;
	const id = mgr.create("alice");
	assert(mgr.ownedBy(id, "alice"));
	assert(!mgr.ownedBy(id, "bob"));
	assert(!mgr.ownedBy(id, ""));
	assert(!mgr.ownedBy("unknown", "alice"));
	const anon = mgr.create();
	assert(mgr.ownedBy(anon, ""));
	assert(!mgr.ownedBy(anon, "alice"));
}

unittest  // past the cap, never-used sessions are evicted before used ones
{
	import core.thread : Thread;
	import core.time : msecs;

	auto mgr = new SessionManager(SessionLimits(Duration.zero, 3));
	const used = mgr.create();
	assert(mgr.stateFor(used) !is null);
	Thread.sleep(2.msecs);
	string[] flood;
	foreach (_; 0 .. 5)
	{
		flood ~= mgr.create();
		Thread.sleep(2.msecs);
	}
	assert(mgr.activeCount() == 3);
	assert(mgr.isActive(used), "an initialize flood must not evict a session in use");
	assert(mgr.isActive(flood[$ - 1]) && mgr.isActive(flood[$ - 2]));
}

unittest  // resolving a just-minted session for its initialize does not count as use
{
	import core.thread : Thread;
	import core.time : msecs;

	auto mgr = new SessionManager(SessionLimits(Duration.zero, 2));
	const a = mgr.create();
	assert(mgr.stateFor(a, false) !is null);
	Thread.sleep(2.msecs);
	const b = mgr.create();
	assert(mgr.stateFor(b) !is null);
	Thread.sleep(2.msecs);
	mgr.create();
	assert(!mgr.isActive(a), "a never-used session is the first eviction victim");
	assert(mgr.isActive(b));
}

unittest  // past the cap, a session running a request is never evicted; create fails instead
{
	import std.exception : assertThrown;
	import mcp.server.context : CancellationToken;

	auto mgr = new SessionManager(SessionLimits(Duration.zero, 1));
	const a = mgr.create();
	mgr.stateFor(a).inFlight["i:1"] = new CancellationToken;
	assertThrown!SessionCapacityException(mgr.create());
	assert(mgr.isActive(a), "a busy session must survive an initialize past the cap");
	assert(mgr.activeCount == 1);
}

unittest  // past the cap, a session holding a GET stream is never evicted
{
	import std.exception : assertThrown;

	auto mgr = new SessionManager(SessionLimits(Duration.zero, 1));
	const a = mgr.create();
	mgr.streamOpened(a, 1);
	assertThrown!SessionCapacityException(mgr.create());
	assert(mgr.isActive(a));
	mgr.streamClosed(a, 1);
	const b = mgr.create();
	assert(!mgr.isActive(a) && mgr.isActive(b), "an idle session makes room once its stream ends");
}

unittest  // a session's GET streams are reported oldest first and close in any order
{
	auto mgr = new SessionManager;
	const a = mgr.create();
	assert(mgr.oldestStream(a) == 0);
	mgr.streamOpened(a, 7);
	mgr.streamOpened(a, 9);
	mgr.streamOpened(a, 11);
	assert(mgr.openStreams(a) == 3 && mgr.oldestStream(a) == 7);
	mgr.streamClosed(a, 9);
	assert(mgr.openStreams(a) == 2 && mgr.oldestStream(a) == 7);
	mgr.streamClosed(a, 7);
	assert(mgr.oldestStream(a) == 11);
	mgr.streamClosed(a, 7);
	assert(mgr.openStreams(a) == 1, "closing an unknown stream changes nothing");
}

unittest  // a session holding a GET stream does not expire as idle
{
	import core.thread : Thread;
	import core.time : msecs;

	auto mgr = new SessionManager(SessionLimits(5.msecs, 0));
	const a = mgr.create();
	mgr.streamOpened(a, 1);
	Thread.sleep(20.msecs);
	assert(mgr.isActive(a));
}

unittest  // past the per-principal cap, the principal's own oldest idle session is evicted
{
	import core.thread : Thread;
	import core.time : msecs;

	SessionLimits limits;
	limits.idleTtl = Duration.zero;
	limits.maxPerPrincipal = 2;
	auto mgr = new SessionManager(limits);
	const bob = mgr.create("bob");
	Thread.sleep(2.msecs);
	const a1 = mgr.create("alice");
	Thread.sleep(2.msecs);
	const a2 = mgr.create("alice");
	Thread.sleep(2.msecs);
	const a3 = mgr.create("alice");
	assert(!mgr.isActive(a1), "alice's oldest session makes room for her new one");
	assert(mgr.isActive(a2) && mgr.isActive(a3));
	assert(mgr.isActive(bob), "one principal's sessions never evict another's");
}

unittest  // past the per-principal cap with every session busy, create fails
{
	import std.exception : assertThrown;

	SessionLimits limits;
	limits.maxPerPrincipal = 1;
	auto mgr = new SessionManager(limits);
	const a = mgr.create("alice");
	mgr.streamOpened(a, 1);
	assertThrown!SessionCapacityException(mgr.create("alice"));
	assert(mgr.isActive(a));
	mgr.create("bob");
}

unittest  // the per-principal cap bounds an authenticated principal by default
{
	auto mgr = new SessionManager(SessionLimits(Duration.zero, 0));
	const first = mgr.create("alice");
	foreach (_; 0 .. 200)
		mgr.create("alice");
	assert(!mgr.isActive(first), "a principal's sessions are bounded without configuration");
	assert(mgr.activeCount < 200);
}

unittest  // past the per-address cap, an anonymous caller evicts only its own address's sessions
{
	import core.thread : Thread;
	import core.time : msecs;

	SessionLimits limits;
	limits.idleTtl = Duration.zero;
	limits.maxAnonymousPerAddress = 2;
	auto mgr = new SessionManager(limits);
	const other = mgr.create("", "10.0.0.2");
	const alice = mgr.create("alice", "10.0.0.1");
	Thread.sleep(2.msecs);
	const a1 = mgr.create("", "10.0.0.1");
	Thread.sleep(2.msecs);
	const a2 = mgr.create("", "10.0.0.1");
	Thread.sleep(2.msecs);
	const a3 = mgr.create("", "10.0.0.1");
	assert(!mgr.isActive(a1), "the address's oldest anonymous session makes room");
	assert(mgr.isActive(a2) && mgr.isActive(a3));
	assert(mgr.isActive(other), "another address's sessions are untouched");
	assert(mgr.isActive(alice), "an authenticated session is not in the anonymous bucket");
	assert(mgr.ownedBy(a3, ""), "an anonymous session is still owned by the empty principal");
}

unittest  // terminated and cap-evicted sessions free their slot in the creator's bucket
{
	import core.thread : Thread;
	import core.time : msecs;

	SessionLimits limits;
	limits.idleTtl = Duration.zero;
	limits.maxSessions = 3;
	limits.maxPerPrincipal = 2;
	auto mgr = new SessionManager(limits);
	const a1 = mgr.create("alice");
	Thread.sleep(2.msecs);
	const a2 = mgr.create("alice");
	Thread.sleep(2.msecs);
	assert(mgr.terminate(a1));
	const a3 = mgr.create("alice");
	Thread.sleep(2.msecs);
	assert(mgr.isActive(a2) && mgr.isActive(a3), "a terminated session frees its slot");
	mgr.create("bob");
	Thread.sleep(2.msecs);
	mgr.create("bob");
	assert(!mgr.isActive(a2), "the global cap evicts the oldest session");
	mgr.streamOpened(a3, 1);
	mgr.create("alice");
	assert(mgr.isActive(a3), "a cap-evicted session frees its slot");
}
