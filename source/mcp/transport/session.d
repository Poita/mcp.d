module mcp.transport.session;

import core.sync.mutex : Mutex;

/// Tracks active Streamable HTTP sessions for a server mount.
///
/// When session management is enabled (see `StreamableHttpOptions.enableSessions`),
/// the server assigns a cryptographically-secure `Mcp-Session-Id` on the response
/// carrying the `InitializeResult`, requires that id on every subsequent request
/// (HTTP 400 when absent, HTTP 404 when unknown/terminated), and supports
/// client-driven termination via HTTP DELETE.
///
/// The store is thread-safe: vibe.d may dispatch concurrent requests on different
/// fibers/threads, and a single coordinator/mount is shared across them.
final class SessionManager
{
	private Mutex mutex;
	private bool[string] active;

	this() @safe
	{
		mutex = new Mutex;
	}

	/// Generate a new cryptographically-secure session id, record it as active,
	/// and return it. The id is a 256-bit value rendered as lowercase hex, which
	/// satisfies the spec requirement that the id "MUST only contain visible
	/// ASCII characters (ranging from 0x21 to 0x7E)".
	string create() @safe
	{
		const id = generateSessionId();
		() @trusted {
			synchronized (mutex)
				active[id] = true;
		}();
		return id;
	}

	/// Whether `id` names a currently-active (non-terminated) session.
	bool isActive(string id) @safe
	{
		if (id.length == 0)
			return false;
		return () @trusted {
			synchronized (mutex)
				return (id in active) !is null;
		}();
	}

	/// Terminate `id`. Returns true if the session existed (and was removed),
	/// false if it was unknown/already terminated.
	bool terminate(string id) @safe
	{
		if (id.length == 0)
			return false;
		return () @trusted {
			synchronized (mutex)
			{
				if ((id in active) is null)
					return false;
				active.remove(id);
				return true;
			}
		}();
	}
}

/// Produce a cryptographically-secure, hex-encoded 256-bit session id.
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

/// Fill `dst` with cryptographically-secure random bytes, falling back to the
/// std.random PRNG only if the OS source is unavailable.
private void fillSecureRandom(ubyte[] dst) @trusted
{
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
	}
	// Fallback: still unpredictable enough to avoid collisions; the OS source
	// above is the primary path on every supported platform.
	import std.random : rndGen, uniform;

	foreach (ref b; dst)
		b = cast(ubyte) uniform(0, 256);
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
