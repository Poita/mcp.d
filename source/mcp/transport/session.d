module mcp.transport.session;

import mcp.protocol.errors : McpException, internalError;

/// Tracks active Streamable HTTP sessions for a server mount.
///
/// When session management is enabled (see `StreamableHttpOptions.enableSessions`),
/// the server assigns a cryptographically-secure `Mcp-Session-Id` on the response
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
	private bool[string] active;

	this() @safe
	{
	}

	/// Generate a new cryptographically-secure session id, record it as active,
	/// and return it. The id is a 256-bit value rendered as lowercase hex, which
	/// satisfies the spec requirement that the id "MUST only contain visible
	/// ASCII characters (ranging from 0x21 to 0x7E)".
	string create() @safe
	{
		const id = generateSessionId();
		active[id] = true;
		return id;
	}

	/// Whether `id` names a currently-active (non-terminated) session.
	bool isActive(string id) @safe
	{
		if (id.length == 0)
			return false;
		return (id in active) !is null;
	}

	/// Terminate `id`. Returns true if the session existed (and was removed),
	/// false if it was unknown/already terminated.
	bool terminate(string id) @safe
	{
		if (id.length == 0)
			return false;
		if ((id in active) is null)
			return false;
		active.remove(id);
		return true;
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

/// Fill `dst` with cryptographically-secure random bytes drawn from the host
/// OS's CSPRNG (`/dev/urandom` on Posix, `BCryptGenRandom` on Windows). There is
/// deliberately NO `std.random` fallback: a Mersenne-Twister-derived id would be
/// predictable and would weaken session-hijacking protection (audit finding #27).
/// If no OS crypto source can be read, this fails closed by throwing rather than
/// emitting a non-cryptographic id.
private void fillSecureRandom(ubyte[] dst) @trusted
{
	if (dst.length == 0)
		return;

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
	// Audit finding #27: the id MUST come from an OS CSPRNG, never the std.random
	// Mt19937 fallback (which was removed). Two consecutive 256-bit draws being
	// distinct, and not all-zero, demonstrates the secure path ran rather than an
	// untouched/constant buffer.
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
