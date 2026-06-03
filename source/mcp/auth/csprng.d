module mcp.auth.csprng;

/**
 * Cryptographically secure random bytes from the operating system's CSPRNG.
 *
 * OAuth PKCE code verifiers and the `state` parameter (the CSRF /
 * authorization-response mix-up defense) MUST be unpredictable. The default
 * `std.random` generator (Mersenne Twister, `rndGen`) is fast but not
 * cryptographically secure, so it must not be used to mint these values.
 *
 * `cryptoRandomBytes` draws from the OS CSPRNG:
 *   - Linux/Android: `getrandom(2)` (falls back to `/dev/urandom`).
 *   - macOS / BSD:   `arc4random_buf(3)`.
 *   - Windows:       `BCryptGenRandom`.
 *   - Other POSIX:   `/dev/urandom`.
 *
 * There is no silent fall back to `std.random`: if the OS CSPRNG cannot be
 * reached, the function throws rather than emit predictable bytes.
 */

// D has no `version(linux) || version(Posix)` operator. linux implies Posix,
// so aliasing both onto one identifier selects the shared /dev/urandom reader.
version (linux) version = McpHasDevUrandom;
version (Posix) version = McpHasDevUrandom;

@safe:

/// Thrown when the operating system CSPRNG cannot be read.
class CsprngException : Exception
{
	this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure nothrow
	{
		super(msg, file, line);
	}
}

/// Fill `buf` with cryptographically secure random bytes from the OS CSPRNG.
/// Throws `CsprngException` if the OS CSPRNG is unavailable.
void cryptoRandomFill(scope ubyte[] buf) @trusted
{
	if (buf.length == 0)
		return;

	version (linux)
	{
		import core.stdc.errno : errno, EINTR;

		// Try getrandom(2) first (Linux 3.17+). glibc may not expose a wrapper,
		// so go through the raw syscall.
		size_t filled = 0;
		bool getrandomWorked = true;
		while (filled < buf.length)
		{
			const n = sysGetrandom(&buf[filled], buf.length - filled, 0);
			if (n < 0)
			{
				if (errno == EINTR)
					continue;
				getrandomWorked = false;
				break;
			}
			filled += cast(size_t) n;
		}
		if (getrandomWorked && filled == buf.length)
			return;

		// Fall back to /dev/urandom.
		readDevUrandom(buf);
		return;
	}
	else version (Windows)
	{
		// BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG (0x00000002).
		const status = BCryptGenRandom(null, buf.ptr, cast(uint) buf.length, 0x00000002);
		if (status != 0)
			throw new CsprngException("BCryptGenRandom failed");
		return;
	}
	else version (OSX)
	{
		arc4random_buf(buf.ptr, buf.length);
		return;
	}
	else version (FreeBSD)
	{
		arc4random_buf(buf.ptr, buf.length);
		return;
	}
	else version (NetBSD)
	{
		arc4random_buf(buf.ptr, buf.length);
		return;
	}
	else version (OpenBSD)
	{
		arc4random_buf(buf.ptr, buf.length);
		return;
	}
	else version (DragonFlyBSD)
	{
		arc4random_buf(buf.ptr, buf.length);
		return;
	}
	else version (Posix)
	{
		readDevUrandom(buf);
		return;
	}
	else
	{
		static assert(false, "mcp.auth.csprng: no OS CSPRNG available for this platform");
	}
}

/// Allocate and return `n` cryptographically secure random bytes.
ubyte[] cryptoRandomBytes(size_t n) @safe
{
	auto buf = new ubyte[n];
	cryptoRandomFill(buf);
	return buf;
}

// ===========================================================================
// Platform bindings / helpers
// ===========================================================================

version (linux)
{
	// Raw getrandom(2) syscall: glibc < 2.25 has no wrapper. SYS_getrandom
	// differs by architecture.
	private extern (C) long syscall(long number, ...) @system nothrow @nogc;

	private long sysGetrandom(scope void* buf, size_t buflen, uint flags) @trusted nothrow @nogc
	{
		version (X86_64)
			enum sysno = 318;
		else version (X86)
			enum sysno = 355;
		else version (AArch64)
			enum sysno = 278;
		else version (ARM)
			enum sysno = 384;
		else version (PPC64)
			enum sysno = 359;
		else version (RISCV64)
			enum sysno = 278;
		else
			enum sysno = -1; // unknown: force /dev/urandom fallback
		static if (sysno < 0)
			return -1;
		else
			return syscall(sysno, buf, buflen, flags);
	}
}

version (McpHasDevUrandom) private void readDevUrandom(scope ubyte[] buf) @trusted
{
	import core.sys.posix.unistd : read, close;
	import core.sys.posix.fcntl : open, O_RDONLY;
	import core.stdc.errno : errno, EINTR;

	const fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		throw new CsprngException("cannot open /dev/urandom");
	scope (exit)
		close(fd);
	size_t filled = 0;
	while (filled < buf.length)
	{
		const n = read(fd, &buf[filled], buf.length - filled);
		if (n < 0)
		{
			if (errno == EINTR)
				continue;
			throw new CsprngException("read(/dev/urandom) failed");
		}
		if (n == 0)
			throw new CsprngException("unexpected EOF on /dev/urandom");
		filled += cast(size_t) n;
	}
}

version (OSX)
	private extern (C) void arc4random_buf(scope void* buf, size_t nbytes) @system nothrow @nogc;
else version (FreeBSD)
	private extern (C) void arc4random_buf(scope void* buf, size_t nbytes) @system nothrow @nogc;
else version (NetBSD)
	private extern (C) void arc4random_buf(scope void* buf, size_t nbytes) @system nothrow @nogc;
else version (OpenBSD)
	private extern (C) void arc4random_buf(scope void* buf, size_t nbytes) @system nothrow @nogc;
else version (DragonFlyBSD)
	private extern (C) void arc4random_buf(scope void* buf, size_t nbytes) @system nothrow @nogc;

version (Windows) private extern (C) int BCryptGenRandom(void* hAlgorithm,
		scope ubyte* pbBuffer, uint cbBuffer, uint dwFlags) @system nothrow @nogc;

// ===========================================================================
// Tests
// ===========================================================================

unittest  // cryptoRandomBytes returns the requested length
{
	auto b = cryptoRandomBytes(32);
	assert(b.length == 32);
}

unittest  // cryptoRandomFill into a zero-length buffer is a no-op
{
	ubyte[0] empty;
	cryptoRandomFill(empty[]); // must not throw
}

unittest  // two draws are overwhelmingly unlikely to be identical
{
	auto a = cryptoRandomBytes(32);
	auto b = cryptoRandomBytes(32);
	assert(a != b);
}

unittest  // bytes are not all zero (the OS CSPRNG actually wrote into the buffer)
{
	import std.algorithm : all;

	auto b = cryptoRandomBytes(32);
	assert(!b.all!(x => x == 0));
}

unittest  // the source is the OS CSPRNG, not the default-seeded std.random rndGen
{
	// A fresh, default-seeded Mersenne Twister produces a fixed, predictable
	// sequence. The CSPRNG MUST NOT reproduce that sequence.
	import std.random : rndGen, uniform;

	auto gen = rndGen; // default-seeded Mersenne Twister
	ubyte[32] predictable;
	foreach (ref x; predictable)
		x = cast(ubyte) uniform(0, 256, gen);

	auto secure = cryptoRandomBytes(32);
	assert(secure[] != predictable[]);
}
