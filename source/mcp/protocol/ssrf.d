module mcp.protocol.ssrf;

import core.time : Duration;
import vibe.http.client : HTTPClientRequest, HTTPClientResponse;
import vibe.stream.tls : TLSContext;

@safe:

// ===========================================================================
// SSRF connector — one parser, one address classifier, two policies.
//
// Every outbound HTTP request the SDK makes flows through `secureRequestHTTP`
// (auth/discovery) or `pinnedConnectAddress` (the raw-TCP client transport).
// Both parse the URL with vibe's own `URL`/endpoint parser and then derive BOTH
// the vetted host and the pinned connect address from that single parse, so the
// host that is validated is provably the host that is connected to (no parser
// differential between a guard and the connector).
//
// `classifyHost` is the single address classifier: it handles IPv4 literals in
// every numeric encoding (decimal/octal/hex/inet_aton short forms), IPv6
// literals (including embedded IPv4, ULA, link-local and loopback), and DNS
// resolution of every A/AAAA record, failing CLOSED to `privateOrLinkLocal` on
// a resolution error or when any resolved address is internal.
//
// `SsrfPolicy.blockInternal` rejects loopback/private/link-local hosts and is
// used for every URL an untrusted party names. `SsrfPolicy.allowLoopback` adds
// a plain-http allowance for explicit loopback hosts, for URLs the operator or
// user configured (local development). `SsrfPolicy.allowUserConfigured`
// resolves and pins the address for stability but permits internal/loopback
// targets, for the user-chosen client transport endpoint.
// ===========================================================================

/// The trust class of a host or resolved address.
enum AddressClass
{
	/// A public, global-unicast address (or a registered name resolving only to
	/// such addresses).
	public_,
	/// An explicit loopback host: `localhost`, `127.0.0.0/8` in any numeric
	/// encoding, or `[::1]`.
	loopback,
	/// A private (RFC 1918), link-local, ULA, unspecified, this-host or
	/// embedded-internal address — or a fail-closed result (unresolvable host,
	/// malformed literal, or a resolved internal address).
	privateOrLinkLocal,
}

/// How a fetch treats internal targets.
enum SsrfPolicy
{
	/// Require `https` to a public host: loopback, private and link-local
	/// targets are all rejected. Used for every URL an untrusted party names
	/// (endpoints from discovered OAuth metadata of a remote server, Client ID
	/// Metadata Document URLs, webhook callbacks).
	blockInternal,
	/// As `blockInternal`, but an explicit literal loopback host (`localhost`,
	/// `127.0.0.0/8` in any encoding, `[::1]`) is also permitted over plain
	/// `http` — the local-development allowance. Used only for URLs the operator
	/// or user configured (JWKS, introspection, upstream OAuth endpoints) or that
	/// a user-configured loopback MCP endpoint names.
	allowLoopback,
	/// Resolve and pin the address (TOCTOU-stable) but do NOT reject internal or
	/// loopback targets. Used for the user-chosen MCP client transport endpoint.
	allowUserConfigured,
}

// ---------------------------------------------------------------------------
// Numeric IPv4 literal canonicalization (inet_aton encodings).
// ---------------------------------------------------------------------------

/// Canonicalize a bare all-numeric IPv4 authority host into four octets using
/// `inet_aton` rules so that alternate encodings cannot slip past the SSRF
/// guard. Accepts 1-4 parts where each part may be decimal, octal (`0`-prefix)
/// or hex (`0x`-prefix); a short form lets the final part absorb the remaining
/// low bytes (1 part = 32 bits, 2 parts = a.(24 bits), 3 parts = a.b.(16 bits)).
/// Returns true and fills `outOct` only when the whole host is such a literal;
/// returns false for any host that is not a pure numeric IPv4 literal (e.g. a
/// registered hostname), which the caller treats as "not an IP literal".
/// `@safe pure nothrow @nogc`.
bool canonicalizeNumericIpv4(string host, out ubyte[4] outOct) @safe pure nothrow @nogc
{
	if (host.length == 0)
		return false;

	// Parse 1-4 dot-separated parts, each decimal/octal/hex.
	ulong[4] part;
	size_t parts;
	size_t i;
	while (i < host.length)
	{
		if (parts >= 4)
			return false;
		ulong v;
		size_t digits;
		if (i + 1 < host.length && host[i] == '0' && (host[i + 1] == 'x' || host[i + 1] == 'X'))
		{
			// Hex part.
			i += 2;
			while (i < host.length)
			{
				const ch = host[i];
				uint d;
				if (ch >= '0' && ch <= '9')
					d = cast(uint)(ch - '0');
				else if (ch >= 'a' && ch <= 'f')
					d = cast(uint)(ch - 'a' + 10);
				else if (ch >= 'A' && ch <= 'F')
					d = cast(uint)(ch - 'A' + 10);
				else
					break;
				v = v * 16 + d;
				if (v > 0xFFFF_FFFFUL)
					return false;
				i++;
				digits++;
			}
		}
		else if (host[i] == '0' && i + 1 < host.length && host[i + 1] >= '0'
				&& host[i + 1] <= '7' && !(i + 1 < host.length && host[i + 1] == '.'))
		{
			// Octal part (leading 0 followed by octal digits).
			i++; // skip leading 0
			digits++;
			while (i < host.length && host[i] >= '0' && host[i] <= '7')
			{
				v = v * 8 + cast(uint)(host[i] - '0');
				if (v > 0xFFFF_FFFFUL)
					return false;
				i++;
				digits++;
			}
			// A non-octal digit (8/9) inside an octal part is not a valid literal.
			if (i < host.length && host[i] >= '0' && host[i] <= '9')
				return false;
		}
		else
		{
			// Decimal part.
			while (i < host.length && host[i] >= '0' && host[i] <= '9')
			{
				v = v * 10 + cast(uint)(host[i] - '0');
				if (v > 0xFFFF_FFFFUL)
					return false;
				i++;
				digits++;
			}
		}
		if (digits == 0)
			return false; // empty part -> not a numeric literal
		part[parts++] = v;
		if (i < host.length)
		{
			if (host[i] != '.')
				return false; // trailing junk -> not a numeric literal
			i++;
			if (i == host.length)
				return false; // trailing dot
		}
	}
	if (parts == 0)
		return false;

	// Combine parts per inet_aton short-form rules into a 32-bit address.
	ulong addr;
	final switch (parts)
	{
	case 1:
		addr = part[0];
		break;
	case 2:
		if (part[0] > 0xFF || part[1] > 0x00FF_FFFF)
			return false;
		addr = (part[0] << 24) | part[1];
		break;
	case 3:
		if (part[0] > 0xFF || part[1] > 0xFF || part[2] > 0xFFFF)
			return false;
		addr = (part[0] << 24) | (part[1] << 16) | part[2];
		break;
	case 4:
		if (part[0] > 0xFF || part[1] > 0xFF || part[2] > 0xFF || part[3] > 0xFF)
			return false;
		addr = (part[0] << 24) | (part[1] << 16) | (part[2] << 8) | part[3];
		break;
	}
	if (addr > 0xFFFF_FFFFUL)
		return false;
	outOct[0] = cast(ubyte)((addr >> 24) & 0xFF);
	outOct[1] = cast(ubyte)((addr >> 16) & 0xFF);
	outOct[2] = cast(ubyte)((addr >> 8) & 0xFF);
	outOct[3] = cast(ubyte)(addr & 0xFF);
	return true;
}

/// True when a numeric IPv4 literal has a multi-digit, non-hex part that starts
/// with `0` (e.g. `0127.0.0.1`). `inet_aton` reads such a part as octal but some
/// resolvers (macOS `getaddrinfo`) read it as decimal, so the literal names no
/// single address and the classifiers fail it closed.
private bool hasLeadingZeroPart(string host) @safe pure nothrow @nogc
{
	size_t start;
	foreach (i; 0 .. host.length + 1)
	{
		if (i < host.length && host[i] != '.')
			continue;
		const part = host[start .. i];
		if (part.length > 1 && part[0] == '0' && part[1] != 'x' && part[1] != 'X')
			return true;
		start = i + 1;
	}
	return false;
}

/// The canonical dotted-quad text of `oct`.
private string dottedQuad(const ubyte[4] oct) @safe pure nothrow
{
	import std.conv : to;

	return oct[0].to!string ~ "." ~ oct[1].to!string ~ "." ~ oct[2].to!string
		~ "." ~ oct[3].to!string;
}

// ---------------------------------------------------------------------------
// IPv6 literal parsing.
// ---------------------------------------------------------------------------

/// Parse an IPv6 literal (the inner text of a bracketed host, with any zone-id
/// stripped) into 16 bytes, expanding a `::` run. Returns false (fail closed)
/// on any malformed input. Handles the embedded-IPv4 tail forms
/// (`::ffff:a.b.c.d`, `::a.b.c.d`) by parsing the dotted-decimal suffix into the
/// final 4 bytes. `@safe pure nothrow @nogc`.
private bool parseIpv6Literal(string s, out ubyte[16] outBytes) @safe pure nothrow @nogc
{
	import std.string : indexOf;

	// Strip a zone id (e.g. fe80::1%eth0).
	const pct = s.indexOf('%');
	if (pct >= 0)
		s = s[0 .. pct];
	if (s.length == 0)
		return false;

	// Detect and parse a trailing embedded IPv4 (dotted-decimal) tail.
	bool haveV4;
	ubyte[4] v4;
	{
		// Find the last ':' — the IPv4 tail (if any) follows it.
		ptrdiff_t lastColon = -1;
		foreach (k, ch; s)
			if (ch == ':')
				lastColon = k;
		auto tail = (lastColon < 0) ? s : s[lastColon + 1 .. $];
		bool hasDot;
		foreach (ch; tail)
			if (ch == '.')
				hasDot = true;
		if (hasDot)
		{
			uint[4] oct;
			size_t idx;
			size_t i;
			while (i < tail.length)
			{
				uint v;
				size_t digits;
				// A multi-digit octet starting with `0` is octal to some resolvers
				// and decimal here; reject the ambiguous spelling.
				if (i + 1 < tail.length && tail[i] == '0' && tail[i + 1] >= '0' && tail[i + 1] <= '9')
					return false;
				while (i < tail.length && tail[i] >= '0' && tail[i] <= '9')
				{
					v = v * 10 + cast(uint)(tail[i] - '0');
					if (v > 255)
						return false;
					i++;
					digits++;
				}
				if (digits == 0)
					return false;
				if (idx >= 4)
					return false;
				oct[idx++] = v;
				if (i < tail.length)
				{
					if (tail[i] != '.')
						return false;
					i++;
				}
			}
			if (idx != 4)
				return false;
			v4 = [
				cast(ubyte) oct[0], cast(ubyte) oct[1], cast(ubyte) oct[2],
				cast(ubyte) oct[3]
			];
			haveV4 = true;
			// Replace the IPv4 tail with the hextet portion for hextet parsing,
			// dropping the separator colon unless it closes a `::`.
			if (lastColon < 0)
				s = "";
			else if (lastColon > 0 && s[lastColon - 1] == ':')
				s = s[0 .. lastColon + 1];
			else
				s = s[0 .. lastColon];
		}
	}

	// Split on "::" (at most one allowed).
	ptrdiff_t dbl = -1;
	for (size_t k = 0; k + 1 < s.length; k++)
	{
		if (s[k] == ':' && s[k + 1] == ':')
		{
			dbl = k;
			break;
		}
	}

	const v4bytes = haveV4 ? 4 : 0;
	const totalHextetBytes = 16 - v4bytes;

	if (dbl < 0)
	{
		// No "::": must fully fill the hextet area.
		ubyte[16] tmp;
		const n = parseHextets(s, tmp[0 .. totalHextetBytes]);
		if (n != totalHextetBytes)
			return false;
		outBytes[0 .. totalHextetBytes] = tmp[0 .. totalHextetBytes];
	}
	else
	{
		auto left = s[0 .. dbl];
		auto right = (dbl + 2 <= s.length) ? s[dbl + 2 .. $] : "";
		// A leading or trailing ':' adjacent to "::" (i.e. ":::") is invalid; left
		// must not end with ':' and right must not start with ':'.
		if (left.length && left[$ - 1] == ':')
			return false;
		if (right.length && right[0] == ':')
			return false;
		ubyte[16] lbuf;
		ubyte[16] rbuf;
		const ln = parseHextets(left, lbuf[]);
		if (ln < 0)
			return false;
		const rn = parseHextets(right, rbuf[]);
		if (rn < 0)
			return false;
		if (ln + rn > totalHextetBytes)
			return false;
		outBytes[] = 0;
		outBytes[0 .. ln] = lbuf[0 .. ln];
		outBytes[totalHextetBytes - rn .. totalHextetBytes] = rbuf[0 .. rn];
	}

	if (haveV4)
		outBytes[12 .. 16] = v4[];
	return true;
}

/// Render 16 IPv6 address bytes in the RFC 5952 canonical text form: lowercase
/// hextets without leading zeros, with the longest run of two or more zero
/// hextets (the first, on a tie) compressed to `::`.
private string renderIpv6(const ubyte[16] b) @safe pure nothrow
{
	ushort[8] h;
	foreach (i; 0 .. 8)
		h[i] = cast(ushort)((b[2 * i] << 8) | b[2 * i + 1]);

	ptrdiff_t bestStart = -1;
	size_t bestLen;
	for (size_t i = 0; i < 8;)
	{
		if (h[i] != 0)
		{
			i++;
			continue;
		}
		size_t j = i;
		while (j < 8 && h[j] == 0)
			j++;
		if (j - i > bestLen)
		{
			bestStart = i;
			bestLen = j - i;
		}
		i = j;
	}
	if (bestLen < 2)
		bestStart = -1;

	static immutable hexDigits = "0123456789abcdef";
	string s;
	for (size_t i = 0; i < 8;)
	{
		if (i == bestStart)
		{
			s ~= "::";
			i += bestLen;
			continue;
		}
		if (s.length && s[$ - 1] != ':')
			s ~= ':';
		bool started;
		foreach (shift; [12, 8, 4, 0])
		{
			const nibble = (h[i] >> shift) & 0xF;
			if (nibble != 0 || started || shift == 0)
			{
				s ~= hexDigits[nibble];
				started = true;
			}
		}
		i++;
	}
	return s;
}

/// Parse a colon-separated list of IPv6 hextets into bytes; returns count of
/// bytes written, or -1 on error. An empty segment yields 0 bytes.
private ptrdiff_t parseHextets(string seg, ubyte[] dst) @safe pure nothrow @nogc
{
	if (seg.length == 0)
		return 0;
	size_t written;
	size_t i;
	while (i <= seg.length)
	{
		// Read one hextet (1-4 hex digits) up to ':' or end.
		uint v;
		size_t digits;
		while (i < seg.length && seg[i] != ':')
		{
			const ch = seg[i];
			uint d;
			if (ch >= '0' && ch <= '9')
				d = ch - '0';
			else if (ch >= 'a' && ch <= 'f')
				d = ch - 'a' + 10;
			else if (ch >= 'A' && ch <= 'F')
				d = ch - 'A' + 10;
			else
				return -1;
			v = (v << 4) | d;
			digits++;
			if (digits > 4)
				return -1;
			i++;
		}
		if (digits == 0)
			return -1;
		if (written + 2 > dst.length)
			return -1;
		dst[written++] = cast(ubyte)(v >> 8);
		dst[written++] = cast(ubyte)(v & 0xff);
		if (i == seg.length)
			break;
		i++; // skip ':'
		if (i == seg.length)
			return -1; // trailing single ':'
	}
	return written;
}

// ---------------------------------------------------------------------------
// Range checks.
// ---------------------------------------------------------------------------

/// Range-check four IPv4 octets. Returns the class: loopback (127/8), private/
/// link-local/this-host/special-purpose (RFC 1918, 169.254/16, 0/8, CGNAT,
/// IETF-assigned, benchmarking, documentation, multicast, reserved), or public. `@safe pure
/// nothrow @nogc`.
private AddressClass classifyIpv4Octets(ubyte a, ubyte b, ubyte c, ubyte d) @safe pure nothrow @nogc
{
	if (a == 127) // 127.0.0.0/8 loopback
		return AddressClass.loopback;
	if (a == 10) // 10.0.0.0/8
		return AddressClass.privateOrLinkLocal;
	if (a == 172 && b >= 16 && b <= 31) // 172.16.0.0/12
		return AddressClass.privateOrLinkLocal;
	if (a == 192 && b == 168) // 192.168.0.0/16
		return AddressClass.privateOrLinkLocal;
	if (a == 169 && b == 254) // 169.254.0.0/16 link-local (incl. metadata 169.254.169.254)
		return AddressClass.privateOrLinkLocal;
	if (a == 100 && b >= 64 && b <= 127) // 100.64.0.0/10 RFC 6598 carrier-grade-NAT shared space (not globally routable)
		return AddressClass.privateOrLinkLocal;
	if (a == 0) // 0.0.0.0/8 "this host"
		return AddressClass.privateOrLinkLocal;
	if (a == 192 && b == 0 && (c == 0 || c == 2)) // 192.0.0.0/24 IETF protocol assignments, 192.0.2.0/24 TEST-NET-1
		return AddressClass.privateOrLinkLocal;
	if (a == 198 && (b == 18 || b == 19)) // 198.18.0.0/15 benchmarking
		return AddressClass.privateOrLinkLocal;
	if (a == 198 && b == 51 && c == 100) // 198.51.100.0/24 TEST-NET-2
		return AddressClass.privateOrLinkLocal;
	if (a == 203 && b == 0 && c == 113) // 203.0.113.0/24 TEST-NET-3
		return AddressClass.privateOrLinkLocal;
	if (a >= 224 && a <= 239) // 224.0.0.0/4 multicast (not a unicast destination)
		return AddressClass.privateOrLinkLocal;
	if (a >= 240) // 240.0.0.0/4 reserved/future-use, incl. 255.255.255.255 broadcast
		return AddressClass.privateOrLinkLocal;
	return AddressClass.public_;
}

/// Classify an IPv6 *literal* (the inner text of a bracketed `[...]` host, or a
/// bracketless IPv6 host as produced by vibe's parser). Unparseable literals
/// fail closed (`privateOrLinkLocal`). `@safe pure nothrow @nogc`.
private AddressClass classifyIpv6Literal(string inner) @safe pure nothrow @nogc
{
	ubyte[16] b;
	if (!parseIpv6Literal(inner, b))
		return AddressClass.privateOrLinkLocal; // fail closed

	// Unspecified "::".
	bool allZero = true;
	foreach (x; b)
		if (x != 0)
		{
			allZero = false;
			break;
		}
	if (allZero)
		return AddressClass.privateOrLinkLocal;

	// Loopback ::1.
	bool isLoopbackV6 = true;
	foreach (k; 0 .. 15)
		if (b[k] != 0)
		{
			isLoopbackV6 = false;
			break;
		}
	if (isLoopbackV6 && b[15] == 1)
		return AddressClass.loopback;

	// ULA fc00::/7 (first byte 0xFC or 0xFD).
	if (b[0] == 0xFC || b[0] == 0xFD)
		return AddressClass.privateOrLinkLocal;
	// Link-local fe80::/10 (0xFE 0x80..0xBF).
	if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80)
		return AddressClass.privateOrLinkLocal;
	// Deprecated site-local fec0::/10 (0xFE 0xC0..0xFF), still routed internally
	// by some networks.
	if (b[0] == 0xFE && (b[1] & 0xC0) == 0xC0)
		return AddressClass.privateOrLinkLocal;
	// Multicast ff00::/8 (first byte 0xFF) — not a unicast destination.
	if (b[0] == 0xFF)
		return AddressClass.privateOrLinkLocal;

	// IPv4-mapped ::ffff:a.b.c.d/96 and IPv4-compatible ::/96 (first 12 bytes
	// either 0...0 ffff or all zero) — extract the embedded IPv4 and classify it.
	bool mapped = true;
	foreach (k; 0 .. 10)
		if (b[k] != 0)
		{
			mapped = false;
			break;
		}
	if (mapped && ((b[10] == 0xFF && b[11] == 0xFF) || (b[10] == 0 && b[11] == 0)))
		return classifyIpv4Octets(b[12], b[13], b[14], b[15]);

	// IPv4-translated ::ffff:0:a.b.c.d/96 (RFC 2765 SIIT): bytes 0..7 zero,
	// then ff ff 00 00, then the IPv4 a translator routes to.
	bool translated = true;
	foreach (k; 0 .. 8)
		if (b[k] != 0)
		{
			translated = false;
			break;
		}
	if (translated && b[8] == 0xFF && b[9] == 0xFF && b[10] == 0 && b[11] == 0)
		return classifyIpv4Octets(b[12], b[13], b[14], b[15]);

	// An IPv4 embedded in a 6to4 or NAT64 address is reached through a relay or
	// gateway, not on this host, so an embedded 127.x is internal but never the
	// literal-loopback dev allowance.
	static AddressClass routed(AddressClass c) @safe pure nothrow @nogc
	{
		return c == AddressClass.loopback ? AddressClass.privateOrLinkLocal : c;
	}

	// 6to4 2002::/16 (RFC 3056) carries the relay-routed IPv4 in bytes 2..5.
	if (b[0] == 0x20 && b[1] == 0x02)
		return routed(classifyIpv4Octets(b[2], b[3], b[4], b[5]));

	// NAT64 prefixes carry an embedded IPv4 that a NAT64 gateway translates and
	// routes. Well-known 64:ff9b::/96 (RFC 6052): 00 64 ff 9b then bytes 4..11
	// zero, with the IPv4 in the low 32 bits.
	if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B)
	{
		bool wellKnown = true;
		foreach (k; 4 .. 12)
			if (b[k] != 0)
			{
				wellKnown = false;
				break;
			}
		if (wellKnown)
			return routed(classifyIpv4Octets(b[12], b[13], b[14], b[15]));
		// Local-use 64:ff9b:1::/48 (RFC 8215): 00 64 ff 9b 00 01. Its prefix
		// length, and so where the IPv4 sits, is a local choice, so the whole
		// block is internal.
		if (b[4] == 0x00 && b[5] == 0x01)
			return AddressClass.privateOrLinkLocal;
	}

	// Teredo 2001::/32 (RFC 4380) tunnels to an obfuscated IPv4 client address
	// via a relay; it is never a direct public destination, so fail closed.
	if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0 && b[3] == 0)
		return AddressClass.privateOrLinkLocal;

	return AddressClass.public_;
}

/// Whether `name` is the loopback name `localhost`. Host names compare
/// case-insensitively, and one trailing dot marks the same name fully qualified.
private bool isLocalhostName(string name) @safe pure nothrow @nogc
{
	import std.ascii : toLower;

	enum lh = "localhost";
	if (name.length && name[$ - 1] == '.')
		name = name[0 .. $ - 1];
	if (name.length != lh.length)
		return false;
	foreach (i, c; name)
		if (toLower(c) != lh[i])
			return false;
	return true;
}

/// Classify a resolved address given as its numeric string form (as produced by
/// `std.socket.Address.toAddrString`). Empty/unparseable forms fail closed.
/// `@safe pure nothrow @nogc`.
private AddressClass classifyResolvedAddress(string addr) @safe pure nothrow @nogc
{
	import std.string : indexOf;

	// Strip a zone id if the resolver attached one (e.g. fe80::1%en0).
	const pct = addr.indexOf('%');
	if (pct >= 0)
		addr = addr[0 .. pct];
	if (addr.length == 0)
		return AddressClass.privateOrLinkLocal; // fail closed

	// IPv6 addresses contain a ':'; IPv4 (dotted or numeric) never does.
	if (addr.indexOf(':') >= 0)
		return classifyIpv6Literal(addr);

	ubyte[4] oct;
	if (!canonicalizeNumericIpv4(addr, oct))
		return AddressClass.privateOrLinkLocal; // unrecognized literal -> fail closed
	return classifyIpv4Octets(oct[0], oct[1], oct[2], oct[3]);
}

// ---------------------------------------------------------------------------
// Host splitting helpers.
// ---------------------------------------------------------------------------

/// Strip an optional `:port` suffix from a host, leaving a bracketless IPv6
/// literal's colons intact. A single trailing colon is a port separator; two or
/// more colons mark a bracketless IPv6 address. A bracketed `[...]` host returns
/// its inner text. `@safe pure nothrow @nogc`.
private string stripPortAndBrackets(string host) @safe pure nothrow @nogc
{
	import std.string : indexOf;

	if (host.length && host[0] == '[')
	{
		const close = host.indexOf(']');
		if (close > 0)
			return host[1 .. close];
		return host[1 .. $]; // malformed; classifier fails it closed
	}
	const colon = host.indexOf(':');
	if (colon >= 0 && host.indexOf(':', colon + 1) < 0)
		return host[0 .. colon];
	return host;
}

// ---------------------------------------------------------------------------
// The single classifier.
// ---------------------------------------------------------------------------

/// Classify `host` (an authority host, optionally bracketed and/or with a
/// `:port` suffix) and produce the numeric address to pin the connection to in
/// `pinnedIp`. This is the SINGLE address classifier all SSRF decisions flow
/// through:
///
/// - IPv4 literals in every numeric encoding are classified directly and
///   `pinnedIp` is their canonical dotted quad. A literal with a multi-digit
///   part that starts with `0` (`0127.0.0.1`) is octal to `inet_aton` but
///   decimal to some resolvers, so it is `privateOrLinkLocal` with an empty
///   `pinnedIp` (fail CLOSED).
/// - IPv6 literals (including embedded-IPv4, ULA, link-local and loopback) are
///   classified directly and `pinnedIp` is the RFC 5952 rendering of the parsed
///   bytes (unbracketed, no port, zone id kept). An unparseable literal is
///   `privateOrLinkLocal` with an empty `pinnedIp` (fail CLOSED).
/// - `localhost` is classified as loopback and pinned to `127.0.0.1`, so the
///   connection never re-resolves the name.
/// - A registered hostname is resolved; EVERY returned A/AAAA address is
///   classified and `pinnedIp` is set to the first one. If ANY resolved address
///   is loopback/private/link-local the result is `privateOrLinkLocal` (resolved
///   loopback is demoted to private so it cannot claim the literal-loopback dev
///   allowance — DNS-rebinding guard). On a resolution error (or no usable
///   record) the result is `privateOrLinkLocal` with an empty `pinnedIp` (fail
///   CLOSED).
///
/// `@safe` (DNS resolution is `@system` in `std.socket`; wrapped here).
AddressClass classifyHost(string host, out string pinnedIp) @safe
{
	pinnedIp = "";
	if (host.length == 0)
		return AddressClass.privateOrLinkLocal; // fail closed

	const bare = stripPortAndBrackets(host);
	if (bare.length == 0)
		return AddressClass.privateOrLinkLocal;

	// Bracketed or bracketless IPv6 literal (contains ':').
	{
		import std.string : indexOf;

		if (host[0] == '[' || (bare.indexOf(':') >= 0 && bare.indexOf('.') < 0)
				|| (bare.indexOf(':') >= 0 && bare.indexOf("::") >= 0))
		{
			ubyte[16] bytes;
			if (!parseIpv6Literal(bare, bytes))
				return AddressClass.privateOrLinkLocal; // fail closed
			// Pin the parsed address, not the text as written, so the connection
			// reaches exactly the classified bytes; a zone id is kept verbatim.
			const pct = bare.indexOf('%');
			pinnedIp = renderIpv6(bytes) ~ (pct >= 0 ? bare[pct .. $] : "");
			return classifyIpv6Literal(bare);
		}
	}

	if (isLocalhostName(bare))
	{
		pinnedIp = "127.0.0.1";
		return AddressClass.loopback;
	}

	// A numeric IPv4 literal in any encoding — classify directly and pin the
	// canonical dotted quad, so the connection reaches exactly the classified
	// address whatever the resolver makes of the original spelling.
	ubyte[4] oct;
	if (canonicalizeNumericIpv4(bare, oct))
	{
		if (hasLeadingZeroPart(bare))
			return AddressClass.privateOrLinkLocal; // ambiguous literal -> fail CLOSED
		pinnedIp = dottedQuad(oct);
		return classifyIpv4Octets(oct[0], oct[1], oct[2], oct[3]);
	}

	// A registered hostname: resolve and vet every returned address.
	const res = resolveHostAddresses(bare);
	if (res.failed || res.addresses.length == 0)
		return AddressClass.privateOrLinkLocal; // unresolved / no usable record -> fail CLOSED
	AddressClass worst = AddressClass.public_;
	foreach (addr; res.addresses)
	{
		auto cls = classifyResolvedAddress(addr);
		// A resolved loopback address is demoted to private/link-local: the
		// literal-loopback dev allowance applies only to literal hosts
		// (localhost/127.x/[::1], handled above before this DNS branch), never to
		// a registered name an attacker can point at 127.x via DNS.
		if (cls == AddressClass.loopback)
			cls = AddressClass.privateOrLinkLocal;
		// A single internal address taints the whole host (DNS-rebinding guard).
		if (cls != AddressClass.public_)
			worst = cls;
	}
	pinnedIp = res.addresses[0];
	return worst;
}

/// The numeric A/AAAA addresses a name resolves to, or `failed` when the
/// resolver reported an error.
private struct Resolution
{
	string[] addresses;
	bool failed;
}

/// Resolve `host` with the system resolver (`getaddrinfo`), keeping every
/// IPv4/IPv6 address. Blocks the calling thread.
private Resolution systemResolve(string host) @trusted nothrow
{
	import std.socket : getAddressInfo, AddressFamily;

	Resolution r;
	try
	{
		foreach (info; getAddressInfo(host))
			if (info.family == AddressFamily.INET || info.family == AddressFamily.INET6)
				r.addresses ~= info.address.toAddrString();
	}
	catch (Exception)
		r.failed = true;
	return r;
}

/// The resolver `classifyHost` uses for registered names.
private __gshared Resolution function(string) @safe nothrow hostResolver = &systemResolve;

/// Resolve `host` through `hostResolver` on a worker thread: the system
/// resolver blocks, and running it on the caller's event loop would stall every
/// other task there until it returns. The caller waits without blocking its
/// thread.
private Resolution resolveHostAddresses(string host) @trusted
{
	import vibe.core.concurrency : asyncWork;

	return asyncWork(hostResolver, host).getResult();
}

// ---------------------------------------------------------------------------
// The connector.
// ---------------------------------------------------------------------------

/// Classify `host` WITHOUT performing DNS resolution: IP literals (every numeric
/// IPv4 encoding and IPv6 incl. embedded-IPv4/ULA/link-local/loopback) and the
/// explicit loopback names (`localhost`) are classified directly; any registered
/// hostname is treated as `public_` (a lexical pre-filter cannot know what it
/// resolves to — the resolve-and-pin connector makes the authoritative call).
/// An IPv4 literal with a leading-zero multi-digit part is `privateOrLinkLocal`,
/// as in `classifyHost`. `@safe pure nothrow @nogc`.
AddressClass classifyHostLexical(string host) @safe pure nothrow @nogc
{
	import std.string : indexOf;

	if (host.length == 0)
		return AddressClass.privateOrLinkLocal; // fail closed

	const bare = stripPortAndBrackets(host);
	if (bare.length == 0)
		return AddressClass.privateOrLinkLocal;

	// Bracketed or bracketless IPv6 literal (contains ':').
	if (host[0] == '[' || (bare.indexOf(':') >= 0 && bare.indexOf('.') < 0)
			|| (bare.indexOf(':') >= 0 && bare.indexOf("::") >= 0))
		return classifyIpv6Literal(bare);

	if (isLocalhostName(bare))
		return AddressClass.loopback;

	ubyte[4] oct;
	if (canonicalizeNumericIpv4(bare, oct))
	{
		if (hasLeadingZeroPart(bare))
			return AddressClass.privateOrLinkLocal; // ambiguous literal -> fail closed
		return classifyIpv4Octets(oct[0], oct[1], oct[2], oct[3]);
	}

	// A registered hostname: lexically public (no resolution here).
	return AddressClass.public_;
}

/// The result of vetting an endpoint for a raw-TCP connect: the numeric address
/// to `connectTCP` to (`pinnedIp`, port stripped), the original host to use for
/// the `Host` header and TLS SNI (`sniHost`), and whether the endpoint passed
/// the policy (`ok`).
struct PinnedConnect
{
	string pinnedIp;
	string sniHost;
	bool ok;
}

/// Vet a `host` (authority host, optionally bracketed / with a `:port` suffix)
/// against `policy` for a raw-TCP connect, returning the address to connect to
/// and the SNI/Host name to present. `tls` records whether the connection uses
/// TLS.
///
/// `blockInternal`: only public hosts pass.
/// `allowLoopback`: public hosts pass, and an explicit literal-loopback host
/// (`localhost`, `127.x` in any encoding, `[::1]`) passes over plain http as
/// the dev-loopback allowance; loopback over TLS and a registered name that
/// DNS-resolves to loopback are rejected (`classifyHost` demotes resolved
/// loopback to private). A caller that must reach a loopback TLS service uses
/// `allowUserConfigured`.
/// `allowUserConfigured`: every classifiable host passes (loopback and private
/// included); only a fail-closed classification (unresolvable / malformed)
/// is rejected.
///
/// The returned `pinnedIp` has any `:port` suffix stripped and bracketing
/// preserved for IPv6 so the caller pins the connection to the vetted address.
/// `@safe`.
PinnedConnect pinnedConnectAddress(string host, bool tls, SsrfPolicy policy) @safe
{
	import std.string : indexOf;

	PinnedConnect r;
	string pinned;
	const cls = classifyHost(host, pinned);

	// A fail-closed classification (empty pin) is always rejected.
	if (pinned.length == 0)
		return r;

	final switch (policy)
	{
	case SsrfPolicy.blockInternal:
		if (cls == AddressClass.public_)
			break;
		return r; // loopback, private/link-local -> reject
	case SsrfPolicy.allowLoopback:
		if (cls == AddressClass.public_)
			break;
		// Literal loopback is the plain-http dev allowance only: over TLS it would
		// reach local TLS services (admin consoles, sidecars).
		if (cls == AddressClass.loopback && !tls)
			break;
		return r; // loopback over TLS, private/link-local -> reject
	case SsrfPolicy.allowUserConfigured:
		break; // any classifiable host is permitted
	}

	// Derive the SNI/Host name (host with the port suffix removed, brackets kept
	// off — vibe's TLS layer wants the bare name).
	r.sniHost = stripPortAndBrackets(host);

	// Strip a port suffix from the pinned address (the caller keeps its own port).
	string connHost = pinned;
	if (connHost.length && connHost[0] == '[')
	{
		const close = connHost.indexOf(']');
		if (close > 0)
			connHost = connHost[1 .. close];
	}
	else if (connHost.length)
	{
		const c = connHost.indexOf(':');
		// IPv4/host:port carries a single ':'; a bracketless IPv6 literal has many.
		if (c >= 0 && connHost.indexOf(':', c + 1) < 0)
			connHost = connHost[0 .. c];
	}
	r.pinnedIp = connHost;
	r.ok = true;
	return r;
}

/// How outbound TLS connections validate the server certificate.
struct TlsTrust
{
	/// A PEM file of CA certificates to trust in place of the system store — a
	/// private CA, or the certificate of a self-signed development server. Empty
	/// (the default) trusts the system CA bundle: the file named by
	/// `SSL_CERT_FILE` when set, else OpenSSL's default bundle, else a
	/// well-known platform location. Where no system bundle exists (e.g.
	/// Windows) set this or `SSL_CERT_FILE`; TLS connections fail otherwise.
	string caFile;

	/// Accept any server certificate without verifying its chain or host name.
	/// For local development and tests against self-signed servers only: it
	/// leaves every TLS connection open to interception.
	bool insecureSkipVerify;
}

/// Per-request knobs for `secureRequestHTTP`.
struct FetchOptions
{
	import core.time : seconds;

	/// Overall bound on the request — name resolution, connect, sending, and
	/// reading the response, however slowly the server trickles bytes — so an
	/// unresponsive endpoint cannot hold the calling task indefinitely. Zero
	/// removes the bound.
	Duration timeout = 30.seconds;

	/// Certificate validation for `https` URLs.
	TlsTrust tls;
}

/// The system CA bundle: the file `SSL_CERT_FILE` names, else OpenSSL's
/// compiled-in default, else the first well-known platform bundle that exists.
/// Empty when none is found. Resolved once per thread.
private string systemCaBundle() @trusted
{
	import deimos.openssl.x509 : X509_get_default_cert_file, X509_get_default_cert_file_env;
	import std.file : exists, isFile;
	import std.process : environment;
	import std.string : fromStringz;

	static bool resolved;
	static string bundle;
	if (resolved)
		return bundle;
	resolved = true;

	string[] candidates = [
		environment.get(fromStringz(X509_get_default_cert_file_env()).idup, ""),
		fromStringz(X509_get_default_cert_file()).idup,
		"/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
		"/etc/ssl/ca-bundle.pem", "/usr/local/etc/openssl/cert.pem",
		"/usr/local/share/certs/ca-root-nss.crt",
	];
	foreach (c; candidates)
	{
		try
		{
			if (c.length && exists(c) && isFile(c))
			{
				bundle = c;
				break;
			}
		}
		catch (Exception)
		{
		}
	}
	return bundle;
}

/// Build the setup for a client TLS context that validates servers under
/// `trust`: the full chain against the trusted CAs plus the host name, or
/// nothing when `trust.insecureSkipVerify` is set. The CA bundle is resolved
/// here, so a missing bundle throws before any connection is attempted rather
/// than letting one proceed unverified.
void delegate(TLSContext) @safe nothrow tlsContextSetup(TlsTrust trust) @safe
{
	import mcp.protocol.errors : internalError;
	import vibe.stream.tls : TLSPeerValidationMode;

	if (trust.insecureSkipVerify)
		return (TLSContext ctx) @safe nothrow{
		try
			ctx.peerValidationMode = TLSPeerValidationMode.none;
		catch (Exception)
		{
		}
	};

	const caFile = trust.caFile.length ? trust.caFile : systemCaBundle();
	if (caFile.length == 0)
		throw internalError("No CA bundle is available to verify TLS server certificates; "
				~ "set SSL_CERT_FILE or TlsTrust.caFile");
	return (TLSContext ctx) @safe nothrow{
		// A bundle that fails to load leaves the trust store empty, so every
		// handshake is refused.
		try
		{
			ctx.peerValidationMode = TLSPeerValidationMode.trustedCert;
			ctx.useTrustedCertificateFile(caFile);
		}
		catch (Exception)
		{
		}
	};
}

/// SSRF-safe HTTP fetch. Parses `url` with vibe's `URL` — the exact parser the
/// connector uses — so the host vetted is the host connected to (no parser
/// differential). The host is classified ONCE via `classifyHost`; under
/// `policy` an internal target is rejected (`blockInternal`; `allowLoopback`
/// excepts plain-http literal loopback) or pinned-but-permitted
/// (`allowUserConfigured`). The request
/// URL's host is rewritten to the vetted numeric IP and the connection pinned to
/// it, while the original hostname is preserved for the `Host` header and TLS
/// SNI (no TOCTOU re-resolution).
///
/// An `https` server must present a certificate chaining to a trusted CA and
/// matching the original host name; `options.tls` selects the trusted CAs.
/// `options.timeout` bounds the whole request.
///
/// Throws `invalidRequest` when the URL is unsafe under `policy` (insecure
/// scheme for `blockInternal`/`allowLoopback`, an internal IP-literal/resolved address, or an
/// unresolvable host — fail CLOSED), and `internalError` when the request
/// times out.
void secureRequestHTTP(string url, SsrfPolicy policy,
		scope void delegate(scope HTTPClientRequest) @safe requester,
		scope void delegate(scope HTTPClientResponse) @safe responder,
		FetchOptions options = FetchOptions.init) @safe
{
	import mcp.protocol.errors : internalError;
	import vibe.core.core : setTimer, Timer;
	import vibe.core.task : InterruptException, Task;

	// The deadline interrupts the calling task when it elapses, cutting short
	// whichever step (resolution, connect, or a drip-fed read) is in progress.
	// Outside a task the per-operation connect/read timeouts still apply.
	auto self = Task.getThis();
	bool finished, expired;
	Timer deadline;
	if (options.timeout > Duration.zero && self != Task.init)
		deadline = setTimer(options.timeout, () @safe nothrow{
			if (finished)
				return;
			expired = true;
			self.interrupt();
		});
	scope (exit)
	{
		finished = true;
		if (deadline)
			deadline.stop();
	}
	try
		fetchPinned(url, policy, requester, responder, options);
	catch (InterruptException e)
	{
		if (!expired)
			throw e;
		throw internalError("Request timed out after " ~ options.timeout.toString());
	}
}

/// The body of `secureRequestHTTP`: vet, pin and perform the request.
private void fetchPinned(string url, SsrfPolicy policy,
		scope void delegate(scope HTTPClientRequest) @safe requester,
		scope void delegate(scope HTTPClientResponse) @safe responder, FetchOptions options) @safe
{
	import mcp.protocol.errors : invalidRequest;
	import vibe.inet.url : URL;
	import vibe.http.client : HTTPClient, HTTPClientSettings;
	import vibe.http.internal.basic_auth_client : addBasicAuth;

	string scheme, host;
	try
	{
		auto parsed = URL(url);
		scheme = parsed.schema;
		host = parsed.host;
	}
	catch (Exception)
	{
		// Unparseable -> fail closed.
	}
	if (host.length == 0)
		throw invalidRequest("Refusing to fetch URL with no parseable host: " ~ url);

	// Scheme gate: https to any host, plus (allowLoopback only) http to an
	// explicit loopback host for dev. allowUserConfigured leaves the scheme to
	// the caller (the transport already enforces its own scheme rules).
	const isHttps = eqSchemeAscii(scheme, "https");
	const isHttp = eqSchemeAscii(scheme, "http");
	const tls = isHttps;

	if (policy == SsrfPolicy.blockInternal && !isHttps)
		throw invalidRequest(
				"Refusing to fetch insecure URL (must be https to a public host): " ~ url);
	if (policy == SsrfPolicy.allowLoopback)
	{
		// The lexical class (no DNS) decides the scheme; the resolved-address
		// verdict comes from pinnedConnectAddress below.
		const loopback = classifyHostLexical(host) == AddressClass.loopback;
		if (!(isHttps || (isHttp && loopback)))
			throw invalidRequest(
					"Refusing to fetch insecure URL (must be https, or http to an explicit "
					~ "loopback host; private/link-local addresses are rejected): " ~ url);
	}

	const pin = pinnedConnectAddress(host, tls, policy);
	if (!pin.ok)
		throw invalidRequest("Refusing to fetch URL whose host resolves to a "
				~ "private/link-local address (or could not be resolved): " ~ url);

	// Build the pinned URL: same scheme/path/port/userinfo, host replaced by the
	// vetted numeric address so the connector cannot re-resolve to a different
	// (internal) target. Preserve the original host for Host header + SNI.
	const originalHost = host;
	auto u = URL(url);
	u.host = pin.pinnedIp;

	auto settings = new HTTPClientSettings;
	settings.tlsPeerName = originalHost;
	if (tls)
		settings.tlsContextSetup = tlsContextSetup(options.tls);
	if (options.timeout > Duration.zero)
	{
		settings.connectTimeout = options.timeout;
		settings.readTimeout = options.timeout;
	}

	// Restore the original host so the server sees the intended virtual host,
	// not the pinned IP.
	string hostHeader = buildHostHeader(originalHost, u.port, u.defaultPort);

	// A dedicated connection per request rather than vibe's shared pool: the
	// pool is keyed by host and port only, so a connection opened under one
	// TLS trust setting (e.g. insecureSkipVerify) would otherwise be handed to
	// a later request that expects full certificate verification.
	auto client = new HTTPClient;
	client.connect(u.host, u.port, tls, settings);
	scope (exit)
		client.disconnect();
	client.request((scope HTTPClientRequest req) {
		req.requestURL = u.localURI;
		req.headers["Host"] = hostHeader;
		if (u.username.length)
			req.addBasicAuth(u.username, u.password);
		if (requester !is null)
			requester(req);
	}, (scope HTTPClientResponse res) {
		if (responder !is null)
			responder(res);
	});
}

/// Build the RFC 7230 §5.4 Host header value from a bare host string (as
/// returned by vibe's URL.host, which strips brackets from IPv6 literals) and
/// the connection's port numbers. IPv6 literals (detected by a colon in the
/// host string) are re-bracketed per RFC 3986 §3.2.2; the port suffix is
/// appended only when the port is non-zero and differs from the scheme default.
private string buildHostHeader(string host, ushort port, ushort defaultPort) @safe pure
{
	import std.conv : to;
	import std.string : indexOf;

	// Re-bracket IPv6 literals stripped by vibe's URL parser.
	string base = host.indexOf(':') >= 0 ? "[" ~ host ~ "]" : host;
	if (port && port != defaultPort)
		return base ~ ":" ~ port.to!string;
	return base;
}

/// Case-insensitive ASCII scheme compare without allocating.
private bool eqSchemeAscii(string scheme, string sc) @safe pure nothrow @nogc
{
	if (scheme.length != sc.length)
		return false;
	foreach (k, ch; scheme)
	{
		char c = ch;
		if (c >= 'A' && c <= 'Z')
			c = cast(char)(c + 32);
		if (c != sc[k])
			return false;
	}
	return true;
}

// ===========================================================================
// Unit tests — the consolidated classifier and the two policies.
// ===========================================================================

unittest  // canonicalizeNumericIpv4 rejects non-numeric / malformed hosts
{
	ubyte[4] oct;
	assert(!canonicalizeNumericIpv4("metadata.attacker.example", oct));
	assert(!canonicalizeNumericIpv4("example.com", oct));
	assert(!canonicalizeNumericIpv4("1.2.3.4.5", oct)); // too many parts
	assert(!canonicalizeNumericIpv4("256.0.0.1", oct)); // octet overflow in 4-part form
	assert(!canonicalizeNumericIpv4("0x", oct)); // empty hex
	assert(!canonicalizeNumericIpv4("1..2", oct)); // empty part
	assert(!canonicalizeNumericIpv4("0192.168.0.1", oct)); // 9 is not an octal digit
}

unittest  // canonicalizeNumericIpv4 decodes the documented inet_aton forms
{
	ubyte[4] oct;
	assert(canonicalizeNumericIpv4("2130706433", oct) && oct == cast(ubyte[4])[
		127, 0, 0, 1
	]);
	assert(canonicalizeNumericIpv4("0x7f000001", oct) && oct == cast(ubyte[4])[
		127, 0, 0, 1
	]);
	assert(canonicalizeNumericIpv4("0177.0.0.1", oct) && oct == cast(ubyte[4])[
		127, 0, 0, 1
	]);
	assert(canonicalizeNumericIpv4("127.1", oct) && oct == cast(ubyte[4])[
		127, 0, 0, 1
	]);
	assert(canonicalizeNumericIpv4("0xa9fea9fe", oct) && oct == cast(ubyte[4])[
		169, 254, 169, 254
	]);
	assert(canonicalizeNumericIpv4("2852039166", oct) && oct == cast(ubyte[4])[
		169, 254, 169, 254
	]);
	assert(canonicalizeNumericIpv4("8.8.8.8", oct) && oct == cast(ubyte[4])[
		8, 8, 8, 8
	]);
}

unittest  // classifyIpv4Octets places each range in the right class
{
	assert(classifyIpv4Octets(127, 0, 0, 1) == AddressClass.loopback);
	assert(classifyIpv4Octets(10, 0, 0, 5) == AddressClass.privateOrLinkLocal);
	assert(classifyIpv4Octets(172, 16, 0, 1) == AddressClass.privateOrLinkLocal);
	assert(classifyIpv4Octets(192, 168, 1, 1) == AddressClass.privateOrLinkLocal);
	assert(classifyIpv4Octets(169, 254, 169, 254) == AddressClass.privateOrLinkLocal);
	assert(classifyIpv4Octets(0, 0, 0, 0) == AddressClass.privateOrLinkLocal);
	assert(classifyIpv4Octets(8, 8, 8, 8) == AddressClass.public_);
}

unittest  // classifyIpv6Literal classes loopback/ULA/link-local/embedded-v4
{
	assert(classifyIpv6Literal("::1") == AddressClass.loopback);
	assert(classifyIpv6Literal("::") == AddressClass.privateOrLinkLocal);
	assert(classifyIpv6Literal("fd00::1") == AddressClass.privateOrLinkLocal);
	assert(classifyIpv6Literal("fc00::1") == AddressClass.privateOrLinkLocal);
	assert(classifyIpv6Literal("fe80::1") == AddressClass.privateOrLinkLocal);
	assert(classifyIpv6Literal("::ffff:169.254.169.254") == AddressClass.privateOrLinkLocal);
	assert(classifyIpv6Literal("::ffff:10.0.0.5") == AddressClass.privateOrLinkLocal);
	assert(classifyIpv6Literal("::ffff:0a00:0001") == AddressClass.privateOrLinkLocal);
}

unittest  // classifyIpv6Literal classes NAT64 well-known 64:ff9b::/96 embedded internal IPv4 as private/link-local
{
	// A NAT64 gateway translates these to the embedded low-32-bit IPv4 and routes it,
	// reaching loopback / link-local-metadata / RFC1918 internal targets. The embedded
	// IPv4 is classified as the ::ffff: path does, except that an embedded 127.x is
	// reached through the gateway rather than on this host, so it is not loopback.
	assert(classifyIpv6Literal("64:ff9b::7f00:1") == AddressClass.privateOrLinkLocal); // 127.0.0.1
	assert(classifyIpv6Literal("64:ff9b::a9fe:a9fe") == AddressClass.privateOrLinkLocal); // 169.254.169.254
	assert(classifyIpv6Literal("64:ff9b::a00:5") == AddressClass.privateOrLinkLocal); // 10.0.0.5
}

unittest  // classifyIpv6Literal classes the whole NAT64 local-use 64:ff9b:1::/48 as private
{
	assert(classifyIpv6Literal("64:ff9b:1::7f00:1") == AddressClass.privateOrLinkLocal); // 127.0.0.1
	assert(classifyIpv6Literal("64:ff9b:1::a9fe:a9fe") == AddressClass.privateOrLinkLocal); // 169.254.169.254
	assert(classifyIpv6Literal("64:ff9b:1::808:808") == AddressClass.privateOrLinkLocal); // 8.8.8.8
	assert(classifyIpv6Literal("64:ff9b:1:abcd::808:808") == AddressClass.privateOrLinkLocal);
}

unittest  // embedded 127.x in 6to4 and NAT64 is not the plain-http loopback dev allowance
{
	assert(!pinnedConnectAddress("[2002:7f00:1::]", false, SsrfPolicy.allowLoopback).ok);
	assert(!pinnedConnectAddress("[64:ff9b::7f00:1]", false, SsrfPolicy.allowLoopback).ok);
}

unittest  // classifyIpv6Literal treats NAT64 with public embedded IPv4 like ::ffff: public embedded
{
	// 8.8.8.8 classifies public_, so the NAT64-embedded form matches the existing
	// embedded-public behaviour of the ::ffff: path.
	assert(classifyIpv6Literal("64:ff9b::808:808") == classifyIpv6Literal("::ffff:808:808")); // 8.8.8.8
	assert(classifyIpv6Literal("64:ff9b::808:808") == AddressClass.public_);
}

unittest  // classifyIpv6Literal classes public global-unicast and fails closed on garbage
{
	assert(classifyIpv6Literal("2606:4700:4700::1111") == AddressClass.public_);
	assert(classifyIpv6Literal("2606:4700::1") == AddressClass.public_);
	assert(classifyIpv6Literal("not-an-ipv6") == AddressClass.privateOrLinkLocal);
}

unittest  // classifyIpv4Octets classes 224.0.0.0/4 multicast as private/link-local
{
	assert(classifyIpv4Octets(224, 0, 0, 1) == AddressClass.privateOrLinkLocal);
	assert(classifyIpv4Octets(239, 255, 255, 250) == AddressClass.privateOrLinkLocal);
}

unittest  // classifyIpv4Octets classes 240.0.0.0/4 reserved (incl. broadcast) as private/link-local
{
	assert(classifyIpv4Octets(240, 0, 0, 1) == AddressClass.privateOrLinkLocal);
	assert(classifyIpv4Octets(255, 255, 255, 255) == AddressClass.privateOrLinkLocal);
}

unittest  // classifyIpv4Octets classes IETF protocol-assignment, benchmarking and documentation ranges as internal
{
	assert(classifyIpv4Octets(192, 0, 0, 1) == AddressClass.privateOrLinkLocal); // 192.0.0.0/24
	assert(classifyIpv4Octets(192, 0, 0, 170) == AddressClass.privateOrLinkLocal);
	assert(classifyIpv4Octets(198, 18, 0, 1) == AddressClass.privateOrLinkLocal); // 198.18.0.0/15
	assert(classifyIpv4Octets(198, 19, 255, 255) == AddressClass.privateOrLinkLocal);
	assert(classifyIpv4Octets(192, 0, 2, 1) == AddressClass.privateOrLinkLocal); // TEST-NET-1
	assert(classifyIpv4Octets(198, 51, 100, 1) == AddressClass.privateOrLinkLocal); // TEST-NET-2
	assert(classifyIpv4Octets(203, 0, 113, 1) == AddressClass.privateOrLinkLocal); // TEST-NET-3
	// Neighbours of those ranges stay public.
	assert(classifyIpv4Octets(192, 0, 1, 1) == AddressClass.public_);
	assert(classifyIpv4Octets(198, 17, 255, 255) == AddressClass.public_);
	assert(classifyIpv4Octets(198, 20, 0, 1) == AddressClass.public_);
	assert(classifyIpv4Octets(203, 0, 114, 1) == AddressClass.public_);
}

unittest  // classifyIpv6Literal classes Teredo 2001::/32 as private/link-local
{
	assert(classifyIpv6Literal(
			"2001:0:4136:e378:8000:63bf:80ff:fffe") == AddressClass.privateOrLinkLocal);
	assert(classifyIpv6Literal("2001::1") == AddressClass.privateOrLinkLocal);
	assert(classifyIpv6Literal("2001:4860:4860::8888") == AddressClass.public_);
}

unittest  // classifyIpv6Literal classifies the IPv4 embedded in a 6to4 2002::/16 address
{
	assert(classifyIpv6Literal("2002:7f00:1::1") == AddressClass.privateOrLinkLocal); // 127.0.0.1
	assert(classifyIpv6Literal("2002:a9fe:a9fe::") == AddressClass.privateOrLinkLocal); // 169.254.169.254
	assert(classifyIpv6Literal("2002:a00:5::1") == AddressClass.privateOrLinkLocal); // 10.0.0.5
	assert(classifyIpv6Literal("2002:808:808::1") == AddressClass.public_); // 8.8.8.8
}

unittest  // classifyIpv6Literal classifies the IPv4 in an IPv4-translated ::ffff:0:0:0/96 address
{
	assert(classifyIpv6Literal("::ffff:0:7f00:1") == AddressClass.loopback); // 127.0.0.1
	assert(classifyIpv6Literal("::ffff:0:a9fe:a9fe") == AddressClass.privateOrLinkLocal); // 169.254.169.254
	assert(classifyIpv6Literal("::ffff:0:808:808") == AddressClass.public_); // 8.8.8.8
}

unittest  // classifyIpv6Literal classes deprecated site-local fec0::/10 as private
{
	assert(classifyIpv6Literal("fec0::1") == AddressClass.privateOrLinkLocal);
	assert(classifyIpv6Literal("feff::1") == AddressClass.privateOrLinkLocal);
}

unittest  // classifyIpv4Octets keeps a public unicast control public
{
	assert(classifyIpv4Octets(8, 8, 8, 8) == AddressClass.public_);
}

unittest  // classifyIpv4Octets classes 100.64.0.0/10 CGNAT shared space as private/link-local
{
	assert(classifyIpv4Octets(100, 64, 0, 1) == AddressClass.privateOrLinkLocal);
	assert(classifyIpv4Octets(100, 127, 255, 255) == AddressClass.privateOrLinkLocal);
	// 100.0.0.0/8 outside the 64..127 second-octet window stays public.
	assert(classifyIpv4Octets(100, 63, 255, 255) == AddressClass.public_);
	assert(classifyIpv4Octets(100, 128, 0, 0) == AddressClass.public_);
	assert(classifyIpv4Octets(100, 0, 0, 1) == AddressClass.public_);
}

unittest  // classifyIpv6Literal classes ff00::/8 multicast as private/link-local
{
	assert(classifyIpv6Literal("ff02::1") == AddressClass.privateOrLinkLocal);
	assert(classifyIpv6Literal("ff05::1:3") == AddressClass.privateOrLinkLocal);
}

unittest  // classifyIpv6Literal keeps a public global-unicast control public
{
	assert(classifyIpv6Literal("2001:db8::1") == AddressClass.public_);
}

unittest  // an IPv6 literal's embedded IPv4 tail with a leading-zero octet fails closed
{
	string pin;
	assert(classifyIpv6Literal("::0177.0.0.1") == AddressClass.privateOrLinkLocal);
	assert(classifyHost("[::0177.0.0.1]", pin) == AddressClass.privateOrLinkLocal);
	assert(pin.length == 0);
	assert(!pinnedConnectAddress("[::0177.0.0.1]", true, SsrfPolicy.allowUserConfigured).ok);
}

unittest  // an embedded IPv4 tail after hextets parses into the low 32 bits
{
	string pin;
	assert(classifyIpv6Literal("::ffff:8.8.8.8") == AddressClass.public_);
	assert(classifyIpv6Literal("::ffff:127.0.0.1") == AddressClass.loopback);
	assert(classifyIpv6Literal("64:ff9b::10.0.0.1") == AddressClass.privateOrLinkLocal);
	assert(classifyIpv6Literal("2001:db8:1:2:3:4:8.8.8.8") == AddressClass.public_);
	assert(classifyHost("[::FFFF:8.8.8.8]", pin) == AddressClass.public_);
	assert(pin == "::ffff:808:808", pin);
}

unittest  // an embedded IPv4 tail octet of a single zero is still accepted
{
	assert(classifyIpv6Literal("::8.8.0.8") == AddressClass.public_);
}

unittest  // classifyHost pins an IPv6 literal as the canonical rendering of its bytes
{
	static string pinOf(string host)
	{
		string pin;
		cast(void) classifyHost(host, pin);
		return pin;
	}

	assert(pinOf("[2001:0DB8:0:0::1]:443") == "2001:db8::1");
	assert(pinOf("[::8.8.8.8]") == "::808:808");
	assert(pinOf("[::FFFF:808:808]") == "::ffff:808:808");
	assert(pinOf("[2001:db8:0:1:0:0:0:1]") == "2001:db8:0:1::1");
	assert(pinOf("[2001:db8:1:2:3:4:5:6]") == "2001:db8:1:2:3:4:5:6");
	assert(pinOf("[fe80::1%25eth0]") == "fe80::1%25eth0");
}

unittest  // classifyHost leaves an unparseable IPv6 literal unpinned
{
	string pin;
	assert(classifyHost("[2001:db8::zz]", pin) == AddressClass.privateOrLinkLocal);
	assert(pin.length == 0);
}

unittest  // classifyHost classes loopback hosts without resolving
{
	string pin;
	assert(classifyHost("localhost", pin) == AddressClass.loopback && pin == "127.0.0.1");
	assert(classifyHost("localhost:8080", pin) == AddressClass.loopback && pin == "127.0.0.1");
	assert(classifyHost("127.0.0.1", pin) == AddressClass.loopback && pin == "127.0.0.1");
	assert(classifyHost("[::1]", pin) == AddressClass.loopback && pin == "::1");
	assert(classifyHost("127.0.0.1:8765", pin) == AddressClass.loopback);
}

unittest  // localhost matches case-insensitively and with one trailing root dot
{
	string pin;
	foreach (h; ["LOCALHOST", "localhost.", "LocalHost.:8080"])
	{
		assert(classifyHost(h, pin) == AddressClass.loopback && pin == "127.0.0.1", h);
		assert(classifyHostLexical(h) == AddressClass.loopback, h);
		assert(pinnedConnectAddress(h, false, SsrfPolicy.allowLoopback).ok, h);
	}
	assert(classifyHostLexical("localhost..") == AddressClass.public_);
	assert(classifyHostLexical("localhostx") == AddressClass.public_);
}

unittest  // classifyHost classes numeric-encoded loopback as loopback (SSRF encodings)
{
	string pin;
	assert(classifyHost("2130706433", pin) == AddressClass.loopback); // 127.0.0.1
	assert(classifyHost("127.1", pin) == AddressClass.loopback);
	assert(classifyHost("0x7f000001", pin) == AddressClass.loopback);
}

unittest  // classifyHost pins a numeric IPv4 literal to its canonical dotted quad
{
	string pin;
	assert(classifyHost("0x7f000001", pin) == AddressClass.loopback && pin == "127.0.0.1");
	assert(classifyHost("2130706433:8080", pin) == AddressClass.loopback && pin == "127.0.0.1");
	assert(classifyHost("8.8.2056", pin) == AddressClass.public_ && pin == "8.8.8.8");
}

unittest  // classifyHost fails closed on a multi-digit IPv4 part with a leading zero
{
	// Resolvers disagree on whether `0127` is octal (87) or decimal (127).
	string pin;
	assert(classifyHost("0127.0.0.1", pin) == AddressClass.privateOrLinkLocal && pin.length == 0);
	assert(classifyHost("8.8.8.010", pin) == AddressClass.privateOrLinkLocal && pin.length == 0);
	assert(classifyHost("00", pin) == AddressClass.privateOrLinkLocal && pin.length == 0);
	assert(classifyHostLexical("0127.0.0.1") == AddressClass.privateOrLinkLocal);
	assert(classifyHostLexical("0177.0.0.1:80") == AddressClass.privateOrLinkLocal);
}

unittest  // pinnedConnectAddress rejects a leading-zero IPv4 literal under every policy
{
	assert(!pinnedConnectAddress("0127.0.0.1", false, SsrfPolicy.blockInternal).ok);
	assert(!pinnedConnectAddress("0127.0.0.1", false, SsrfPolicy.allowLoopback).ok);
	assert(!pinnedConnectAddress("0127.0.0.1", false, SsrfPolicy.allowUserConfigured).ok);
}

unittest  // classifyHost keeps single-digit zero parts and hex parts unambiguous
{
	string pin;
	assert(classifyHost("0.0.0.0", pin) == AddressClass.privateOrLinkLocal && pin == "0.0.0.0");
	assert(classifyHost("10.0.0.1", pin) == AddressClass.privateOrLinkLocal && pin == "10.0.0.1");
	assert(classifyHost("0x08.0x08.0x08.0x08", pin) == AddressClass.public_ && pin == "8.8.8.8");
}

unittest  // classifyHost classes numeric-encoded metadata/RFC1918 as private (SSRF encodings)
{
	string pin;
	assert(classifyHost("0xa9fea9fe", pin) == AddressClass.privateOrLinkLocal); // 169.254.169.254
	assert(classifyHost("2852039166", pin) == AddressClass.privateOrLinkLocal);
	assert(classifyHost("169.254.169.254", pin) == AddressClass.privateOrLinkLocal);
	assert(classifyHost("0xa000005", pin) == AddressClass.privateOrLinkLocal); // 10.0.0.5
	assert(classifyHost("192.0xa8.0.1", pin) == AddressClass.privateOrLinkLocal); // 192.168.0.1
	assert(classifyHost("10.0", pin) == AddressClass.privateOrLinkLocal); // 10.0.0.0
}

unittest  // classifyHost classes IPv6 literals (bracketed and bracketless)
{
	string pin;
	assert(classifyHost("[fe80::1]", pin) == AddressClass.privateOrLinkLocal);
	assert(classifyHost("[fd00::1]", pin) == AddressClass.privateOrLinkLocal);
	assert(classifyHost("[2606:4700:4700::1111]", pin) == AddressClass.public_);
	assert(classifyHost("[::ffff:169.254.169.254]", pin) == AddressClass.privateOrLinkLocal);
	assert(classifyHost("fe80::1", pin) == AddressClass.privateOrLinkLocal);
}

unittest  // classifyHost classes a genuine public numeric IPv4 literal as public
{
	string pin;
	assert(classifyHost("8.8.8.8", pin) == AddressClass.public_ && pin == "8.8.8.8");
	assert(classifyHost("1.1.1.1", pin) == AddressClass.public_);
}

unittest  // classifyHost fails closed for an unresolvable hostname
{
	string pin = "stale";
	assert(classifyHost("nonexistent-host.invalid", pin) == AddressClass.privateOrLinkLocal);
	assert(pin.length == 0);
}

unittest  // classifyHost resolves a name without stalling other tasks on the event loop
{
	import core.thread : Thread;
	import core.time : msecs;
	import vibe.core.core : runTask, sleep;

	static Resolution slowResolve(string host) @trusted nothrow
	{
		Thread.sleep(300.msecs);
		return Resolution(["93.184.216.34"], false);
	}

	auto saved = () @trusted { return hostResolver; }();
	() @trusted { hostResolver = &slowResolve; }();
	scope (exit)
		() @trusted { hostResolver = saved; }();

	int ticks;
	bool done;
	auto ticker = runTask(() nothrow{
		while (!done)
		{
			ticks++;
			try
				sleep(10.msecs);
			catch (Exception)
			{
			}
		}
	});
	string pin;
	const cls = classifyHost("slow.example", pin);
	done = true;
	ticker.join();
	assert(cls == AddressClass.public_ && pin == "93.184.216.34");
	assert(ticks >= 5, "other tasks must keep running while a name resolves");
}

unittest  // classifyHost fails closed when any resolved address is internal
{
	static Resolution mixedResolve(string host) @safe nothrow
	{
		return Resolution(["93.184.216.34", "10.0.0.5"], false);
	}

	auto saved = () @trusted { return hostResolver; }();
	() @trusted { hostResolver = &mixedResolve; }();
	scope (exit)
		() @trusted { hostResolver = saved; }();

	string pin;
	assert(classifyHost("rebind.example", pin) == AddressClass.privateOrLinkLocal);
}

unittest  // classifyHost fails closed for an empty host
{
	string pin = "stale";
	assert(classifyHost("", pin) == AddressClass.privateOrLinkLocal);
	assert(pin.length == 0);
}

unittest  // blockInternal accepts a public host over https and pins it
{
	const r = pinnedConnectAddress("8.8.8.8", true, SsrfPolicy.blockInternal);
	assert(r.ok && r.pinnedIp == "8.8.8.8" && r.sniHost == "8.8.8.8");
}

unittest  // blockInternal rejects a literal loopback host even over plain http
{
	assert(!pinnedConnectAddress("127.0.0.1", false, SsrfPolicy.blockInternal).ok);
	assert(!pinnedConnectAddress("localhost", false, SsrfPolicy.blockInternal).ok);
	assert(!pinnedConnectAddress("[::1]", false, SsrfPolicy.blockInternal).ok);
}

unittest  // secureRequestHTTP(blockInternal) refuses a plain-http loopback URL before connecting
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	assertThrown!McpException(secureRequestHTTP("http://127.0.0.1:1/token",
			SsrfPolicy.blockInternal, null, null));
	assertThrown!McpException(secureRequestHTTP("http://localhost:1/token",
			SsrfPolicy.blockInternal, null, null));
}

unittest  // allowLoopback permits the explicit loopback dev allowance over plain http
{
	assert(pinnedConnectAddress("127.0.0.1", false, SsrfPolicy.allowLoopback).ok);
	assert(pinnedConnectAddress("localhost", false, SsrfPolicy.allowLoopback).ok);
	assert(pinnedConnectAddress("[::1]", false, SsrfPolicy.allowLoopback).ok);
}

unittest  // pinnedConnectAddress pins localhost to the numeric loopback address
{
	const r = pinnedConnectAddress("localhost:8080", false, SsrfPolicy.allowLoopback);
	assert(r.ok && r.pinnedIp == "127.0.0.1" && r.sniHost == "localhost");
}

unittest  // allowLoopback still rejects loopback over https and private/link-local hosts
{
	assert(!pinnedConnectAddress("127.0.0.1", true, SsrfPolicy.allowLoopback).ok);
	assert(!pinnedConnectAddress("10.0.0.5", false, SsrfPolicy.allowLoopback).ok);
	assert(!pinnedConnectAddress("169.254.169.254", true, SsrfPolicy.allowLoopback).ok);
	assert(pinnedConnectAddress("8.8.8.8", true, SsrfPolicy.allowLoopback).ok);
}

unittest  // allowLoopback refuses plain http to anything but an explicit loopback host
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	assertThrown!McpException(secureRequestHTTP("http://as.example.com/token",
			SsrfPolicy.allowLoopback, null, null));
	assertThrown!McpException(secureRequestHTTP("http://8.8.8.8/token",
			SsrfPolicy.allowLoopback, null, null));
}

unittest  // blockInternal rejects loopback over https (local TLS services are not reachable)
{
	assert(!pinnedConnectAddress("127.0.0.1", true, SsrfPolicy.blockInternal).ok);
	assert(!pinnedConnectAddress("2130706433", true, SsrfPolicy.blockInternal).ok);
	assert(!pinnedConnectAddress("localhost", true, SsrfPolicy.blockInternal).ok);
	assert(!pinnedConnectAddress("[::1]", true, SsrfPolicy.blockInternal).ok);
	assert(!pinnedConnectAddress("[64:ff9b::7f00:1]", true, SsrfPolicy.blockInternal).ok);
}

unittest  // allowUserConfigured still reaches loopback over https
{
	assert(pinnedConnectAddress("127.0.0.1", true, SsrfPolicy.allowUserConfigured).ok);
}

unittest  // secureRequestHTTP(blockInternal) refuses an https loopback URL before connecting
{
	import std.exception : assertThrown;

	assertThrown(secureRequestHTTP("https://127.0.0.1:8443/client.json",
			SsrfPolicy.blockInternal, null, null));
}

unittest  // blockInternal rejects private/link-local hosts
{
	assert(!pinnedConnectAddress("169.254.169.254", true, SsrfPolicy.blockInternal).ok);
	assert(!pinnedConnectAddress("10.0.0.5", true, SsrfPolicy.blockInternal).ok);
	assert(!pinnedConnectAddress("[fe80::1]", true, SsrfPolicy.blockInternal).ok);
	assert(!pinnedConnectAddress("0xa9fea9fe", true, SsrfPolicy.blockInternal).ok);
}

unittest  // blockInternal rejects a registered name that DNS-resolves to loopback (no literal-loopback allowance for resolved hosts)
{
	// A resolved loopback address must NOT receive the literal dev-loopback
	// allowance.
	static Resolution loopbackResolve(string host) @safe nothrow
	{
		return Resolution(["127.0.0.1", "::1"], false);
	}

	auto saved = () @trusted { return hostResolver; }();
	() @trusted { hostResolver = &loopbackResolve; }();
	scope (exit)
		() @trusted { hostResolver = saved; }();

	string pin;
	assert(classifyHost("loop.example", pin) == AddressClass.privateOrLinkLocal);
	assert(!pinnedConnectAddress("loop.example", true, SsrfPolicy.blockInternal).ok);
	assert(!pinnedConnectAddress("loop.example", false, SsrfPolicy.blockInternal).ok);
	assert(!pinnedConnectAddress("loop.example", false, SsrfPolicy.allowLoopback).ok);
}

unittest  // allowUserConfigured permits loopback and private targets (user-chosen endpoint)
{
	assert(pinnedConnectAddress("127.0.0.1", false, SsrfPolicy.allowUserConfigured).ok);
	assert(pinnedConnectAddress("10.0.0.5", false, SsrfPolicy.allowUserConfigured).ok);
	assert(pinnedConnectAddress("192.168.1.1", true, SsrfPolicy.allowUserConfigured).ok);
	assert(pinnedConnectAddress("[::1]", false, SsrfPolicy.allowUserConfigured).ok);
}

unittest  // allowUserConfigured still fails closed on an unresolvable host
{
	assert(!pinnedConnectAddress("nonexistent-host.invalid", true,
			SsrfPolicy.allowUserConfigured).ok);
	assert(!pinnedConnectAddress("", false, SsrfPolicy.allowUserConfigured).ok);
}

unittest  // pinnedConnectAddress strips the port from the pinned IP, keeps SNI as the bare host
{
	const r = pinnedConnectAddress("8.8.8.8:8443", true, SsrfPolicy.blockInternal);
	assert(r.ok && r.pinnedIp == "8.8.8.8" && r.sniHost == "8.8.8.8");
	const r6 = pinnedConnectAddress("[2606:4700::1]:443", true, SsrfPolicy.allowUserConfigured);
	assert(r6.ok && r6.pinnedIp == "2606:4700::1" && r6.sniHost == "2606:4700::1");
}

unittest  // secureRequestHTTP(blockInternal) rejects the '?@'/'#@' authority differential
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	// vibe parses the real host after the first '@' as the authority; the guard
	// sees the SAME host and rejects the internal target.
	assertThrown!McpException(secureRequestHTTP("https://public?@169.254.169.254/jwks",
			SsrfPolicy.blockInternal, null, null));
	assertThrown!McpException(secureRequestHTTP("https://public#@10.0.0.5/jwks",
			SsrfPolicy.blockInternal, null, null));
}

unittest  // secureRequestHTTP(blockInternal) rejects insecure scheme and private literals
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	assertThrown!McpException(secureRequestHTTP("http://as.example.com/token",
			SsrfPolicy.blockInternal, null, null));
	assertThrown!McpException(secureRequestHTTP("https://169.254.169.254/",
			SsrfPolicy.blockInternal, null, null));
	assertThrown!McpException(secureRequestHTTP("file:///etc/passwd",
			SsrfPolicy.blockInternal, null, null));
}

unittest  // buildHostHeader brackets IPv6 literals on the default port (RFC 7230 §5.4)
{
	// IPv6 on default port: must produce "[::1]", not bare "::1".
	assert(buildHostHeader("::1", 0, 443) == "[::1]");
	assert(buildHostHeader("::1", 443, 443) == "[::1]");
	// IPv6 on non-default port: must produce "[::1]:8443".
	assert(buildHostHeader("::1", 8443, 443) == "[::1]:8443");
	// IPv4 on default port: no brackets, no port suffix.
	assert(buildHostHeader("127.0.0.1", 0, 80) == "127.0.0.1");
	assert(buildHostHeader("127.0.0.1", 80, 80) == "127.0.0.1");
	// IPv4 on non-default port: no brackets, port suffix.
	assert(buildHostHeader("127.0.0.1", 8080, 80) == "127.0.0.1:8080");
	// Hostname: unchanged.
	assert(buildHostHeader("example.com", 0, 443) == "example.com");
	assert(buildHostHeader("example.com", 8443, 443) == "example.com:8443");
}

// ---------------------------------------------------------------------------
// Edge-case coverage for the numeric-IPv4 and IPv6-literal parsers. These guard
// the SSRF classifier against malformed / overflowing / alternately-encoded
// literals, all of which must fail closed (never classified public).
// ---------------------------------------------------------------------------

unittest  // canonicalizeNumericIpv4 rejects overflow / malformed parts and decodes uppercase hex
{
	ubyte[4] oct;

	// Empty input is not a literal.
	assert(!canonicalizeNumericIpv4("", oct));
	// Uppercase hex digits decode (single-part inet_aton form 0xAB -> 0.0.0.171).
	assert(canonicalizeNumericIpv4("0xAB", oct));
	assert(oct == [0, 0, 0, 0xAB]);
	// Each numeric base can overflow the 32-bit address space.
	assert(!canonicalizeNumericIpv4("0xFFFFFFFFF", oct)); // hex > 2^32-1
	assert(!canonicalizeNumericIpv4("0777777777777", oct)); // octal > 2^32-1
	assert(!canonicalizeNumericIpv4("99999999999", oct)); // decimal > 2^32-1
	// Trailing junk and a trailing dot are both rejected.
	assert(!canonicalizeNumericIpv4("1a", oct));
	assert(!canonicalizeNumericIpv4("1.2.", oct));
	// Short-form part-range violations (2-part: b > 24 bits; 3-part: c > 16 bits).
	assert(!canonicalizeNumericIpv4("0xFF.0xFFFFFFFF", oct));
	assert(!canonicalizeNumericIpv4("1.2.0x1FFFF", oct));
	// A well-formed dotted quad still decodes.
	assert(canonicalizeNumericIpv4("192.168.1.1", oct));
	assert(oct == [192, 168, 1, 1]);
}

unittest  // malformed IPv6 literals fail closed; an IPv4-mapped public address classifies public
{
	// Every malformed literal must be treated as unsafe (never public).
	static immutable string[] bad = [
		"[%eth0]", // empty after zone-id strip
		"[::1.2.3.999]", // embedded-IPv4 octet out of range
		"[::1.2..4]", // empty embedded-IPv4 octet
		"[::1.2.3.4.5]", // too many embedded-IPv4 octets
		"[::1.2.3x4]", // non-dot separator in the embedded-IPv4 tail
		"[::1.2.3]", // too few embedded-IPv4 octets
		"[1:2:3]", // no "::" but the hextet area is underfilled
		"[:::2]", // ":::" — a hextet group adjacent to "::"
		"[g::1]", // invalid hextet left of "::"
		"[::g]", // invalid hextet right of "::"
		"[1:2:3:4:5:6:7:8::9]", // more than 16 bytes of hextets
	];
	foreach (h; bad)
		assert(classifyHostLexical(h) == AddressClass.privateOrLinkLocal,
				"malformed IPv6 literal must fail closed: " ~ h);

	// A fully-specified (no "::") public global-unicast literal fills the entire
	// hextet area and classifies public.
	assert(classifyHostLexical("[2606:4700:4700:1:2:3:4:5]") == AddressClass.public_);
}

unittest  // secureRequestHTTP enforces an overall deadline on a server that drip-feeds its response
{
	import core.time : msecs, seconds;
	import std.conv : to;
	import std.datetime.stopwatch : StopWatch, AutoStart;
	import vibe.core.core : exitEventLoop, runEventLoop, runTask, sleep;
	import vibe.http.server : HTTPServerRequest, HTTPServerResponse,
		HTTPServerSettings, listenHTTP;
	import vibe.stream.operations : readAllUTF8;

	string failure;
	bool timedOut, stopDripping, handlerDone;
	Duration elapsed;
	runTask(() nothrow{
		try
		{
			auto settings = new HTTPServerSettings();
			settings.bindAddresses = ["127.0.0.1"];
			settings.port = 0;
			auto listener = listenHTTP(settings, (scope HTTPServerRequest req,
				scope HTTPServerResponse res) @safe {
				scope (exit)
					handlerDone = true;
				res.contentType = "text/plain";
				// Each byte arrives well inside a per-read timeout; the whole body
				// takes far longer than the request may.
				while (!stopDripping)
				{
					res.bodyWriter.write("x");
					res.bodyWriter.flush();
					sleep(50.msecs);
				}
			});
			scope (exit)
				listener.stopListening();
			const url = "http://127.0.0.1:" ~ listener.bindAddresses[0].port.to!string ~ "/";

			FetchOptions opts;
			opts.timeout = 400.msecs;
			auto sw = StopWatch(AutoStart.yes);
			try
				secureRequestHTTP(url, SsrfPolicy.allowLoopback, null,
					(scope HTTPClientResponse res) {
					res.bodyReader.readAllUTF8();
				}, opts);
			catch (Exception e)
				timedOut = true;
			elapsed = sw.peek();
			// Let the server handler finish before the listener and loop go away.
			stopDripping = true;
			while (!handlerDone)
				sleep(10.msecs);
		}
		catch (Exception e)
			failure = e.msg;
		exitEventLoop();
	});
	runEventLoop();

	assert(failure.length == 0, failure);
	assert(timedOut, "a drip-fed response must not outlive the request timeout");
	assert(elapsed < 3.seconds, "the deadline must cut the request short");
}

unittest  // outbound fetches are bounded by a timeout unless a caller sets its own
{
	assert(FetchOptions.init.timeout > Duration.zero);
}

// ---------------------------------------------------------------------------
// TLS peer validation against a local server whose certificate no trusted CA
// vouches for.
// ---------------------------------------------------------------------------

version (unittest)
{
	import vibe.http.server : HTTPListener;

	/// A self-signed certificate for `localhost` / `127.0.0.1` (valid until
	/// 2126) and its private key.
	package(mcp) enum string selfSignedTestCertPem = `-----BEGIN CERTIFICATE-----
MIIBmjCCAUGgAwIBAgIUAovDwvpLlQMt8gK+erC9S5I42yIwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDkzMDIzMzkzNloYDzIxMjYwOTA2
MjMzOTM2WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAARK4ceRzW/TvRDjH6cserBLy70rdIJd/O+iiA11+NVcrtBaf1RXgENx
PtEo4dB2AjfdyjZG2bkI3tMjdREfJS6Go28wbTAdBgNVHQ4EFgQUzK5LlfqR4ye2
dOlo7ZCfU7rIWAUwHwYDVR0jBBgwFoAUzK5LlfqR4ye2dOlo7ZCfU7rIWAUwGgYD
VR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZI
zj0EAwIDRwAwRAIgRiBXZ0iBHYlwFM1lvIDVuGHIAhQ6PeWnIM3O2IVLTmECIFg1
KwQhpZaxyjtic6lb644+zasZ1FhrQxH85bL68vNc
-----END CERTIFICATE-----
`;

	/// ditto
	package(mcp) enum string selfSignedTestKeyPem = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgyac0Dphvj23tfCMC
9gshddtbn//XQZ9+DFg/hs80DCKhRANCAARK4ceRzW/TvRDjH6cserBLy70rdIJd
/O+iiA11+NVcrtBaf1RXgENxPtEo4dB2AjfdyjZG2bkI3tMjdREfJS6G
-----END PRIVATE KEY-----
`;

	/// Write `pem` to a fresh temporary file and return its path.
	package(mcp) string writeTestPemFile(string pem) @trusted
	{
		import std.conv : to;
		import std.file : tempDir, write;
		import std.path : buildPath;
		import std.random : uniform;

		const path = buildPath(tempDir(), "mcp-d-test-" ~ uniform!ulong().to!string ~ ".pem");
		write(path, pem);
		return path;
	}

	/// Listen for HTTPS on an ephemeral `127.0.0.1` port presenting the
	/// self-signed test certificate, answering every request with 200 "ok".
	package(mcp) HTTPListener startSelfSignedTlsServer() @trusted
	{
		import vibe.http.server : HTTPServerRequest, HTTPServerResponse,
			HTTPServerSettings, listenHTTP;
		import vibe.stream.tls : createTLSContext, TLSContextKind;

		auto settings = new HTTPServerSettings();
		settings.bindAddresses = ["127.0.0.1"];
		settings.port = 0;
		settings.tlsContext = createTLSContext(TLSContextKind.server);
		settings.tlsContext.useCertificateChainFile(writeTestPemFile(selfSignedTestCertPem));
		settings.tlsContext.usePrivateKeyFile(writeTestPemFile(selfSignedTestKeyPem));
		return listenHTTP(settings, (scope HTTPServerRequest req, scope HTTPServerResponse res) @safe {
			res.writeBody("ok", "text/plain");
		});
	}
}

unittest  // secureRequestHTTP refuses a server whose certificate no trusted CA vouches for
{
	import std.conv : to;

	auto listener = startSelfSignedTlsServer();
	scope (exit)
		() @trusted { listener.stopListening(); }();
	const url = "https://127.0.0.1:" ~ listener.bindAddresses[0].port.to!string ~ "/";

	bool reached;
	try
		secureRequestHTTP(url, SsrfPolicy.allowUserConfigured, null, (scope HTTPClientResponse res) {
			reached = true;
		});
	catch (Exception)
	{
	}
	assert(!reached, "an untrusted server certificate must fail the TLS handshake");
}

unittest  // secureRequestHTTP trusts a server certificate issued by the configured caFile
{
	import std.conv : to;

	auto listener = startSelfSignedTlsServer();
	scope (exit)
		() @trusted { listener.stopListening(); }();
	const url = "https://127.0.0.1:" ~ listener.bindAddresses[0].port.to!string ~ "/";

	int status;
	FetchOptions opts;
	opts.tls.caFile = writeTestPemFile(selfSignedTestCertPem);
	secureRequestHTTP(url, SsrfPolicy.allowUserConfigured, null, (scope HTTPClientResponse res) {
		status = res.statusCode;
	}, opts);
	assert(status == 200);
}

unittest  // secureRequestHTTP skips certificate verification only when insecureSkipVerify is set
{
	import std.conv : to;

	auto listener = startSelfSignedTlsServer();
	scope (exit)
		() @trusted { listener.stopListening(); }();
	const url = "https://127.0.0.1:" ~ listener.bindAddresses[0].port.to!string ~ "/";

	int status;
	FetchOptions opts;
	opts.tls.insecureSkipVerify = true;
	secureRequestHTTP(url, SsrfPolicy.allowUserConfigured, null, (scope HTTPClientResponse res) {
		status = res.statusCode;
	}, opts);
	assert(status == 200);
}

unittest  // a connection opened with insecureSkipVerify is never reused by a verifying request
{
	import std.conv : to;

	auto listener = startSelfSignedTlsServer();
	scope (exit)
		() @trusted { listener.stopListening(); }();
	const url = "https://127.0.0.1:" ~ listener.bindAddresses[0].port.to!string ~ "/";

	FetchOptions insecure;
	insecure.tls.insecureSkipVerify = true;
	int status;
	secureRequestHTTP(url, SsrfPolicy.allowUserConfigured, null, (scope HTTPClientResponse res) {
		status = res.statusCode;
	}, insecure);
	assert(status == 200);

	bool reached;
	try
		secureRequestHTTP(url, SsrfPolicy.allowUserConfigured, null, (scope HTTPClientResponse res) {
			reached = true;
		});
	catch (Exception)
	{
	}
	assert(!reached, "a verifying request must not ride an unverified pooled connection");
}

unittest  // secureRequestHTTP rejects a @system requester delegate at compile time
{
	static assert(!__traits(compiles, secureRequestHTTP("https://example.com",
			SsrfPolicy.blockInternal, (scope HTTPClientRequest req) @system {}, null)));
}

unittest  // secureRequestHTTP rejects a @system responder delegate at compile time
{
	static assert(!__traits(compiles, secureRequestHTTP("https://example.com",
			SsrfPolicy.blockInternal, null, (scope HTTPClientResponse res) @system {
			})));
}

unittest  // secureRequestHTTP is callable from @safe code with @safe delegates
{
	static assert(__traits(compiles, () @safe {
			secureRequestHTTP("https://example.com", SsrfPolicy.blockInternal,
			(scope HTTPClientRequest req) {}, (scope HTTPClientResponse res) {});
		}));
}
