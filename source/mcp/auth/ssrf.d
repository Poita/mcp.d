module mcp.auth.ssrf;

import vibe.http.client : HTTPClientRequest, HTTPClientResponse;

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
// `SsrfPolicy.blockInternal` rejects loopback/private/link-local hosts (the
// dev-loopback-over-http allowance excepted) and is used for every
// attacker-influenceable fetch. `SsrfPolicy.allowUserConfigured` resolves and
// pins the address for stability but permits internal/loopback targets, for the
// user-chosen client transport endpoint.
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
	/// Reject loopback/private/link-local hosts. The only internal targets
	/// permitted are explicit loopback hosts reached over plaintext `http`
	/// (the local-development allowance). Used for every attacker-influenceable
	/// fetch (OAuth/discovery, JWKS, introspection, proxy upstream).
	blockInternal,
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
			// Replace the IPv4 tail with the hextet portion for hextet parsing.
			s = (lastColon < 0) ? "" : s[0 .. lastColon + 1];
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
/// link-local/this-host (RFC 1918, 169.254/16, 0/8), or public. `@safe pure
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

	// NAT64 prefixes carry an embedded IPv4 in the low 32 bits that a NAT64
	// gateway translates and routes, so classify that IPv4 the same as ::ffff:.
	// Well-known 64:ff9b::/96 (RFC 6052): 00 64 ff 9b then bytes 4..11 zero.
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
			return classifyIpv4Octets(b[12], b[13], b[14], b[15]);
		// Local-use 64:ff9b:1::/48 (RFC 8215): 00 64 ff 9b 00 01.
		if (b[4] == 0x00 && b[5] == 0x01)
			return classifyIpv4Octets(b[12], b[13], b[14], b[15]);
	}

	return AddressClass.public_;
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
/// - IP literals (IPv4 in every numeric encoding, IPv6 including embedded-IPv4,
///   ULA, link-local and loopback) are classified directly and `pinnedIp` is the
///   host verbatim (already a literal vibe will not re-resolve).
/// - `localhost` and `::1` are classified as loopback; `pinnedIp` is the host
///   verbatim.
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
	import std.socket : getAddressInfo, AddressFamily, SocketException;

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
			pinnedIp = host;
			return classifyIpv6Literal(bare);
		}
	}

	if (bare == "localhost")
	{
		pinnedIp = host;
		return AddressClass.loopback;
	}

	// A numeric IPv4 literal in any encoding — classify directly, pin verbatim.
	ubyte[4] oct;
	if (canonicalizeNumericIpv4(bare, oct))
	{
		pinnedIp = host;
		return classifyIpv4Octets(oct[0], oct[1], oct[2], oct[3]);
	}

	// A registered hostname: resolve and vet every returned address.
	try
	{
		auto infos = getAddressInfo(bare);
		string chosen;
		AddressClass worst = AddressClass.public_;
		bool any;
		foreach (info; infos)
		{
			if (info.family != AddressFamily.INET && info.family != AddressFamily.INET6)
				continue;
			const addr = info.address.toAddrString();
			auto cls = classifyResolvedAddress(addr);
			any = true;
			// A resolved loopback address is demoted to private/link-local: the
			// literal-loopback dev allowance applies only to literal hosts
			// (localhost/127.x/[::1], handled above before this DNS branch), never to
			// a registered name an attacker can point at 127.x via DNS.
			if (cls == AddressClass.loopback)
				cls = AddressClass.privateOrLinkLocal;
			// A single internal address taints the whole host (DNS-rebinding guard).
			if (cls != AddressClass.public_)
				worst = cls;
			if (chosen.length == 0)
				chosen = addr;
		}
		if (!any || chosen.length == 0)
			return AddressClass.privateOrLinkLocal; // no usable record -> fail closed
		pinnedIp = chosen;
		return worst;
	}
	catch (SocketException)
	{
		pinnedIp = "";
		return AddressClass.privateOrLinkLocal; // unresolved -> fail CLOSED
	}
}

// ---------------------------------------------------------------------------
// The connector.
// ---------------------------------------------------------------------------

/// Classify `host` WITHOUT performing DNS resolution: IP literals (every numeric
/// IPv4 encoding and IPv6 incl. embedded-IPv4/ULA/link-local/loopback) and the
/// explicit loopback names (`localhost`) are classified directly; any registered
/// hostname is treated as `public_` (a lexical pre-filter cannot know what it
/// resolves to — the resolve-and-pin connector makes the authoritative call).
/// `@safe pure nothrow @nogc`.
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

	if (bare == "localhost")
		return AddressClass.loopback;

	ubyte[4] oct;
	if (canonicalizeNumericIpv4(bare, oct))
		return classifyIpv4Octets(oct[0], oct[1], oct[2], oct[3]);

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
/// TLS; the http-vs-loopback scheme restriction itself is enforced by the
/// caller's scheme gate (`secureRequestHTTP`), not here.
///
/// `blockInternal`: public hosts pass; an explicit literal-loopback host
/// (`localhost`, `127.x` in any encoding, `[::1]`) passes as the dev-loopback
/// allowance; everything else — including a registered name that DNS-resolves to
/// loopback — is rejected (`classifyHost` demotes resolved loopback to private).
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
		if (cls == AddressClass.loopback)
			break; // literal-loopback dev allowance; the caller's scheme gate restricts http to it
		return r; // private/link-local -> reject
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

/// SSRF-safe HTTP fetch. Parses `url` with vibe's `URL` — the exact parser the
/// connector uses — so the host vetted is the host connected to (no parser
/// differential). The host is classified ONCE via `classifyHost`; under
/// `policy` an internal target is rejected (`blockInternal`, dev-loopback-over-
/// http excepted) or pinned-but-permitted (`allowUserConfigured`). The request
/// URL's host is rewritten to the vetted numeric IP and the connection pinned to
/// it, while the original hostname is preserved for the `Host` header and TLS
/// SNI (no TOCTOU re-resolution).
///
/// Throws `invalidRequest` when the URL is unsafe under `policy` (insecure
/// scheme for `blockInternal`, an internal IP-literal/resolved address, or an
/// unresolvable host — fail CLOSED). `@trusted` because the vibe HTTP client API
/// is `@system`.
void secureRequestHTTP(string url, SsrfPolicy policy, scope void delegate(
		scope HTTPClientRequest) requester, scope void delegate(scope HTTPClientResponse) responder) @trusted
{
	import mcp.protocol.errors : invalidRequest;
	import std.string : indexOf;
	import vibe.inet.url : URL;
	import vibe.http.client : requestHTTP, HTTPClientSettings;

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

	// Scheme gate (only meaningful for blockInternal): https to any host, or http
	// to an explicit loopback host for dev. allowUserConfigured leaves the scheme
	// to the caller (the transport already enforces its own scheme rules).
	const isHttps = eqSchemeAscii(scheme, "https");
	const isHttp = eqSchemeAscii(scheme, "http");
	const tls = isHttps;

	if (policy == SsrfPolicy.blockInternal)
	{
		// Scheme gate uses the lexical class (no DNS): https to any host, or http
		// only to an explicit loopback host. The resolved-address verdict comes from
		// pinnedConnectAddress below.
		const loopback = classifyHostLexical(host) == AddressClass.loopback;
		if (!(isHttps || (isHttp && loopback)))
			throw invalidRequest(
					"Refusing to fetch insecure OAuth/discovery URL (must be https, or http to an "
					~ "explicit loopback host; private/link-local addresses are rejected): " ~ url);
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

	// vibe derives the Host header from u.host; restore the original host so the
	// server sees the intended virtual host, not the pinned IP.
	string hostHeader = originalHost;
	if (u.port && u.port != u.defaultPort)
	{
		import std.conv : to;

		hostHeader = (originalHost.indexOf(':') >= 0 ? "[" ~ originalHost ~ "]" : originalHost)
			~ ":" ~ u.port.to!string;
	}

	requestHTTP(u, (scope HTTPClientRequest req) {
		req.headers["Host"] = hostHeader;
		if (requester !is null)
			requester(req);
	}, (scope HTTPClientResponse res) {
		if (responder !is null)
			responder(res);
	}, settings);
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
	// IPv4 is classified exactly as the ::ffff: path does, so each matches the IPv4 class.
	assert(classifyIpv6Literal("64:ff9b::7f00:1") == AddressClass.loopback); // 127.0.0.1
	assert(classifyIpv6Literal("64:ff9b::a9fe:a9fe") == AddressClass.privateOrLinkLocal); // 169.254.169.254
	assert(classifyIpv6Literal("64:ff9b::a00:5") == AddressClass.privateOrLinkLocal); // 10.0.0.5
}

unittest  // classifyIpv6Literal classes NAT64 local-use 64:ff9b:1::/48 embedded internal IPv4 as internal
{
	assert(classifyIpv6Literal("64:ff9b:1::7f00:1") == AddressClass.loopback); // 127.0.0.1
	assert(classifyIpv6Literal("64:ff9b:1::a9fe:a9fe") == AddressClass.privateOrLinkLocal); // 169.254.169.254
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

unittest  // classifyHost classes loopback hosts without resolving
{
	string pin;
	assert(classifyHost("localhost", pin) == AddressClass.loopback && pin == "localhost");
	assert(classifyHost("127.0.0.1", pin) == AddressClass.loopback && pin == "127.0.0.1");
	assert(classifyHost("[::1]", pin) == AddressClass.loopback && pin == "[::1]");
	assert(classifyHost("127.0.0.1:8765", pin) == AddressClass.loopback);
}

unittest  // classifyHost classes numeric-encoded loopback as loopback (SSRF encodings)
{
	string pin;
	assert(classifyHost("2130706433", pin) == AddressClass.loopback); // 127.0.0.1
	assert(classifyHost("127.1", pin) == AddressClass.loopback);
	assert(classifyHost("0x7f000001", pin) == AddressClass.loopback);
	assert(classifyHost("0177.0.0.1", pin) == AddressClass.loopback);
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

unittest  // blockInternal permits the explicit loopback dev allowance (http and https)
{
	assert(pinnedConnectAddress("127.0.0.1", false, SsrfPolicy.blockInternal).ok);
	assert(pinnedConnectAddress("127.0.0.1", true, SsrfPolicy.blockInternal).ok);
	assert(pinnedConnectAddress("localhost", false, SsrfPolicy.blockInternal).ok);
	assert(pinnedConnectAddress("[::1]", false, SsrfPolicy.blockInternal).ok);
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
	// "LOCALHOST" does not match the case-sensitive literal `localhost` fast path,
	// so it goes through DNS resolution and resolves to 127.0.0.1/::1. A resolved
	// loopback address must NOT receive the literal dev-loopback allowance.
	string pin;
	assert(classifyHost("LOCALHOST", pin) == AddressClass.privateOrLinkLocal);
	assert(!pinnedConnectAddress("LOCALHOST", true, SsrfPolicy.blockInternal).ok);
	assert(!pinnedConnectAddress("LOCALHOST", false, SsrfPolicy.blockInternal).ok);
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
