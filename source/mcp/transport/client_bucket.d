/// The per-address key that per-client limits count unauthenticated callers
/// under.
module mcp.transport.client_bucket;

import vibe.core.net : NetworkAddress;

/// The IPv6 prefix length, in bits, that per-address limits group callers by
/// unless configured otherwise: a /64 is the smallest block a single network
/// is normally assigned, so one client can rotate through all of it.
enum uint defaultIpv6BucketPrefix = 64;

/// The key per-address limits count a caller connecting from `addr` under, or
/// "" when it did not connect over IP (a test request, a Unix socket). An IPv4
/// address is its own key, and so is the IPv4 address inside an IPv4-mapped
/// IPv6 one. Any other IPv6 address is keyed by its first `ipv6Prefix` bits, so
/// a client cannot escape the limit by rotating through its own block.
package(mcp) string clientBucket(in NetworkAddress addr, uint ipv6Prefix = defaultIpv6BucketPrefix) @safe nothrow
{
	import std.socket : AddressFamily;

	if (addr.family == AddressFamily.INET)
		return addr.toAddressString();
	if (addr.family != AddressFamily.INET6)
		return "";
	const ubyte[16] ip = () @trusted {
		return addr.sockAddrInet6.sin6_addr.s6_addr;
	}();
	return ipv6Bucket(ip, ipv6Prefix);
}

/// `clientBucket` for the IPv6 address `ip`.
private string ipv6Bucket(const ubyte[16] ip, uint prefix) @safe pure nothrow
{
	static immutable ubyte[12] mappedPrefix = [
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
	];
	if (ip[0 .. 12] == mappedPrefix[])
		return decimal(ip[12]) ~ "." ~ decimal(ip[13]) ~ "." ~ decimal(ip[14])
			~ "." ~ decimal(ip[15]);

	if (prefix > 128)
		prefix = 128;
	ubyte[16] masked = ip;
	foreach (i; 0 .. 16)
	{
		const bitsKept = prefix > i * 8 ? prefix - i * 8 : 0;
		if (bitsKept < 8)
			masked[i] &= cast(ubyte)(0xff << (8 - bitsKept));
	}
	static immutable hexDigits = "0123456789abcdef";
	string key;
	foreach (i, b; masked)
	{
		if (i && i % 2 == 0)
			key ~= ':';
		key ~= hexDigits[b >> 4];
		key ~= hexDigits[b & 0xf];
	}
	return key ~ "/" ~ decimal(prefix);
}

private string decimal(uint n) @safe pure nothrow
{
	if (n == 0)
		return "0";
	string s;
	for (; n; n /= 10)
		s = cast(char)('0' + n % 10) ~ s;
	return s;
}

version (unittest) private NetworkAddress ip(string literal) @safe
{
	import vibe.core.net : resolveHost;

	return resolveHost(literal);
}

unittest  // an IPv4 address is its own bucket
{
	assert(clientBucket(ip("10.0.0.1")) == "10.0.0.1");
	assert(clientBucket(ip("10.0.0.1")) != clientBucket(ip("10.0.0.2")));
}

unittest  // IPv6 addresses in one /64 share a bucket
{
	assert(clientBucket(ip("2001:db8:1:2::1")) == clientBucket(ip("2001:db8:1:2:ffff::9")));
}

unittest  // IPv6 addresses in different /64s get different buckets
{
	assert(clientBucket(ip("2001:db8:1:2::1")) != clientBucket(ip("2001:db8:1:3::1")));
}

unittest  // the IPv6 bucket prefix is configurable
{
	assert(clientBucket(ip("2001:db8:1:2::1"), 128) != clientBucket(ip("2001:db8:1:2::2"), 128));
	assert(clientBucket(ip("2001:db8:1:2::1"), 48) == clientBucket(ip("2001:db8:1:3::1"), 48));
	assert(clientBucket(ip("2001:db8:1:2::1"), 60) == clientBucket(ip("2001:db8:1:f::1"), 60));
	assert(clientBucket(ip("2001:db8:1:2::1"), 60) != clientBucket(ip("2001:db8:1:10::1"), 60));
}

unittest  // an IPv4-mapped IPv6 address shares its IPv4 address's bucket
{
	assert(clientBucket(ip("::ffff:10.0.0.1")) == "10.0.0.1");
}

unittest  // a caller not connected over IP has no bucket
{
	NetworkAddress none;
	assert(clientBucket(none) == "");
}
