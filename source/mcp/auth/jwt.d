module mcp.auth.jwt;

import core.stdc.config : c_long;

import deimos.openssl.bio;
import deimos.openssl.pem;
import deimos.openssl.evp;
import deimos.openssl.ecdsa;
import deimos.openssl.bn;

import mcp.auth.oauth : base64UrlNoPad;

import vibe.data.json : Json;

@safe:

/// Sign `data` with ECDSA P-256 / SHA-256 (the JWS ES256 algorithm) using the
/// given PKCS#8 EC private key (PEM), returning the raw 64-byte R||S signature.
ubyte[] signEs256(string privateKeyPem, const(ubyte)[] data) @trusted
{
	auto bio = BIO_new_mem_buf(cast(void*) privateKeyPem.ptr, cast(int) privateKeyPem.length);
	if (bio is null)
		throw new Exception("openssl: BIO_new_mem_buf failed");
	scope (exit)
		BIO_free(bio);

	auto pkey = PEM_read_bio_PrivateKey(bio, null, null, null);
	if (pkey is null)
		throw new Exception("openssl: failed to parse EC private key");
	scope (exit)
		EVP_PKEY_free(pkey);

	auto ctx = EVP_MD_CTX_new();
	if (ctx is null)
		throw new Exception("openssl: EVP_MD_CTX_new failed");
	scope (exit)
		EVP_MD_CTX_free(ctx);

	if (EVP_DigestSignInit(ctx, null, EVP_sha256(), null, pkey) != 1)
		throw new Exception("openssl: EVP_DigestSignInit failed");

	size_t sigLen;
	if (EVP_DigestSign(ctx, null, &sigLen, data.ptr, data.length) != 1)
		throw new Exception("openssl: EVP_DigestSign (size) failed");
	auto der = new ubyte[sigLen];
	if (EVP_DigestSign(ctx, der.ptr, &sigLen, data.ptr, data.length) != 1)
		throw new Exception("openssl: EVP_DigestSign failed");

	// Convert the DER-encoded ECDSA signature to the fixed-width R||S form
	// required by JWS (RFC 7518 §3.4): 32 bytes each for P-256.
	const(ubyte)* p = der.ptr;
	auto sig = d2i_ECDSA_SIG(null, &p, cast(c_long) sigLen);
	if (sig is null)
		throw new Exception("openssl: d2i_ECDSA_SIG failed");
	scope (exit)
		ECDSA_SIG_free(sig);

	auto r = ECDSA_SIG_get0_r(sig);
	auto s = ECDSA_SIG_get0_s(sig);
	ubyte[64] raw;
	bnToFixed(r, raw[0 .. 32]);
	bnToFixed(s, raw[32 .. 64]);
	return raw.dup;
}

/// Left-pad a BIGNUM into a fixed-width big-endian buffer.
/// Throws if the BIGNUM is zero or wider than dst, because either case indicates
/// a catastrophic failure (e.g. uninitialised component, memory corruption, wrong
/// key type) that must not be masked by silently emitting an all-zero component.
private void bnToFixed(const(BIGNUM)* bn, ubyte[] dst) @trusted
{
	import core.stdc.string : memset;
	import std.conv : to;

	const n = BN_num_bytes(bn);
	if (n <= 0 || n > dst.length)
		throw new Exception("openssl: ECDSA component out of range (n=" ~ n.to!string ~ ")");
	memset(dst.ptr, 0, dst.length);
	ubyte[64] tmp;
	BN_bn2bin(bn, tmp.ptr);
	dst[$ - n .. $] = tmp[0 .. n];
}

/// Whether `s` contains any C0 control character (U+0000..U+001F) or DEL.
private bool containsControlChar(string s) @safe pure nothrow
{
	foreach (char c; s)
		if (c < 0x20 || c == 0x7F)
			return true;
	return false;
}

/// Build a signed ES256 JWT client assertion (RFC 7523) for OAuth client
/// authentication: `iss`/`sub` = client id, `aud` = the token endpoint.
string makeClientAssertion(string clientId, string audience, string privateKeyPem,
		long now, long lifetimeSeconds = 300, string jti = "") @safe
{
	import std.conv : to;

	if (containsControlChar(clientId))
		throw new Exception("makeClientAssertion: clientId contains control characters");
	if (containsControlChar(audience))
		throw new Exception("makeClientAssertion: audience contains control characters");
	if (jti.length && containsControlChar(jti))
		throw new Exception("makeClientAssertion: jti contains control characters");

	string theJti;
	if (jti.length)
	{
		theJti = jti;
	}
	else
	{
		import mcp.auth.csprng : cryptoRandomBytes;
		import std.base64 : Base64URLNoPadding;

		// Append 8 random bytes (base64url, no padding) so the JTI is unique
		// even when two assertions are generated within the same wall-clock second.
		// RFC 7523 §3 requires each jti to be unique per assertion.
		auto randomSuffix = () @trusted { return cryptoRandomBytes(8); }();
		theJti = "jti-" ~ now.to!string ~ "-" ~ Base64URLNoPadding.encode(randomSuffix).idup;
	}

	auto payloadJson = Json.emptyObject;
	payloadJson["iss"] = clientId;
	payloadJson["sub"] = clientId;
	payloadJson["aud"] = audience;
	payloadJson["jti"] = theJti;
	payloadJson["iat"] = now;
	payloadJson["exp"] = now + lifetimeSeconds;

	const header = `{"alg":"ES256","typ":"JWT"}`;
	const payload = payloadJson.toString();
	const signingInput = base64UrlNoPad(cast(const(ubyte)[]) header) ~ "."
		~ base64UrlNoPad(cast(const(ubyte)[]) payload);
	auto sig = signEs256(privateKeyPem, cast(const(ubyte)[]) signingInput);
	return signingInput ~ "." ~ base64UrlNoPad(sig);
}

/// The OAuth `client_assertion_type` for a JWT bearer client assertion.
enum jwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// A general-purpose set of JWT claims for an ES256 access token, as a typed
/// alternative to hand-concatenating JSON. Unlike `makeClientAssertion` (which
/// is fixed to RFC 7523 client-assertion shape with iss==sub==clientId), this
/// lets the issuer, subject, audience and scope vary independently. String
/// claims are populated into the payload via `Json`, so they are escaped rather
/// than interpolated. Empty `iss`/`aud`/`sub`/`scope`/`kid` are omitted; the
/// time claims (`iat`/`nbf`/`exp`) are emitted only when non-zero.
struct JwtClaims
{
	string iss; /// `iss` — token issuer (omitted if empty).
	string aud; /// `aud` — intended audience / resource (omitted if empty).
	string sub; /// `sub` — subject the token represents (omitted if empty).
	string scope_; /// `scope` — space-delimited granted scopes (omitted if empty).
	long iat; /// `iat` — issued-at (seconds since epoch; omitted if 0).
	long nbf; /// `nbf` — not-before (seconds since epoch; omitted if 0).
	long exp; /// `exp` — expiry (seconds since epoch; omitted if 0).
	string kid; /// JWS `kid` header parameter (omitted if empty).
}

/// Build a signed ES256 JWT carrying the given `claims`, using the supplied
/// PKCS#8 EC P-256 private key (PEM). This is the general access-token sibling of
/// `makeClientAssertion`: the payload is assembled with `Json` (so string claims
/// are JSON-escaped, never interpolated) and string claims are rejected up front
/// if they contain control characters, reusing the same injection-hardening.
string mintJwtEs256(string privateKeyPem, JwtClaims claims) @safe
{
	foreach (s; [claims.iss, claims.aud, claims.sub, claims.scope_, claims.kid])
		if (containsControlChar(s))
			throw new Exception("mintJwtEs256: claim contains control characters");

	auto headerJson = Json.emptyObject;
	headerJson["alg"] = "ES256";
	headerJson["typ"] = "JWT";
	if (claims.kid.length)
		headerJson["kid"] = claims.kid;

	auto payloadJson = Json.emptyObject;
	if (claims.iss.length)
		payloadJson["iss"] = claims.iss;
	if (claims.aud.length)
		payloadJson["aud"] = claims.aud;
	if (claims.sub.length)
		payloadJson["sub"] = claims.sub;
	if (claims.scope_.length)
		payloadJson["scope"] = claims.scope_;
	if (claims.iat != 0)
		payloadJson["iat"] = claims.iat;
	if (claims.nbf != 0)
		payloadJson["nbf"] = claims.nbf;
	if (claims.exp != 0)
		payloadJson["exp"] = claims.exp;

	const header = headerJson.toString();
	const payload = payloadJson.toString();
	const signingInput = base64UrlNoPad(cast(const(ubyte)[]) header) ~ "."
		~ base64UrlNoPad(cast(const(ubyte)[]) payload);
	auto sig = signEs256(privateKeyPem, cast(const(ubyte)[]) signingInput);
	return signingInput ~ "." ~ base64UrlNoPad(sig);
}

unittest  // ES256 JWT client assertion has 3 parts and a 64-byte (raw) signature
{
	import std.algorithm : count;
	import std.array : split;
	import std.base64 : Base64URLNoPadding;

	// A throwaway P-256 key (PKCS#8) generated for the test.
	const pem = "-----BEGIN PRIVATE KEY-----\n"
		~ "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7K6+stITLYsQjC9o\n"
		~ "hyL925dgd6gNWRcGOl5RPvIpye+hRANCAATSBYPkHq12VDW5un1kub6zkBc4ieZ9\n"
		~ "nurGMu+tLzJ6+6syOZsQCGlazcSOGsopLyl1QZMIFh9atUYaDfUjJxMq\n"
		~ "-----END PRIVATE KEY-----\n";
	auto jwt = makeClientAssertion("client-1", "https://as.example.com/token", pem, 1_700_000_000);
	auto parts = jwt.split('.');
	assert(parts.length == 3);
	// Signature decodes to 64 raw bytes (R||S for P-256).
	auto sig = Base64URLNoPadding.decode(parts[2]);
	assert(sig.length == 64);
	// Payload contains the expected claims.
	import std.string : indexOf;

	auto payloadJson = () @trusted {
		return (cast(char[]) Base64URLNoPadding.decode(parts[1])).idup;
	}();
	assert(payloadJson.indexOf(`"iss":"client-1"`) >= 0);
	assert(payloadJson.indexOf(`"aud":"https://as.example.com/token"`) >= 0);
}

unittest  // A clientId containing a quote is JSON-escaped, not injected as raw claims
{
	import std.array : split;
	import std.base64 : Base64URLNoPadding;
	import vibe.data.json : parseJsonString;

	const pem = "-----BEGIN PRIVATE KEY-----\n"
		~ "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7K6+stITLYsQjC9o\n"
		~ "hyL925dgd6gNWRcGOl5RPvIpye+hRANCAATSBYPkHq12VDW5un1kub6zkBc4ieZ9\n"
		~ "nurGMu+tLzJ6+6syOZsQCGlazcSOGsopLyl1QZMIFh9atUYaDfUjJxMq\n"
		~ "-----END PRIVATE KEY-----\n";
	// An attacker-controlled clientId attempting to inject an extra "admin" claim.
	const evil = `x","admin":"true`;
	auto jwt = makeClientAssertion(evil, "https://as.example.com/token", pem, 1_700_000_000);
	auto parts = jwt.split('.');
	assert(parts.length == 3);
	auto payloadStr = () @trusted {
		return (cast(char[]) Base64URLNoPadding.decode(parts[1])).idup;
	}();
	auto j = parseJsonString(payloadStr);
	// The literal string is preserved verbatim in iss/sub, not split into claims.
	assert(j["iss"].get!string == evil);
	assert(j["sub"].get!string == evil);
	// No spurious claim was injected.
	assert(j["admin"].type == Json.Type.undefined);
}

unittest  // iat/exp are emitted as JSON numbers, not strings
{
	import std.array : split;
	import std.base64 : Base64URLNoPadding;
	import vibe.data.json : parseJsonString;

	const pem = "-----BEGIN PRIVATE KEY-----\n"
		~ "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7K6+stITLYsQjC9o\n"
		~ "hyL925dgd6gNWRcGOl5RPvIpye+hRANCAATSBYPkHq12VDW5un1kub6zkBc4ieZ9\n"
		~ "nurGMu+tLzJ6+6syOZsQCGlazcSOGsopLyl1QZMIFh9atUYaDfUjJxMq\n"
		~ "-----END PRIVATE KEY-----\n";
	auto jwt = makeClientAssertion("client-1", "https://as.example.com/token",
			pem, 1_700_000_000, 300);
	auto parts = jwt.split('.');
	auto payloadStr = () @trusted {
		return (cast(char[]) Base64URLNoPadding.decode(parts[1])).idup;
	}();
	auto j = parseJsonString(payloadStr);
	assert(j["iat"].get!long == 1_700_000_000);
	assert(j["exp"].get!long == 1_700_000_300);
}

unittest  // Control characters in clientId or audience fail closed
{
	import std.exception : assertThrown;

	const pem = "-----BEGIN PRIVATE KEY-----\n"
		~ "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7K6+stITLYsQjC9o\n"
		~ "hyL925dgd6gNWRcGOl5RPvIpye+hRANCAATSBYPkHq12VDW5un1kub6zkBc4ieZ9\n"
		~ "nurGMu+tLzJ6+6syOZsQCGlazcSOGsopLyl1QZMIFh9atUYaDfUjJxMq\n"
		~ "-----END PRIVATE KEY-----\n";
	assertThrown(makeClientAssertion("bad\nid", "https://as.example.com/token", pem, 1));
	assertThrown(makeClientAssertion("client-1", "https://as.example.com/\ttoken", pem, 1));
}

unittest  // A control character in a caller-supplied jti fails closed
{
	import std.exception : assertThrown;

	const pem = "-----BEGIN PRIVATE KEY-----\n"
		~ "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7K6+stITLYsQjC9o\n"
		~ "hyL925dgd6gNWRcGOl5RPvIpye+hRANCAATSBYPkHq12VDW5un1kub6zkBc4ieZ9\n"
		~ "nurGMu+tLzJ6+6syOZsQCGlazcSOGsopLyl1QZMIFh9atUYaDfUjJxMq\n"
		~ "-----END PRIVATE KEY-----\n";
	assertThrown(makeClientAssertion("client-1",
			"https://as.example.com/token", pem, 1, 300, "bad\njti"));
}

version (unittest) private enum testEcPem = "-----BEGIN PRIVATE KEY-----\n"
	~ "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7K6+stITLYsQjC9o\n"
	~ "hyL925dgd6gNWRcGOl5RPvIpye+hRANCAATSBYPkHq12VDW5un1kub6zkBc4ieZ9\n"
	~ "nurGMu+tLzJ6+6syOZsQCGlazcSOGsopLyl1QZMIFh9atUYaDfUjJxMq\n" ~ "-----END PRIVATE KEY-----\n";

unittest  // mintJwtEs256 emits the supplied claims with iss/sub/aud varying independently
{
	import std.array : split;
	import std.base64 : Base64URLNoPadding;
	import vibe.data.json : parseJsonString;

	JwtClaims claims;
	claims.iss = "https://auth.example.com";
	claims.aud = "https://rs.example.com/mcp";
	claims.sub = "user-42";
	claims.scope_ = "mcp:read mcp:write";
	claims.iat = 1_700_000_000;
	claims.nbf = 1_700_000_000;
	claims.exp = 1_700_003_600;
	claims.kid = "as-1";
	auto jwt = mintJwtEs256(testEcPem, claims);
	auto parts = jwt.split('.');
	assert(parts.length == 3);

	auto headerStr = () @trusted {
		return (cast(char[]) Base64URLNoPadding.decode(parts[0])).idup;
	}();
	auto h = parseJsonString(headerStr);
	assert(h["alg"].get!string == "ES256");
	assert(h["kid"].get!string == "as-1");

	auto payloadStr = () @trusted {
		return (cast(char[]) Base64URLNoPadding.decode(parts[1])).idup;
	}();
	auto j = parseJsonString(payloadStr);
	assert(j["iss"].get!string == "https://auth.example.com");
	assert(j["aud"].get!string == "https://rs.example.com/mcp");
	assert(j["sub"].get!string == "user-42");
	assert(j["scope"].get!string == "mcp:read mcp:write");
	assert(j["iat"].get!long == 1_700_000_000);
	assert(j["nbf"].get!long == 1_700_000_000);
	assert(j["exp"].get!long == 1_700_003_600);
}

unittest  // mintJwtEs256 JSON-escapes a subject containing a quote rather than injecting claims
{
	import std.array : split;
	import std.base64 : Base64URLNoPadding;
	import vibe.data.json : parseJsonString;

	JwtClaims claims;
	claims.iss = "https://auth.example.com";
	claims.sub = `x","admin":"true`;
	auto jwt = mintJwtEs256(testEcPem, claims);
	auto parts = jwt.split('.');
	auto payloadStr = () @trusted {
		return (cast(char[]) Base64URLNoPadding.decode(parts[1])).idup;
	}();
	auto j = parseJsonString(payloadStr);
	assert(j["sub"].get!string == `x","admin":"true`);
	assert(j["admin"].type == Json.Type.undefined);
}

unittest  // mintJwtEs256 omits empty string claims and zero time claims
{
	import std.array : split;
	import std.base64 : Base64URLNoPadding;
	import vibe.data.json : parseJsonString;

	JwtClaims claims;
	claims.iss = "https://auth.example.com";
	claims.sub = "user-42";
	auto jwt = mintJwtEs256(testEcPem, claims);
	auto parts = jwt.split('.');
	auto payloadStr = () @trusted {
		return (cast(char[]) Base64URLNoPadding.decode(parts[1])).idup;
	}();
	auto j = parseJsonString(payloadStr);
	assert(j["aud"].type == Json.Type.undefined);
	assert(j["scope"].type == Json.Type.undefined);
	assert(j["iat"].type == Json.Type.undefined);
	assert(j["nbf"].type == Json.Type.undefined);
	assert(j["exp"].type == Json.Type.undefined);

	auto headerStr = () @trusted {
		return (cast(char[]) Base64URLNoPadding.decode(parts[0])).idup;
	}();
	auto h = parseJsonString(headerStr);
	assert(h["kid"].type == Json.Type.undefined);
}

unittest  // mintJwtEs256 fails closed on control characters in a claim
{
	import std.exception : assertThrown;

	JwtClaims claims;
	claims.iss = "https://auth.example.com";
	claims.sub = "bad\nsub";
	assertThrown(mintJwtEs256(testEcPem, claims));
}

unittest  // auto-generated jti values are unique even when now is identical across calls
{
	import std.array : split;
	import std.base64 : Base64URLNoPadding;
	import vibe.data.json : parseJsonString;

	const pem = "-----BEGIN PRIVATE KEY-----\n"
		~ "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7K6+stITLYsQjC9o\n"
		~ "hyL925dgd6gNWRcGOl5RPvIpye+hRANCAATSBYPkHq12VDW5un1kub6zkBc4ieZ9\n"
		~ "nurGMu+tLzJ6+6syOZsQCGlazcSOGsopLyl1QZMIFh9atUYaDfUjJxMq\n"
		~ "-----END PRIVATE KEY-----\n";
	// Use the same `now` for both calls, as happens when two concurrent requests
	// hit the token endpoint within the same wall-clock second.
	const now = 1_700_000_000L;
	auto jwt1 = makeClientAssertion("client-1", "https://as.example.com/token", pem, now);
	auto jwt2 = makeClientAssertion("client-1", "https://as.example.com/token", pem, now);
	auto payload1 = () @trusted {
		return (cast(char[]) Base64URLNoPadding.decode(jwt1.split('.')[1])).idup;
	}();
	auto payload2 = () @trusted {
		return (cast(char[]) Base64URLNoPadding.decode(jwt2.split('.')[1])).idup;
	}();
	auto j1 = parseJsonString(payload1);
	auto j2 = parseJsonString(payload2);
	// The two auto-generated JTI values must differ to prevent replay rejection.
	assert(j1["jti"].get!string != j2["jti"].get!string);
}

unittest  // bnToFixed throws when the BIGNUM is zero (n == 0) rather than silently zeroing dst
{
	import std.exception : assertThrown;

	() @trusted {
		// BN_new() returns a zero-valued BIGNUM; BN_num_bytes returns 0 for it.
		auto bn = BN_new();
		scope (exit)
			BN_free(bn);
		ubyte[32] dst;
		assertThrown(bnToFixed(bn, dst[]));
	}();
}

unittest  // bnToFixed throws when the BIGNUM is wider than dst rather than silently zeroing dst
{
	import std.exception : assertThrown;

	() @trusted {
		// A BIGNUM that requires 33 bytes does not fit in a 32-byte dst.
		auto bn = BN_new();
		scope (exit)
			BN_free(bn);
		// 2^256 requires 33 bytes to encode.
		ubyte[33] bigBytes;
		bigBytes[0] = 1; // = 2^256
		BN_bin2bn(bigBytes.ptr, cast(int) bigBytes.length, bn);
		ubyte[32] dst;
		assertThrown(bnToFixed(bn, dst[]));
	}();
}
