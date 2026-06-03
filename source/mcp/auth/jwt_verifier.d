/// A ready-made JWT (RFC 7519) access-token verifier that plugs into
/// `ResourceServerConfig.validator`, so MCP server authors don't have to
/// hand-roll JWS signature verification, JWKS fetching, and claim checks. It is
/// the D analogue of FastMCP's `JWTVerifier`.
///
/// The verifier checks the JWS signature (RS256 and ES256, RFC 7518), then the
/// registered claims — `exp`/`nbf` with clock skew, `iss`, `aud` (the RFC 8707
/// resource) — and finally any required scopes, mapping a valid token to a
/// `TokenInfo` with `subject`, `scopes`, and `audience` populated.
module mcp.auth.jwt_verifier;

import core.stdc.config : c_long;
import core.time : Duration, seconds;

import std.algorithm : canFind;
import std.array : split;
import std.string : strip;

import vibe.data.json : Json, parseJsonString;

import deimos.openssl.bio;
import deimos.openssl.pem;
import deimos.openssl.evp;
import deimos.openssl.ecdsa;
import deimos.openssl.ec;
import deimos.openssl.rsa;
import deimos.openssl.bn;
import deimos.openssl.obj_mac;

import mcp.auth.resource_server : TokenInfo, TokenValidator;

@safe:

/// Configuration for `jwtVerifier`. Provide either a `jwksUri` (the verifier
/// fetches and caches the issuer's JWKS, selecting the key by `kid`) or one or
/// more `staticPublicKeysPem` (PEM SubjectPublicKeyInfo blobs pinned directly).
struct JwtVerifierConfig
{
	/// The JWKS endpoint to fetch verification keys from (kid-selected). When
	/// empty, only `staticPublicKeysPem` are used.
	string jwksUri;

	/// PEM-encoded public keys (`-----BEGIN PUBLIC KEY-----`) pinned directly,
	/// tried in order. An alternative to `jwksUri` for static deployments.
	string[] staticPublicKeysPem;

	/// The required token issuer (`iss`). When set, a token whose `iss` differs
	/// is rejected.
	string issuer;

	/// The required audience (`aud`, the RFC 8707 resource). When set, a token
	/// that does not list it among its audiences is rejected.
	string audience;

	/// Scopes the token must carry (from `scope` or `scp`). All must be present.
	string[] requiredScopes;

	/// Leeway applied to `exp`/`nbf` to tolerate clock skew.
	Duration clockSkew = 60.seconds;

	/// How long a fetched JWKS document is cached before being refetched.
	Duration jwksCacheTtl = 300.seconds;
}

// ===========================================================================
// Public entry point
// ===========================================================================

/// Build a `TokenValidator` from `cfg`. The returned delegate verifies a bearer
/// JWT and yields a `TokenInfo` (`valid == false` on any failure). Plug it into
/// `ResourceServerConfig.validator`.
TokenValidator jwtVerifier(JwtVerifierConfig cfg) @safe
{
	auto cache = new JwksCache(cfg.jwksUri, cfg.jwksCacheTtl);
	return (string token) @safe {
		try
			return verifyToken(cfg, token, cache, currentUnixTime());
		catch (Exception)
			return TokenInfo.invalid();
	};
}

// ===========================================================================
// Verification core (pure of HTTP / clock; unit-testable)
// ===========================================================================

/// A source of candidate verification keys. `keysFor(kid)` returns the PEM
/// public keys to try for a token bearing the given `kid` (empty `kid` means the
/// header had none).
package interface KeySource
{
	string[] keysFor(string kid) @safe;
}

/// Verify `token` against `cfg` at wall-clock time `now` (unix seconds), drawing
/// JWKS keys from `keys`. Separated from clock/HTTP so tests can drive it
/// deterministically.
package TokenInfo verifyToken(JwtVerifierConfig cfg, string token, KeySource keys, long now) @safe
{
	auto parts = token.split('.');
	if (parts.length != 3)
		return TokenInfo.invalid();

	const headerJson = decodeSegmentJson(parts[0]);
	const payloadJson = decodeSegmentJson(parts[1]);
	if (headerJson.type != Json.Type.object || payloadJson.type != Json.Type.object)
		return TokenInfo.invalid();

	const alg = jsonStr(headerJson, "alg");
	const kid = jsonStr(headerJson, "kid");
	if (alg != "RS256" && alg != "ES256")
		return TokenInfo.invalid();

	// RFC 7515 4.1.11: a `crit` header lists extensions the recipient MUST
	// understand. This verifier implements none, so any token carrying a
	// `crit` member MUST be rejected rather than silently accepted.
	if ("crit" in headerJson)
		return TokenInfo.invalid();

	// Gather candidate keys: pinned PEM keys plus any JWKS keys for this kid.
	string[] candidates = cfg.staticPublicKeysPem.dup;
	candidates ~= keys.keysFor(kid);
	if (candidates.length == 0)
		return TokenInfo.invalid();

	const signingInput = parts[0] ~ "." ~ parts[1];
	const sig = base64UrlDecode(parts[2]);

	bool sigOk = false;
	foreach (pem; candidates)
	{
		if (verifyJws(alg, cast(const(ubyte)[]) signingInput, sig, pem))
		{
			sigOk = true;
			break;
		}
	}
	if (!sigOk)
		return TokenInfo.invalid();

	return validateClaims(cfg, payloadJson, now);
}

/// Validate the registered claims of an already-signature-verified payload.
package TokenInfo validateClaims(JwtVerifierConfig cfg, Json payload, long now) @safe
{
	const skew = cast(long) cfg.clockSkew.total!"seconds";

	// A JWT access token without an integer `exp` cannot be validated as
	// unexpired, so it MUST be rejected (OAuth 2.1 §5.2 token validation,
	// RFC 9068 §2.2/§4). An absent or non-integer `exp` is treated as invalid.
	if (payload["exp"].type != Json.Type.int_)
		return TokenInfo.invalid();
	const e = jsonLong(payload, "exp");
	if (now > e + skew)
		return TokenInfo.invalid();
	const nbf = jsonLong(payload, "nbf");
	if (nbf != 0 && now + skew < nbf)
		return TokenInfo.invalid();

	if (cfg.issuer.length && jsonStr(payload, "iss") != cfg.issuer)
		return TokenInfo.invalid();

	auto auds = audiences(payload);
	if (cfg.audience.length && !auds.canFind(cfg.audience))
		return TokenInfo.invalid();

	auto scopes = tokenScopes(payload);
	foreach (req; cfg.requiredScopes)
		if (!scopes.canFind(req))
			return TokenInfo.invalid();

	TokenInfo ti;
	ti.valid = true;
	ti.subject = jsonStr(payload, "sub");
	ti.scopes = scopes;
	ti.audience = auds;
	ti.claims = payload;
	return ti;
}

// ===========================================================================
// JWS signature verification (OpenSSL EVP)
// ===========================================================================

/// Verify a JWS signature over `signingInput` for the given `alg` using the PEM
/// public key. For ES256 the signature is the raw 64-byte R||S form (RFC 7518
/// §3.4), converted to DER before handing to OpenSSL.
package bool verifyJws(string alg, const(ubyte)[] signingInput,
		const(ubyte)[] sig, string publicKeyPem) @trusted
{
	auto pkey = parsePublicKeyPem(publicKeyPem);
	if (pkey is null)
		return false;
	scope (exit)
		EVP_PKEY_free(pkey);

	const(ubyte)[] derSig;
	if (alg == "ES256")
	{
		derSig = rawEcdsaToDer(sig);
		if (derSig is null)
			return false;
	}
	else
		derSig = sig;

	auto ctx = EVP_MD_CTX_new();
	if (ctx is null)
		return false;
	scope (exit)
		EVP_MD_CTX_free(ctx);

	if (EVP_DigestVerifyInit(ctx, null, EVP_sha256(), null, pkey) != 1)
		return false;
	const rc = EVP_DigestVerify(ctx, derSig.ptr, derSig.length,
			signingInput.ptr, signingInput.length);
	return rc == 1;
}

/// Convert a raw 64-byte ECDSA P-256 signature (R||S) to the DER encoding
/// OpenSSL's verifier expects. Returns null on malformed input.
private const(ubyte)[] rawEcdsaToDer(const(ubyte)[] raw) @trusted
{
	if (raw.length != 64)
		return null;
	auto r = BN_bin2bn(raw.ptr, 32, null);
	auto s = BN_bin2bn(raw.ptr + 32, 32, null);
	if (r is null || s is null)
	{
		if (r !is null)
			BN_free(r);
		if (s !is null)
			BN_free(s);
		return null;
	}
	auto sig = ECDSA_SIG_new();
	if (sig is null)
	{
		BN_free(r);
		BN_free(s);
		return null;
	}
	scope (exit)
		ECDSA_SIG_free(sig);
	// ECDSA_SIG_set0 takes ownership of r and s.
	if (ECDSA_SIG_set0(sig, r, s) != 1)
		return null;

	ubyte* der;
	const len = i2d_ECDSA_SIG(sig, &der);
	if (len <= 0)
		return null;
	scope (exit)
		CRYPTO_free(der);
	return der[0 .. len].dup;
}

/// Parse a PEM SubjectPublicKeyInfo (`-----BEGIN PUBLIC KEY-----`) into an
/// EVP_PKEY (RSA or EC), or null on failure.
private EVP_PKEY* parsePublicKeyPem(string pem) @trusted
{
	auto bio = BIO_new_mem_buf(cast(void*) pem.ptr, cast(int) pem.length);
	if (bio is null)
		return null;
	scope (exit)
		BIO_free(bio);
	return PEM_read_bio_PUBKEY(bio, null, null, null);
}

// CRYPTO_free / OPENSSL_free for the i2d-allocated buffer.
private extern (C) void CRYPTO_free(void* ptr) @nogc nothrow;

// ===========================================================================
// JWKS handling
// ===========================================================================

/// A parsed JWK relevant to verification.
package struct Jwk
{
	string kty; /// "RSA" or "EC"
	string kid;
	string alg;
	// RSA
	string n;
	string e;
	// EC
	string crv;
	string x;
	string y;
}

/// Parse a JWKS document (`{"keys":[...]}`) into JWKs. Tolerant of unknown
/// fields and missing optional members.
package Jwk[] parseJwks(string jwksJson) @safe
{
	Jwk[] result;
	auto root = parseJsonString(jwksJson);
	if (root.type != Json.Type.object)
		return result;
	auto keys = root["keys"];
	if (keys.type != Json.Type.array)
		return result;
	foreach (k; ()@trusted { return keys.get!(Json[]); }())
	{
		if (k.type != Json.Type.object)
			continue;
		Jwk j;
		j.kty = jsonStr(k, "kty");
		j.kid = jsonStr(k, "kid");
		j.alg = jsonStr(k, "alg");
		j.n = jsonStr(k, "n");
		j.e = jsonStr(k, "e");
		j.crv = jsonStr(k, "crv");
		j.x = jsonStr(k, "x");
		j.y = jsonStr(k, "y");
		result ~= j;
	}
	return result;
}

/// Convert a JWK to a PEM SubjectPublicKeyInfo public key. Supports RSA (n/e)
/// and EC P-256 (crv=P-256, x/y). Returns null for unsupported keys.
package string jwkToPem(Jwk jwk) @trusted
{
	if (jwk.kty == "RSA")
		return rsaJwkToPem(jwk);
	if (jwk.kty == "EC")
		return ecJwkToPem(jwk);
	return null;
}

private string rsaJwkToPem(Jwk jwk) @trusted
{
	if (jwk.n.length == 0 || jwk.e.length == 0)
		return null;
	auto nBytes = base64UrlDecode(jwk.n);
	auto eBytes = base64UrlDecode(jwk.e);
	auto n = BN_bin2bn(nBytes.ptr, cast(int) nBytes.length, null);
	auto e = BN_bin2bn(eBytes.ptr, cast(int) eBytes.length, null);
	if (n is null || e is null)
	{
		if (n)
			BN_free(n);
		if (e)
			BN_free(e);
		return null;
	}
	auto rsa = RSA_new();
	if (rsa is null)
	{
		BN_free(n);
		BN_free(e);
		return null;
	}
	scope (exit)
		RSA_free(rsa);
	// RSA_set0_key takes ownership of n and e (d may be null).
	if (RSA_set0_key(rsa, n, e, null) != 1)
		return null;

	auto pkey = EVP_PKEY_new();
	if (pkey is null)
		return null;
	scope (exit)
		EVP_PKEY_free(pkey);
	if (EVP_PKEY_set1_RSA(pkey, rsa) != 1)
		return null;
	return pkeyToPem(pkey);
}

private string ecJwkToPem(Jwk jwk) @trusted
{
	if (jwk.crv != "P-256" || jwk.x.length == 0 || jwk.y.length == 0)
		return null;
	auto eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (eckey is null)
		return null;
	scope (exit)
		EC_KEY_free(eckey);
	auto group = EC_KEY_get0_group(eckey);
	auto pt = EC_POINT_new(group);
	if (pt is null)
		return null;
	scope (exit)
		EC_POINT_free(pt);

	auto xBytes = base64UrlDecode(jwk.x);
	auto yBytes = base64UrlDecode(jwk.y);
	auto bx = BN_bin2bn(xBytes.ptr, cast(int) xBytes.length, null);
	auto by = BN_bin2bn(yBytes.ptr, cast(int) yBytes.length, null);
	if (bx is null || by is null)
	{
		if (bx)
			BN_free(bx);
		if (by)
			BN_free(by);
		return null;
	}
	scope (exit)
	{
		BN_free(bx);
		BN_free(by);
	}
	if (EC_POINT_set_affine_coordinates_GFp(group, pt, bx, by, null) != 1)
		return null;
	if (EC_KEY_set_public_key(eckey, pt) != 1)
		return null;

	auto pkey = EVP_PKEY_new();
	if (pkey is null)
		return null;
	scope (exit)
		EVP_PKEY_free(pkey);
	if (EVP_PKEY_set1_EC_KEY(pkey, eckey) != 1)
		return null;
	return pkeyToPem(pkey);
}

private string pkeyToPem(EVP_PKEY* pkey) @trusted
{
	auto bio = BIO_new(BIO_s_mem());
	if (bio is null)
		return null;
	scope (exit)
		BIO_free(bio);
	if (PEM_write_bio_PUBKEY(bio, pkey) != 1)
		return null;
	ubyte* data;
	const len = BIO_get_mem_data(bio, &data);
	if (len <= 0)
		return null;
	return (cast(char[]) data[0 .. len]).idup;
}

/// A TTL cache for a JWKS document, refetched on demand. Selects keys by `kid`;
/// when a token's `kid` is unknown, every JWKS key is offered as a candidate.
package final class JwksCache : KeySource
{
	private string uri;
	private Duration ttl;
	private string[string] pemByKid; // kid -> PEM
	private string[] allPems;
	private long fetchedAt = -1;
	private bool loaded = false;

	this(string uri, Duration ttl) @safe
	{
		this.uri = uri;
		this.ttl = ttl;
	}

	/// Candidate PEM keys for a `kid`. Triggers a (re)fetch when stale.
	string[] keysFor(string kid) @safe
	{
		if (uri.length == 0)
		{
			if (loaded)
				return kidKeys(kid);
			return null;
		}
		refreshIfStale();
		return kidKeys(kid);
	}

	private string[] kidKeys(string kid) @safe
	{
		if (kid.length)
			if (auto p = kid in pemByKid)
				return [*p];
		// Unknown/absent kid: offer all keys.
		return allPems.dup;
	}

	private void refreshIfStale() @safe
	{
		const now = currentUnixTime();
		if (loaded && fetchedAt >= 0 && now - fetchedAt < cast(long) ttl.total!"seconds")
			return;
		const doc = fetchJwks(uri);
		if (doc.length)
			load(doc);
	}

	/// Populate the cache from a raw JWKS document (also the test seam).
	void load(string jwksJson) @safe
	{
		pemByKid = null;
		allPems = null;
		foreach (jwk; parseJwks(jwksJson))
		{
			const pem = jwkToPem(jwk);
			if (pem.length == 0)
				continue;
			allPems ~= pem;
			if (jwk.kid.length)
				pemByKid[jwk.kid] = pem;
		}
		loaded = true;
		fetchedAt = currentUnixTime();
	}
}

/// Fetch a JWKS document over HTTP(S). Returns the body, or empty on failure.
private string fetchJwks(string uri) @trusted
{
	import vibe.http.client : HTTPClientRequest, HTTPClientResponse;
	import vibe.http.common : HTTPMethod;
	import vibe.stream.operations : readAllUTF8;
	import mcp.auth.oauth : secureRequestHTTP;

	// Refuse to fetch a JWKS over an insecure transport (must be https, or http
	// to a loopback host for dev) or from an internal/link-local address. The
	// fetch is pinned to a pre-vetted resolved address (DNS-rebinding SSRF
	// mitigation); secureRequestHTTP throws on an unsafe or unresolvable host.
	string body_;
	try
	{
		secureRequestHTTP(uri, (scope HTTPClientRequest req) {
			req.method = HTTPMethod.GET;
		}, (scope HTTPClientResponse res) { body_ = res.bodyReader.readAllUTF8(); });
	}
	catch (Exception)
		return null;
	return body_;
}

// ===========================================================================
// Small helpers
// ===========================================================================

// Shared across the mcp.auth package (also used by introspection_verifier).
package long currentUnixTime() @safe
{
	import std.datetime.systime : Clock;

	return Clock.currTime.toUnixTime;
}

/// base64url-decode a JWS segment (no padding), returning the raw bytes.
package ubyte[] base64UrlDecode(string seg) @safe
{
	import std.base64 : Base64URLNoPadding;

	return () @trusted { return Base64URLNoPadding.decode(seg); }();
}

private Json decodeSegmentJson(string seg) @safe
{
	try
	{
		auto bytes = base64UrlDecode(seg);
		auto s = () @trusted { return (cast(char[]) bytes).idup; }();
		return parseJsonString(s);
	}
	catch (Exception)
		return Json.undefined;
}

// Shared across the mcp.auth package (also used by introspection_verifier).
package string jsonStr(Json j, string key) @safe
{
	auto v = j[key];
	if (v.type == Json.Type.string)
		return v.get!string;
	return null;
}

/// Read an integer claim, returning 0 when absent or not an integer. Callers
/// that require presence (e.g. `exp`) must check the JSON type separately;
/// `nbf` is genuinely optional so a 0 result correctly disables the check.
private long jsonLong(Json j, string key) @safe
{
	auto v = j[key];
	if (v.type == Json.Type.int_)
		return v.get!long;
	return 0;
}

/// Extract the audiences from a claims object: `aud` may be a string or an array
/// of strings (RFC 7519 §4.1.3). Shared with introspection (RFC 7662 §2.2).
package string[] audiences(Json payload) @safe
{
	string[] result;
	auto a = payload["aud"];
	if (a.type == Json.Type.string)
		result ~= a.get!string;
	else if (a.type == Json.Type.array)
		foreach (e; ()@trusted { return a.get!(Json[]); }())
			if (e.type == Json.Type.string)
				result ~= e.get!string;
	return result;
}

/// Split a space-delimited scope string into individual scopes, dropping empty
/// elements so an empty or all-whitespace claim yields no scopes (an empty
/// string would otherwise split into a spurious single `""` scope). Shared with
/// introspection's `scope` parsing (RFC 7662 §2.2).
package string[] splitScopes(string s) @safe
{
	import std.algorithm : filter;
	import std.array : array;

	auto parts = s.strip.split(' ').filter!(x => x.length).array;
	return parts.length ? parts : null;
}

/// Extract granted scopes: OAuth uses a space-delimited `scope` string; some
/// issuers use `scp` (string or array).
string[] tokenScopes(Json payload) @safe
{
	auto scope_ = payload["scope"];
	if (scope_.type == Json.Type.string)
		return splitScopes(scope_.get!string);

	auto scp = payload["scp"];
	if (scp.type == Json.Type.string)
		return splitScopes(scp.get!string);
	if (scp.type == Json.Type.array)
	{
		string[] result;
		foreach (e; ()@trusted { return scp.get!(Json[]); }())
			if (e.type == Json.Type.string)
				result ~= e.get!string;
		return result;
	}
	return null;
}

// ===========================================================================
// Tests
// ===========================================================================

version (unittest)
{
	// Throwaway P-256 PKCS#8 private key (matches the EC public key below).
	private enum testEcPrivPem = "-----BEGIN PRIVATE KEY-----\n"
		~ "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgy5nLkurotTseFLEh\n"
		~ "TcetOpmlWQKsY10kx9Dcg6b7m02hRANCAARdpXuunF3oDfCSUKOtGkybZPpwLUPF\n"
		~ "lCYgn/nxuirfH7L2jXQ/brpaEHPPPTMZgp6p33PDD6VGlbXVXCchEIe0\n"
		~ "-----END PRIVATE KEY-----\n";

	private enum testEcPubPem = "-----BEGIN PUBLIC KEY-----\n"
		~ "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXaV7rpxd6A3wklCjrRpMm2T6cC1D\n"
		~ "xZQmIJ/58boq3x+y9o10P266WhBzzz0zGYKeqd9zww+lRpW11VwnIRCHtA==\n"
		~ "-----END PUBLIC KEY-----\n";

	private enum testEcX = "XaV7rpxd6A3wklCjrRpMm2T6cC1DxZQmIJ_58boq3x8";
	private enum testEcY = "svaNdD9uuloQc889MxmCnqnfc8MPpUaVtdVcJyEQh7Q";

	// RS256 token: iss=https://as.example.com aud=https://mcp.example.com/mcp
	// sub=user-42 scope="mcp:read mcp:write" iat/nbf=1700000000 exp=1700003600.
	private enum testRs256Jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJzYS0xIn0." ~ "eyJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIiwiYXVkIjoiaHR0cHM6Ly9tY3AuZXhhbXBsZS5jb20vbWNwIiwic3ViIjoidXNlci00MiIsInNjb3BlIjoibWNwOnJlYWQgbWNwOndyaXRlIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDM2MDAsIm5iZiI6MTcwMDAwMDAwMH0." ~ "rsJbM09KZlDv2dzjrHLx6z6o6bFRv6UiEu1loqw7Yfgb8-po7VEIUlxjSmmCbmk5CAThYczWqCpwiH-biAXSw8kCUZpqkXM4VDiylK0LACOgYLUMMpdpM2dwQUV19w185ZSv4e1aBs9mB7IVQ6FD7_FYSnVOmZcmbEF2EoNiPitwkz4AA_0dMGRXibgvsUZ4FEE1hVmYCw44MiO18V4n9reuVJfttm2jUhBJHQ09E8S7bY2W0xT0Gt9Kl05wYhjtye34U3BV845-5qqbyv97yXwMhXOwBdT1Tzza0beGvw3F-x59JIV4E9r0GnvTa9_x5uR4uxYyK0L-zmHZT51OQw";

	private enum testRsaN = "tM_67g06tD1iNUxYKgTI4Fgusl7FKrFE54E-2VpAAbluGPXBT6_bytUr4bTPgN4URBfQ6rFx31yuvrD6UL1LAOgxEgMOmdl8ZSsjIaN1Y19_MIf7aiqMw8VcqDalHphEQl5Xuv6_TQPjTh9g7WPJGQe5UGr3izTz1ZUxsKDsWYmdMfEpsPoqGQ4MLA3fpXmwXj2x1N9zYKqIFBne8h63X3lVrnp7i9ROp4SyR36pEWL4Wd7NrHLeU8wDDl5gVIzKppFdoZyhrH3Zu_eK8se_f0w-LBx-3laJfqQ3f9T2X3L54k4eUtViDNeNmk3G1gAsPaGBSbvA_5p4rvHW-TtINw";

	private enum testRsaE = "AQAB";

	// A different (unrelated) RSA modulus, for negative key-mismatch tests.
	private enum testRsaN2 = "uxM0I78B8wYCo28dnkkZzt01P1-mpKf1k5tlQiBu0afViMF-7YfkOFwwRt2DigHwYo_eQ3wfZlWIyyDxfb25XafNLQFYIJAJj4B2syTvApR6ze7m208exCD2oaHYmTzc-DfKH0ybG06YtEvvIUiSppN118RIRCwz9u6jb5h5b77rrGLE-bQ-FgW4BYOekowWnYV4YLbWoeBSL2x0UdnLfu8_hgPmzRTzcPJhLivk2uX0zdaREnpcNGSJOcFIInYzdmuZeYbNgUv4J53w558c1I1qkzpnE1Rmn86WD5LCMM9prTFzCi61mDDcTxeJgdO7g3Yc4_FxPGO1urYBtakpVQ";

	// Build an ES256 JWT signed with testEcPrivPem.
	private string makeEs256(string payload, string kid = "") @safe
	{
		import mcp.auth.jwt : signEs256;
		import mcp.auth.oauth : base64UrlNoPad;

		const header = kid.length
			? (`{"alg":"ES256","typ":"JWT","kid":"` ~ kid ~ `"}`) : `{"alg":"ES256","typ":"JWT"}`;
		const si = base64UrlNoPad(cast(const(ubyte)[]) header) ~ "." ~ base64UrlNoPad(
				cast(const(ubyte)[]) payload);
		auto sig = signEs256(testEcPrivPem, cast(const(ubyte)[]) si);
		return si ~ "." ~ base64UrlNoPad(sig);
	}

	// A KeySource that returns no JWKS keys (pinned-PEM-only tests).
	private final class NoKeys : KeySource
	{
		string[] keysFor(string kid) @safe
		{
			return null;
		}
	}
}

unittest  // a valid RS256 token with good sig/iss/aud/scope is accepted
{
	JwtVerifierConfig cfg;
	cfg.issuer = "https://as.example.com";
	cfg.audience = "https://mcp.example.com/mcp";
	cfg.requiredScopes = ["mcp:read"];

	auto cache = new JwksCache("", cfg.jwksCacheTtl);
	cache.load(`{"keys":[{"kty":"RSA","kid":"rsa-1","n":"` ~ testRsaN ~ `","e":"` ~ testRsaE
			~ `"}]}`);

	auto ti = verifyToken(cfg, testRs256Jwt, cache, 1_700_001_000);
	assert(ti.valid);
	assert(ti.subject == "user-42");
	assert(ti.scopes.canFind("mcp:read"));
	assert(ti.scopes.canFind("mcp:write"));
	assert(ti.audience.canFind("https://mcp.example.com/mcp"));
}

unittest  // a tampered RS256 signature is rejected
{
	JwtVerifierConfig cfg;
	auto cache = new JwksCache("", cfg.jwksCacheTtl);
	cache.load(`{"keys":[{"kty":"RSA","kid":"rsa-1","n":"` ~ testRsaN ~ `","e":"` ~ testRsaE
			~ `"}]}`);

	// Flip the last character of the signature segment.
	auto tampered = testRs256Jwt[0 .. $ - 1] ~ (testRs256Jwt[$ - 1] == 'A' ? "B" : "A");
	auto ti = verifyToken(cfg, tampered, cache, 1_700_001_000);
	assert(!ti.valid);
}

unittest  // an expired token is rejected (beyond clock skew)
{
	JwtVerifierConfig cfg;
	auto cache = new JwksCache("", cfg.jwksCacheTtl);
	cache.load(`{"keys":[{"kty":"RSA","kid":"rsa-1","n":"` ~ testRsaN ~ `","e":"` ~ testRsaE
			~ `"}]}`);

	// exp is 1700003600; evaluate well past it + skew.
	auto ti = verifyToken(cfg, testRs256Jwt, cache, 1_700_010_000);
	assert(!ti.valid);
}

unittest  // a token with no exp claim is rejected (cannot be validated as unexpired)
{
	JwtVerifierConfig cfg;
	// A signature-verified payload with every other claim present but no exp.
	auto payload = parseJsonString(`{"iss":"https://as.example.com","sub":"ec-user","scope":"mcp:read","iat":1700000000,"nbf":1700000000}`);
	auto ti = validateClaims(cfg, payload, 1_700_001_000);
	assert(!ti.valid);
}

unittest  // a token with a present integer exp claim validates
{
	JwtVerifierConfig cfg;
	auto payload = parseJsonString(
			`{"sub":"ec-user","iat":1700000000,"exp":1700003600,"nbf":1700000000}`);
	auto ti = validateClaims(cfg, payload, 1_700_001_000);
	assert(ti.valid);
	assert(ti.subject == "ec-user");
}

unittest  // a non-integer exp claim is rejected (cannot be validated as unexpired)
{
	JwtVerifierConfig cfg;
	auto payload = parseJsonString(`{"sub":"ec-user","exp":"not-a-number"}`);
	auto ti = validateClaims(cfg, payload, 1_700_001_000);
	assert(!ti.valid);
}

unittest  // the wrong issuer is rejected
{
	JwtVerifierConfig cfg;
	cfg.issuer = "https://evil.example.com";
	auto cache = new JwksCache("", cfg.jwksCacheTtl);
	cache.load(`{"keys":[{"kty":"RSA","kid":"rsa-1","n":"` ~ testRsaN ~ `","e":"` ~ testRsaE
			~ `"}]}`);

	auto ti = verifyToken(cfg, testRs256Jwt, cache, 1_700_001_000);
	assert(!ti.valid);
}

unittest  // the wrong audience is rejected
{
	JwtVerifierConfig cfg;
	cfg.audience = "https://other.example.com";
	auto cache = new JwksCache("", cfg.jwksCacheTtl);
	cache.load(`{"keys":[{"kty":"RSA","kid":"rsa-1","n":"` ~ testRsaN ~ `","e":"` ~ testRsaE
			~ `"}]}`);

	auto ti = verifyToken(cfg, testRs256Jwt, cache, 1_700_001_000);
	assert(!ti.valid);
}

unittest  // a missing required scope is rejected
{
	JwtVerifierConfig cfg;
	cfg.requiredScopes = ["mcp:admin"];
	auto cache = new JwksCache("", cfg.jwksCacheTtl);
	cache.load(`{"keys":[{"kty":"RSA","kid":"rsa-1","n":"` ~ testRsaN ~ `","e":"` ~ testRsaE
			~ `"}]}`);

	auto ti = verifyToken(cfg, testRs256Jwt, cache, 1_700_001_000);
	assert(!ti.valid);
}

unittest  // a token whose only candidate key is the wrong key is rejected
{
	JwtVerifierConfig cfg;
	auto cache = new JwksCache("", cfg.jwksCacheTtl);
	// The JWKS holds a single, unrelated RSA key; the RS256 token was signed by
	// a different key, so signature verification must fail.
	cache.load(`{"keys":[{"kty":"RSA","kid":"other","n":"` ~ testRsaN2 ~ `","e":"`
			~ testRsaE ~ `"}]}`);

	auto ti = verifyToken(cfg, testRs256Jwt, cache, 1_700_001_000);
	assert(!ti.valid);
}

unittest  // ES256: a token verified with a pinned PEM public key is accepted
{
	JwtVerifierConfig cfg;
	cfg.issuer = "https://as.example.com";
	cfg.audience = "https://mcp.example.com/mcp";
	cfg.staticPublicKeysPem = [testEcPubPem];

	const payload = `{"iss":"https://as.example.com","aud":"https://mcp.example.com/mcp","sub":"ec-user","scope":"mcp:read","iat":1700000000,"exp":1700003600,"nbf":1700000000}`;
	auto jwt = makeEs256(payload);

	auto ti = verifyToken(cfg, jwt, new NoKeys, 1_700_001_000);
	assert(ti.valid);
	assert(ti.subject == "ec-user");
}

unittest  // ES256: verification via an EC JWK (crv/x/y) from a JWKS document
{
	JwtVerifierConfig cfg;
	auto cache = new JwksCache("", cfg.jwksCacheTtl);
	cache.load(`{"keys":[{"kty":"EC","kid":"ec-1","crv":"P-256","x":"`
			~ testEcX ~ `","y":"` ~ testEcY ~ `"}]}`);

	const payload = `{"sub":"ec-user","iat":1700000000,"exp":1700003600,"nbf":1700000000}`;
	auto jwt = makeEs256(payload, "ec-1");

	auto ti = verifyToken(cfg, jwt, cache, 1_700_001_000);
	assert(ti.valid);
	assert(ti.subject == "ec-user");
}

unittest  // a bad-signature ES256 token (verified against the wrong EC key) fails
{
	JwtVerifierConfig cfg;
	cfg.staticPublicKeysPem = [testEcPubPem];

	// Sign with the EC key but tamper a payload byte after signing.
	const payload = `{"sub":"ec-user","exp":1700003600}`;
	auto jwt = makeEs256(payload);
	auto tampered = jwt[0 .. $ - 2] ~ (jwt[$ - 2] == 'A' ? "BB" : "AA");

	auto ti = verifyToken(cfg, tampered, new NoKeys, 1_700_001_000);
	assert(!ti.valid);
}

unittest  // an unsupported alg (e.g. none) is rejected outright
{
	import mcp.auth.oauth : base64UrlNoPad;

	JwtVerifierConfig cfg;
	cfg.staticPublicKeysPem = [testEcPubPem];

	const header = base64UrlNoPad(cast(const(ubyte)[]) `{"alg":"none","typ":"JWT"}`);
	const payload = base64UrlNoPad(cast(const(ubyte)[]) `{"sub":"x"}`);
	auto jwt = header ~ "." ~ payload ~ ".";

	auto ti = verifyToken(cfg, jwt, new NoKeys, 1_700_001_000);
	assert(!ti.valid);
}

unittest  // a token carrying a `crit` header is rejected even with a valid signature (RFC 7515 4.1.11)
{
	import mcp.auth.jwt : signEs256;
	import mcp.auth.oauth : base64UrlNoPad;

	JwtVerifierConfig cfg;
	cfg.staticPublicKeysPem = [testEcPubPem];

	const header = `{"alg":"ES256","typ":"JWT","crit":["exp"]}`;
	const payload = `{"sub":"ec-user","exp":1700003600}`;
	const si = base64UrlNoPad(cast(const(ubyte)[]) header) ~ "." ~ base64UrlNoPad(
			cast(const(ubyte)[]) payload);
	auto sig = signEs256(testEcPrivPem, cast(const(ubyte)[]) si);
	auto jwt = si ~ "." ~ base64UrlNoPad(sig);

	auto ti = verifyToken(cfg, jwt, new NoKeys, 1_700_001_000);
	assert(!ti.valid);
}

unittest  // an empty `scope` claim yields no scopes (not a spurious empty-string scope)
{
	assert(tokenScopes(parseJsonString(`{"scope":""}`)) is null);
}

unittest  // an all-whitespace `scope` claim yields no scopes
{
	assert(tokenScopes(parseJsonString(`{"scope":"   "}`)) is null);
}

unittest  // an empty `scp` string claim yields no scopes
{
	assert(tokenScopes(parseJsonString(`{"scp":""}`)) is null);
}

unittest  // internal runs of spaces do not produce empty-string scopes
{
	assert(tokenScopes(parseJsonString(`{"scope":"a   b"}`)) == ["a", "b"]);
}

unittest  // parseJwks reads RSA and EC keys, ignoring unknown members
{
	auto jwks = parseJwks(`{"keys":[
        {"kty":"RSA","kid":"r1","n":"` ~ testRsaN ~ `","e":"AQAB","use":"sig","extra":123},
        {"kty":"EC","kid":"e1","crv":"P-256","x":"` ~ testEcX ~ `","y":"` ~ testEcY ~ `"}
    ]}`);
	assert(jwks.length == 2);
	assert(jwks[0].kty == "RSA" && jwks[0].kid == "r1" && jwks[0].e == "AQAB");
	assert(jwks[1].kty == "EC" && jwks[1].crv == "P-256");
}

unittest  // jwkToPem produces a parseable PEM for an RSA JWK
{
	Jwk j;
	j.kty = "RSA";
	j.n = testRsaN;
	j.e = testRsaE;
	auto pem = jwkToPem(j);
	import std.string : indexOf;

	assert(pem.indexOf("BEGIN PUBLIC KEY") >= 0);
}

unittest  // JwksCache.keysFor selects by kid, then refreshes from a new document
{
	auto cache = new JwksCache("", 300.seconds);
	// First load: only kid "rsa-1".
	cache.load(`{"keys":[{"kty":"RSA","kid":"rsa-1","n":"` ~ testRsaN ~ `","e":"AQAB"}]}`);
	assert(cache.keysFor("rsa-1").length == 1);
	assert(cache.keysFor("nope").length == 1); // unknown kid: all keys offered

	// Refresh with a different document; the old kid is gone.
	cache.load(`{"keys":[{"kty":"EC","kid":"ec-9","crv":"P-256","x":"`
			~ testEcX ~ `","y":"` ~ testEcY ~ `"}]}`);
	assert(cache.keysFor("rsa-1").length == 1); // falls back to all keys
	assert(cache.keysFor("ec-9").length == 1);
}

unittest  // audiences() handles both a string and an array aud claim
{
	assert(audiences(parseJsonString(`{"aud":"a"}`)) == ["a"]);
	assert(audiences(parseJsonString(`{"aud":["a","b"]}`)) == ["a", "b"]);
	assert(audiences(parseJsonString(`{}`)).length == 0);
}

unittest  // tokenScopes() reads space-delimited scope and array/string scp
{
	assert(tokenScopes(parseJsonString(`{"scope":"a b c"}`)) == ["a", "b", "c"]);
	assert(tokenScopes(parseJsonString(`{"scp":["a","b"]}`)) == ["a", "b"]);
	assert(tokenScopes(parseJsonString(`{"scp":"a b"}`)) == ["a", "b"]);
}

unittest  // jwtVerifier returns a usable TokenValidator that rejects garbage
{
	JwtVerifierConfig cfg;
	cfg.staticPublicKeysPem = [testEcPubPem];
	TokenValidator v = jwtVerifier(cfg);
	assert(!v("not-a-jwt").valid);
	assert(!v("a.b.c").valid);
}

unittest  // JwksCache refuses to fetch from an insecure (plaintext http) JWKS URI
{
	import core.time : seconds;

	// fetchJwks rejects a plaintext-http, non-loopback URI before any network
	// call, so no keys are ever loaded (the verifier cannot be tricked into
	// fetching signing keys over an insecure transport).
	auto cache = new JwksCache("http://as.example.com/jwks", 60.seconds);
	assert(cache.keysFor("any-kid").length == 0);
}

unittest  // JwksCache refuses an internal/link-local JWKS URI (SSRF mitigation)
{
	import core.time : seconds;

	auto cache = new JwksCache("https://169.254.169.254/jwks", 60.seconds);
	assert(cache.keysFor("any-kid").length == 0);
}
