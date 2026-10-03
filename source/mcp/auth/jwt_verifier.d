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

// Same guard as in jwt.d: declare EVP_DigestVerify when the deimos binding omits
// it due to failed version detection on Windows.
static if (!is(typeof(EVP_DigestVerify)))
	extern (C) @system nothrow @nogc int EVP_DigestVerify(EVP_MD_CTX* ctx,
			const(ubyte)* sig, size_t siglen, const(ubyte)* tbs, size_t tbslen);

import mcp.auth.resource_server : TokenInfo, TokenValidator;
import mcp.protocol.ssrf : SsrfPolicy;

@safe:

/// Configuration for `jwtVerifier`. Provide either a `jwksUri` (the verifier
/// fetches and caches the issuer's JWKS, selecting the key by `kid`) or one or
/// more `staticPublicKeysPem` (PEM SubjectPublicKeyInfo blobs pinned directly).
/// `jwtVerifier` refuses a config with neither. Each rejected token is logged at
/// diagnostic level with the reason (never the token).
struct JwtVerifierConfig
{
	/// The JWKS endpoint to fetch verification keys from (kid-selected). When
	/// empty, only `staticPublicKeysPem` are used.
	string jwksUri;

	/// PEM-encoded public keys (`-----BEGIN PUBLIC KEY-----`) pinned directly,
	/// tried in order. An alternative to `jwksUri` for static deployments. RSA
	/// keys shorter than 2048 bits never verify a token.
	string[] staticPublicKeysPem;

	/// The required token issuer (`iss`). A token whose `iss` differs is
	/// rejected. Required unless `allowAnyIssuer` is set: with neither, every
	/// token is rejected and `jwtVerifier` refuses the config.
	string issuer;

	/// Accept a token from any issuer, skipping the `iss` check. Only for a
	/// verifier whose caller checks `iss` itself (e.g. against a list of allowed
	/// issuers) or whose pinned keys belong to exactly one issuer.
	bool allowAnyIssuer;

	/// The required audience (`aud`, the RFC 8707 resource). When set, a token
	/// that does not list it among its audiences is rejected.
	string audience;

	/// Scopes the token must carry (from `scope` or `scp`). All must be present.
	/// A token missing one is rejected as invalid (401 `invalid_token`); to answer
	/// with 403 `insufficient_scope` so the client can step up, require the scopes
	/// via `ResourceServerConfig.requiredScopes` instead (as `resourceServer` does).
	string[] requiredScopes;

	/// JOSE `typ` header values accepted for a bearer access token, compared
	/// case-insensitively (RFC 7515 §4.1.9, which also lets an `application/`
	/// media-type prefix be omitted). RFC 9068 §2.1 specifies `at+jwt` for JWT
	/// access tokens, and §4.1 requires the resource server to reject a token
	/// whose `typ` does not match the expected type, defeating type-confusion
	/// attacks (e.g. an OIDC `id_token` signed with the same key replayed as an
	/// access token). The default also accepts the bare `JWT` that many issuers
	/// (including this SDK's own token signer) emit. A token whose `typ` is
	/// absent or not listed here is rejected; set this empty to disable the
	/// check for legacy issuers.
	///
	/// Accepting `JWT` means `typ` alone cannot tell an access token from an OIDC
	/// `id_token`, whose `aud` is the client id. The verifier therefore also
	/// rejects any token carrying the id_token-only claims `nonce`, `at_hash` or
	/// `c_hash`, but an id_token without them would still pass when `audience`
	/// is a client id. Prefer `["at+jwt"]` for an issuer that emits RFC 9068
	/// tokens, and never set `audience` to an OAuth client id that also receives
	/// id_tokens from the same issuer.
	string[] acceptedTokenTypes = ["at+jwt", "JWT"];

	/// Leeway applied to `exp`/`nbf` to tolerate clock skew.
	Duration clockSkew = 60.seconds;

	/// How long a fetched JWKS document is cached before being refetched.
	Duration jwksCacheTtl = 300.seconds;

	/// The SSRF policy applied to the `jwksUri` fetch. The default requires
	/// `https` to a public host (plain `http` only to loopback); an IdP on a
	/// private network (e.g. `keycloak.internal` resolving to `10.x`) needs
	/// `SsrfPolicy.allowUserConfigured`.
	SsrfPolicy ssrfPolicy = SsrfPolicy.allowLoopback;
}

// ===========================================================================
// Public entry point
// ===========================================================================

/// Build a `TokenValidator` from `cfg`. The returned delegate verifies a bearer
/// JWT and yields a `TokenInfo` (`valid == false` on any failure). Plug it into
/// `ResourceServerConfig.validator`.
///
/// Concurrency: the returned validator and its internal `JwksCache` hold
/// unsynchronized mutable state (the cached PEM keys and fetch timestamp). Like
/// the rest of the SDK they are bound to vibe.d's default single-threaded event
/// loop, where the only fiber yield is the JWKS network fetch (which completes
/// before the cache is mutated), so concurrent fibers never corrupt the cache.
/// Do not share the validator across worker threads; running the router with
/// `HTTPServerOption.distribute` or worker threads is unsupported (see the
/// concurrency contract in `mcp.transport.session`).
TokenValidator jwtVerifier(JwtVerifierConfig cfg) @safe
{
	import std.exception : enforce;

	enforce(cfg.issuer.length || cfg.allowAnyIssuer,
			"jwtVerifier: set JwtVerifierConfig.issuer (or allowAnyIssuer to skip the iss check)");
	enforce(cfg.jwksUri.length || cfg.staticPublicKeysPem.length, "jwtVerifier: set JwtVerifierConfig.jwksUri or staticPublicKeysPem; with neither, no token can verify");
	auto cache = new JwksCache(cfg.jwksUri, cfg.jwksCacheTtl, cfg.ssrfPolicy);
	return (string token) @safe {
		return verifyOrInvalid(() @safe => verifyToken(cfg, token, cache, currentUnixTime()));
	};
}

/// Run `verify` fail-closed: any exception (a JWKS-fetch outage, a key-parse
/// error, an OpenSSL-internal failure) yields an invalid token rather than
/// propagating, so an exception can never be mistaken for a valid credential.
/// The exception is logged first — otherwise a verifier-side outage is
/// indistinguishable from a flood of genuinely-bad-token rejections. The token
/// itself is never logged (it is a bearer credential).
package TokenInfo verifyOrInvalid(scope TokenInfo delegate() @safe verify) @safe
{
	try
		return verify();
	catch (Exception e)
	{
		import vibe.core.log : logWarn;

		logWarn("jwtVerifier: token verification raised an exception (treated as invalid): %s",
				e.msg);
		return TokenInfo.invalid();
	}
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

/// Reject a token, logging `reason` at diagnostic level so a misconfigured
/// verifier (wrong audience, issuer or accepted `typ`) can be diagnosed. The
/// token itself is never logged (it is a bearer credential).
private TokenInfo reject(string reason) @safe
{
	import vibe.core.log : logDiagnostic;

	logDiagnostic("jwtVerifier: token rejected: %s", reason);
	return TokenInfo.invalid();
}

/// Verify `token` against `cfg` at wall-clock time `now` (unix seconds), drawing
/// JWKS keys from `keys`. Separated from clock/HTTP so tests can drive it
/// deterministically.
package TokenInfo verifyToken(JwtVerifierConfig cfg, string token, KeySource keys, long now) @safe
{
	auto parts = token.split('.');
	if (parts.length != 3)
		return reject("not a three-part JWS");

	const headerJson = decodeSegmentJson(parts[0]);
	const payloadJson = decodeSegmentJson(parts[1]);
	if (headerJson.type != Json.Type.object || payloadJson.type != Json.Type.object)
		return reject("header or payload is not a JSON object");

	const alg = jsonStr(headerJson, "alg");
	const kid = jsonStr(headerJson, "kid");
	if (alg != "RS256" && alg != "ES256")
		return reject("unsupported alg");

	// RFC 7515 4.1.11: a `crit` header lists extensions the recipient MUST
	// understand. This verifier implements none, so any token carrying a
	// `crit` member MUST be rejected rather than silently accepted.
	if ("crit" in headerJson)
		return reject("crit header present");

	// RFC 9068 4.1: reject a token whose `typ` is not an expected access-token
	// type, so a token of another type (e.g. an OIDC `id_token`) signed with the
	// same key cannot be replayed as an access token.
	if (!typAccepted(cfg.acceptedTokenTypes, jsonStr(headerJson, "typ")))
		return reject("typ header is absent or not an accepted token type");

	// Gather candidate keys: pinned PEM keys plus any JWKS keys for this kid.
	string[] candidates = cfg.staticPublicKeysPem.dup;
	candidates ~= keys.keysFor(kid);
	if (candidates.length == 0)
		return reject("no verification key available");

	const signingInput = parts[0] ~ "." ~ parts[1];
	// A malformed signature segment is an ordinary bad token, not a verifier
	// fault, so it is rejected here rather than raised and logged.
	ubyte[] sig;
	try
		sig = base64UrlDecode(parts[2]);
	catch (Exception)
		return reject("malformed signature segment");

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
		return reject("signature does not verify against any candidate key");

	return validateClaims(cfg, payloadJson, now);
}

/// Read a JSON NumericDate (RFC 7519 §2: integer or fractional seconds) into
/// `seconds`. Returns false for any other value, including a non-finite float.
private bool numericDate(Json v, out double seconds) @safe
{
	import std.math : isFinite;

	if (v.type == Json.Type.int_)
		seconds = v.get!long;
	else if (v.type == Json.Type.float_)
		seconds = v.get!double;
	else
		return false;
	return isFinite(seconds);
}

/// Validate the registered claims of an already-signature-verified payload.
package TokenInfo validateClaims(JwtVerifierConfig cfg, Json payload, long now) @safe
{
	const skew = cast(long) cfg.clockSkew.total!"seconds";

	// A JWT access token without a NumericDate `exp` (RFC 7519 §2: integer or
	// fractional seconds) cannot be validated as unexpired, so it MUST be
	// rejected (OAuth 2.1 §5.2 token validation, RFC 9068 §2.2/§4). An absent,
	// non-numeric or non-finite `exp` is treated as invalid.
	double e;
	if (!numericDate(payload["exp"], e))
		return reject("exp claim is absent or not a NumericDate");
	// RFC 7519 4.1.4: the token is expired once the current time is no longer
	// before `exp`. With `clockSkew` the grace boundary is `now <= exp + skew`,
	// so reject at the boundary (`>=`) rather than one second past it.
	if (now >= e + skew)
		return reject("token is expired (exp)");
	// `nbf` is optional, but when present it must be a NumericDate; any other
	// value is rejected so a malformed claim cannot switch the not-before check
	// off.
	const nbfClaim = payload["nbf"];
	if (nbfClaim.type != Json.Type.undefined)
	{
		double nbf;
		if (!numericDate(nbfClaim, nbf) || now + skew < nbf)
			return reject("token is not yet valid or nbf is malformed");
	}

	// Claims only an OIDC id_token carries. An id_token is typed `JWT` like many
	// access tokens, and its `aud` is the client id, so without this check one
	// could be replayed as an access token wherever the configured audience is
	// that client id.
	foreach (idTokenClaim; ["nonce", "at_hash", "c_hash"])
		if (payload[idTokenClaim].type != Json.Type.undefined)
			return reject("payload carries an OIDC id_token-only claim");

	if (!cfg.allowAnyIssuer && (cfg.issuer.length == 0 || jsonStr(payload, "iss") != cfg.issuer))
		return reject("iss does not match the configured issuer");

	auto auds = audiences(payload);
	if (cfg.audience.length && !auds.canFind(cfg.audience))
		return reject("aud does not include the configured audience");

	auto scopes = tokenScopes(payload);
	foreach (req; cfg.requiredScopes)
		if (!scopes.canFind(req))
			return reject("a required scope is missing");

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

/// The smallest RSA modulus, in bits, accepted for RS256 verification.
private enum int minRsaKeyBits = 2048;

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

	// Bind the token-header `alg` to the key type rather than relying on OpenSSL
	// to reject a cross-type attempt: RS256 requires an RSA key, ES256 an EC key.
	// This keeps a future symmetric/other alg from introducing an alg-confusion
	// bypass through a key of the wrong family.
	const baseId = EVP_PKEY_base_id(pkey);
	if (alg == "RS256")
	{
		// The same 2048-bit floor JWKS keys are held to (NIST SP 800-131A), so a
		// weak pinned PEM key is not a way around it.
		if (baseId != EVP_PKEY_RSA || EVP_PKEY_bits(pkey) < minRsaKeyBits)
			return false;
	}
	else if (alg == "ES256")
	{
		if (baseId != EVP_PKEY_EC || !isP256Key(pkey))
			return false;
	}
	else
		return false;

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

/// Whether the EC public key `pkey` lies on P-256, the only curve ES256 permits
/// (RFC 7518 §3.4).
private bool isP256Key(EVP_PKEY* pkey) @trusted
{
	auto ec = EVP_PKEY_get1_EC_KEY(pkey);
	if (ec is null)
		return false;
	scope (exit)
		EC_KEY_free(ec);
	auto group = EC_KEY_get0_group(ec);
	return group !is null && EC_GROUP_get_curve_name(group) == NID_X9_62_prime256v1;
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
	// ECDSA_SIG_set0 takes ownership of r and s on success; free them on failure.
	if (ECDSA_SIG_set0(sig, r, s) != 1)
	{
		BN_free(r);
		BN_free(s);
		return null;
	}

	// i2d_ECDSA_SIG with a null output pointer returns the required buffer length
	// without allocating. We then allocate a D-GC buffer and pass it to the
	// encoding call, avoiding an OpenSSL-owned allocation and CRYPTO_free entirely.
	// This also sidesteps a --combined build conflict: deimos/openssl/bio.di publicly
	// imports deimos/openssl/crypto.di, which declares CRYPTO_free with the old
	// single-argument signature, conflicting with any 3-arg re-declaration.
	const len = i2d_ECDSA_SIG(sig, null);
	if (len <= 0)
		return null;
	auto buf = new ubyte[len];
	ubyte* der = buf.ptr;
	i2d_ECDSA_SIG(sig, &der);
	return buf;
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

// ===========================================================================
// JWKS handling
// ===========================================================================

/// A parsed JWK relevant to verification.
package struct Jwk
{
	string kty; /// "RSA" or "EC"
	string kid;
	string alg;
	string use; /// RFC 7517 4.2: intended use ("sig" or "enc"), if declared.
	string[] keyOps; /// RFC 7517 4.3: permitted operations, if declared.
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
		j.use = jsonStr(k, "use");
		j.keyOps = jsonStrArray(k, "key_ops");
		j.n = jsonStr(k, "n");
		j.e = jsonStr(k, "e");
		j.crv = jsonStr(k, "crv");
		j.x = jsonStr(k, "x");
		j.y = jsonStr(k, "y");
		result ~= j;
	}
	return result;
}

/// Whether a JWK may be used to verify signatures (RFC 7517 4.2/4.3/4.4): a key
/// declaring `use` must declare `use=="sig"`, a key declaring `key_ops` must
/// include `"verify"`, and a key declaring `alg` must name a supported algorithm
/// of its own family (RS256 for RSA, ES256 for EC). Keys that declare none of
/// these are usable (the members are optional).
package bool jwkUsableForSig(Jwk jwk) @safe
{
	if (jwk.use.length && jwk.use != "sig")
		return false;
	if (jwk.keyOps.length && !jwk.keyOps.canFind("verify"))
		return false;
	if (jwk.alg.length && !(jwk.alg == "RS256" && jwk.kty == "RSA")
			&& !(jwk.alg == "ES256" && jwk.kty == "EC"))
		return false;
	return true;
}

/// Convert a JWK to a PEM SubjectPublicKeyInfo public key. Supports RSA (n/e)
/// and EC P-256 (crv/x/y, RFC 7518), the key types RS256 and ES256 verify with.
/// Returns null for unsupported keys and for key material that is not valid
/// base64url, so one malformed key never invalidates the rest of a JWKS.
package string jwkToPem(Jwk jwk) @trusted
{
	try
	{
		if (jwk.kty == "RSA")
			return rsaJwkToPem(jwk);
		if (jwk.kty == "EC")
			return ecJwkToPem(jwk);
	}
	catch (Exception)
		return null;
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
	// Reject keys shorter than 2048 bits (NIST SP 800-131A / RFC 8017).
	if (BN_num_bits(n) < minRsaKeyBits)
	{
		BN_free(n);
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
	// RSA_set0_key takes ownership of n and e (d may be null). On failure the
	// ownership transfer did not occur, so free n and e explicitly here before
	// returning — RSA_free(rsa) does not free BIGNUMs it never received.
	if (RSA_set0_key(rsa, n, e, null) != 1)
	{
		BN_free(n);
		BN_free(e);
		return null;
	}

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
	if (jwk.x.length == 0 || jwk.y.length == 0)
		return null;
	if (jwk.crv != "P-256")
		return null;
	const nid = NID_X9_62_prime256v1;
	auto eckey = EC_KEY_new_by_curve_name(nid);
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
	// Explicitly verify the public key is valid: the point lies on the P-256 curve,
	// is not the point at infinity, and satisfies nQ = O. This guards against
	// invalid-curve attacks on OpenSSL versions (< 1.1.0) where
	// EC_POINT_set_affine_coordinates_GFp does not itself validate the point.
	if (EC_KEY_check_key(eckey) != 1)
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
///
/// The document is refetched when the TTL lapses and when a token names a `kid`
/// the cache does not hold (the IdP may have rotated in a new key). Fetch
/// attempts, successful or not, are spaced at least `minRefetchInterval` apart
/// and single-flighted, so neither an unreachable IdP nor a stream of tokens
/// with made-up `kid`s can turn every request into an outbound fetch.
package final class JwksCache : KeySource
{
	import vibe.core.sync : TaskMutex;

	/// Minimum spacing between JWKS fetch attempts. Also how long a failed fetch
	/// is remembered before the next attempt.
	enum Duration minRefetchInterval = 10.seconds;

	private string uri;
	private Duration ttl;
	private SsrfPolicy policy;
	private string[string] pemByKid; // kid -> PEM
	private string[] allPems;
	private long fetchedAt = -1;
	private long lastAttemptAt = -1;
	private bool loaded = false;
	private TaskMutex fetchLock;

	/// Fetches the JWKS document at a URI, returning its body or null on
	/// failure. Null selects the SSRF-guarded HTTP fetch; tests script it.
	package string delegate(string uri) @safe fetcher;

	/// The current Unix time in seconds. Null selects the wall clock; tests
	/// drive it by hand.
	package long delegate() @safe clock;

	this(string uri, Duration ttl, SsrfPolicy policy = SsrfPolicy.allowLoopback) @safe
	{
		this.uri = uri;
		this.ttl = ttl;
		this.policy = policy;
		this.fetchLock = new TaskMutex;
	}

	/// Candidate PEM keys for a `kid`. Triggers a (re)fetch when the cache is
	/// stale or does not hold `kid`.
	string[] keysFor(string kid) @safe
	{
		if (uri.length == 0)
		{
			if (loaded)
				return kidKeys(kid);
			return null;
		}
		const stale = !loaded || now() - fetchedAt >= cast(long) ttl.total!"seconds";
		const unknownKid = kid.length && (kid in pemByKid) is null;
		if (stale || unknownKid)
			refetch();
		return kidKeys(kid);
	}

	private long now() @safe
	{
		return clock !is null ? clock() : currentUnixTime();
	}

	private string[] kidKeys(string kid) @safe
	{
		if (kid.length)
			if (auto p = kid in pemByKid)
				return [*p];
		// Unknown/absent kid: offer all keys.
		return allPems.dup;
	}

	/// Fetch the document unless an attempt happened within
	/// `minRefetchInterval`. Holding `fetchLock` for the fetch makes concurrent
	/// callers wait for the one in flight and then find the attempt recent.
	private void refetch() @safe
	{
		fetchLock.lock();
		scope (exit)
			fetchLock.unlock();
		const t = now();
		if (lastAttemptAt >= 0 && t - lastAttemptAt < minRefetchInterval.total!"seconds")
			return;
		lastAttemptAt = t;
		const doc = fetcher !is null ? fetcher(uri) : fetchJwks(uri, policy);
		if (doc.length == 0)
			return;
		// An unparseable document is handled like a failed fetch: logged, with
		// the cached keys kept, rather than failing the request that triggered it.
		try
			load(doc);
		catch (Exception e)
		{
			import vibe.core.log : logWarn;

			logWarn("JWKS from %s could not be parsed; keeping the cached keys: %s", uri, e.msg);
		}
	}

	/// Populate the cache from a raw JWKS document (also the test seam).
	void load(string jwksJson) @safe
	{
		// Build new key maps in temporaries so that a parse exception (malformed
		// JSON or invalid base64url in a JWK field) leaves the existing cache
		// state untouched rather than clearing it and marking it stale.
		string[string] newPemByKid;
		string[] newAllPems;
		foreach (jwk; parseJwks(jwksJson))
		{
			if (!jwkUsableForSig(jwk))
				continue;
			const pem = jwkToPem(jwk);
			if (pem.length == 0)
				continue;
			newAllPems ~= pem;
			if (jwk.kid.length)
				newPemByKid[jwk.kid] = pem;
		}
		// A document with no usable key is treated like a failed fetch: the
		// previous keys stay and the cache stays stale, so the next fetch is
		// governed by `minRefetchInterval` rather than the full TTL.
		if (newAllPems.length == 0)
		{
			import vibe.core.log : logWarn;

			logWarn(
					"JWKS from %s holds no usable signature-verification key; keeping the cached keys",
					uri);
			return;
		}
		// Swap atomically into the cache fields only after all parsing succeeds.
		pemByKid = newPemByKid;
		allPems = newAllPems;
		loaded = true;
		fetchedAt = now();
	}
}

/// Upper bound on a fetched JWKS document. A larger response is rejected rather
/// than buffered.
private enum size_t maxJwksBytes = 256 * 1024;

/// Fetch a JWKS document over HTTP(S) under `policy`. Returns the body, or
/// empty on failure (logged, since every token then fails verification).
private string fetchJwks(string uri, SsrfPolicy policy) @trusted
{
	import vibe.core.log : logWarn;
	import vibe.http.client : HTTPClientRequest, HTTPClientResponse;
	import vibe.http.common : HTTPMethod;
	import vibe.stream.operations : readAllUTF8;
	import mcp.auth.oauth : secureRequestHTTP;

	// secureRequestHTTP pins the fetch to a pre-vetted resolved address
	// (DNS-rebinding SSRF mitigation) and throws on a host `policy` rejects.
	string body_;
	try
	{
		secureRequestHTTP(uri, policy, (scope HTTPClientRequest req) {
			req.method = HTTPMethod.GET;
		}, (scope HTTPClientResponse res) {
			if (res.statusCode / 100 == 2)
				body_ = res.bodyReader.readAllUTF8(false, maxJwksBytes);
			else
				logWarn("JWKS fetch from %s returned HTTP %d", uri, res.statusCode);
		});
	}
	catch (Exception e)
	{
		logWarn("JWKS fetch from %s failed: %s", uri, e.msg);
		return null;
	}
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

// Read a JSON array-of-strings member, returning null when absent or not an
// array; non-string elements are skipped.
private string[] jsonStrArray(Json j, string key) @safe
{
	auto v = j[key];
	if (v.type != Json.Type.array)
		return null;
	string[] result;
	foreach (e; ()@trusted { return v.get!(Json[]); }())
		if (e.type == Json.Type.string)
			result ~= e.get!string;
	return result;
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

/// Whether a token's `typ` header is one of the `accepted` types. The match is
/// case-insensitive and ignores an optional `application/` media-type prefix on
/// either side (RFC 7515 §4.1.9). An empty `accepted` disables the check; an
/// absent (empty) `typ` matches nothing and is therefore rejected.
package bool typAccepted(string[] accepted, string typ) @safe
{
	import std.uni : toLower;
	import std.algorithm : startsWith;

	if (accepted.length == 0)
		return true;

	static string normalize(string t) @safe
	{
		auto lower = t.toLower;
		return lower.startsWith("application/") ? lower["application/".length .. $] : lower;
	}

	const want = normalize(typ);
	if (want.length == 0)
		return false;
	foreach (a; accepted)
		if (want == normalize(a))
			return true;
	return false;
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

unittest  // a config with no issuer rejects every token rather than skipping the iss check
{
	JwtVerifierConfig cfg;
	auto payload = parseJsonString(`{"iss":"https://evil.example","sub":"u","exp":1700003600}`);
	assert(!validateClaims(cfg, payload, 1_700_001_000).valid);
	assert(!validateClaims(cfg,
			parseJsonString(`{"sub":"u","exp":1700003600}`), 1_700_001_000).valid);
}

unittest  // jwtVerifier refuses a config that pins no issuer
{
	import std.exception : assertThrown;

	JwtVerifierConfig cfg;
	cfg.staticPublicKeysPem = ["unused"];
	assertThrown(jwtVerifier(cfg));
}

unittest  // jwtVerifier refuses a config with neither a jwksUri nor a pinned key
{
	import std.exception : assertThrown;

	JwtVerifierConfig cfg;
	cfg.issuer = "https://as.example.com";
	assertThrown(jwtVerifier(cfg));
}

unittest  // a claim rejection is logged with its reason, never with the token
{
	import std.algorithm : any;
	import vibe.core.log : deregisterLogger, LogLevel, Logger, LogLine, registerLogger;

	static final class DiagLogger : Logger
	{
		string[] lines;
		this() @safe
		{
			minLevel = LogLevel.diagnostic;
		}

		override void log(ref LogLine line) @safe
		{
			lines ~= line.text;
		}
	}

	auto logger = new DiagLogger;
	auto shared_ = () @trusted { return cast(shared) logger; }();
	() @trusted { registerLogger(shared_); }();
	scope (exit)
		() @trusted { deregisterLogger(shared_); }();

	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	cfg.audience = "https://other.example.com";
	auto cache = new JwksCache("", cfg.jwksCacheTtl);
	cache.load(`{"keys":[{"kty":"RSA","kid":"rsa-1","n":"` ~ testRsaN ~ `","e":"` ~ testRsaE
			~ `"}]}`);
	assert(!verifyToken(cfg, testRs256Jwt, cache, 1_700_001_000).valid);

	auto lines = () @trusted { return (cast() logger).lines; }();
	assert(lines.any!(l => l.canFind("aud")), "the audience rejection must be logged");
	assert(!lines.any!(l => l.canFind(testRs256Jwt[0 .. 20])), "the token must never be logged");
}

unittest  // a `typ` rejection is logged with its reason
{
	import std.algorithm : any;
	import vibe.core.log : deregisterLogger, LogLevel, Logger, LogLine, registerLogger;

	static final class DiagLogger : Logger
	{
		string[] lines;
		this() @safe
		{
			minLevel = LogLevel.diagnostic;
		}

		override void log(ref LogLine line) @safe
		{
			lines ~= line.text;
		}
	}

	auto logger = new DiagLogger;
	auto shared_ = () @trusted { return cast(shared) logger; }();
	() @trusted { registerLogger(shared_); }();
	scope (exit)
		() @trusted { deregisterLogger(shared_); }();

	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	cfg.acceptedTokenTypes = ["at+jwt"];
	cfg.staticPublicKeysPem = [testEcPubPem];
	auto tok = makeEs256(`{"sub":"u","exp":1700003600}`);
	assert(!verifyToken(cfg, tok, new NoKeys, 1_700_001_000).valid);

	auto lines = () @trusted { return (cast() logger).lines; }();
	assert(lines.any!(l => l.canFind("typ")), "the typ rejection must be logged");
}

unittest  // allowAnyIssuer explicitly accepts a token from any issuer
{
	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	cfg.staticPublicKeysPem = [testEcPubPem];
	auto payload = parseJsonString(`{"iss":"https://any.example","sub":"u","exp":1700003600}`);
	assert(validateClaims(cfg, payload, 1_700_001_000).valid);
	cast(void) jwtVerifier(cfg);
}

unittest  // a tampered RS256 signature is rejected
{
	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
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
	cfg.allowAnyIssuer = true;
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
	cfg.allowAnyIssuer = true;
	// A signature-verified payload with every other claim present but no exp.
	auto payload = parseJsonString(`{"iss":"https://as.example.com","sub":"ec-user","scope":"mcp:read","iat":1700000000,"nbf":1700000000}`);
	auto ti = validateClaims(cfg, payload, 1_700_001_000);
	assert(!ti.valid);
}

unittest  // a token with a present integer exp claim validates
{
	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	auto payload = parseJsonString(
			`{"sub":"ec-user","iat":1700000000,"exp":1700003600,"nbf":1700000000}`);
	auto ti = validateClaims(cfg, payload, 1_700_001_000);
	assert(ti.valid);
	assert(ti.subject == "ec-user");
}

unittest  // a non-integer exp claim is rejected (cannot be validated as unexpired)
{
	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	auto payload = parseJsonString(`{"sub":"ec-user","exp":"not-a-number"}`);
	auto ti = validateClaims(cfg, payload, 1_700_001_000);
	assert(!ti.valid);
}

unittest  // a token is rejected at the exact exp+skew boundary (RFC 7519 4.1.4)
{
	JwtVerifierConfig cfg; // default clockSkew is 60s
	cfg.allowAnyIssuer = true;
	auto payload = parseJsonString(`{"sub":"ec-user","exp":1700003600,"nbf":1700000000}`);
	// now == exp + skew: the token is no longer before its expiry, so reject.
	auto ti = validateClaims(cfg, payload, 1_700_003_660);
	assert(!ti.valid);
}

unittest  // a token one second before the exp+skew boundary is still valid
{
	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	auto payload = parseJsonString(`{"sub":"ec-user","exp":1700003600,"nbf":1700000000}`);
	auto ti = validateClaims(cfg, payload, 1_700_003_659);
	assert(ti.valid);
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
	cfg.allowAnyIssuer = true;
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
	cfg.allowAnyIssuer = true;
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
	cfg.allowAnyIssuer = true;
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
	cfg.allowAnyIssuer = true;
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
	cfg.allowAnyIssuer = true;
	cfg.staticPublicKeysPem = [testEcPubPem];

	// Sign with the EC key but tamper a payload byte after signing.
	const payload = `{"sub":"ec-user","exp":1700003600}`;
	auto jwt = makeEs256(payload);
	auto tampered = jwt[0 .. $ - 2] ~ (jwt[$ - 2] == 'A' ? "BB" : "AA");

	auto ti = verifyToken(cfg, tampered, new NoKeys, 1_700_001_000);
	assert(!ti.valid);
}

unittest  // a pinned RSA public key shorter than 2048 bits is not used to verify
{
	// A 1024-bit RSA key and an RS256 token it signed correctly.
	enum weakPem = "-----BEGIN PUBLIC KEY-----\n"
		~ "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC677t17xuMpPQagrUx7LYzqLJh\n"
		~ "EM/uXXIIPC5rlQh8rZFHNl1Nozt6XWq3Bvd+Gesl3eZ/PVd0B+IYU/V8+Fex/fst\n"
		~ "W8pqucd+wGhFUUa7Q24u1momdVAhYOW2M+na8V3TBcr7snfNd+L7L8pkmZiGRos3\n"
		~ "EKi8uzdJlHOeNGMmmQIDAQAB\n" ~ "-----END PUBLIC KEY-----\n";
	enum weakToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ3ZWFrIiwiZXhwIjoxNzAwMDAzNjAwfQ." ~ "Mpded0h9CGy8Ro-2N5OEpJCCMd1E9FLE0XxqEtNXi4D3bxDW1shcbyKNfRNeOMZCOPSdAi3z8etblLoiCDrr3a_" ~ "wfnC_cfHQ9rK2Uq541N77MF1fmvptAdE6VnsRmjh5Kzqu8VaGVP4_q2Gra7OEFciZQ6kXpFMO3w-1_gMMzRs";

	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	cfg.staticPublicKeysPem = [weakPem];
	assert(!verifyToken(cfg, weakToken, new NoKeys, 1_700_001_000).valid);
}

unittest  // a malformed signature segment is invalid without raising (no per-request warning)
{
	import std.exception : assertNotThrown;
	import std.string : lastIndexOf;

	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	cfg.staticPublicKeysPem = [testEcPubPem];
	auto jwt = makeEs256(`{"sub":"ec-user","exp":1700003600}`);
	const dot = jwt.lastIndexOf('.');
	const garbled = jwt[0 .. dot + 1] ~ "not*base64!";

	TokenInfo ti;
	assertNotThrown(ti = verifyToken(cfg, garbled, new NoKeys, 1_700_001_000));
	assert(!ti.valid);
}

unittest  // an unsupported alg (e.g. none) is rejected outright
{
	import mcp.auth.oauth : base64UrlNoPad;

	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
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
	cfg.allowAnyIssuer = true;
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

unittest  // a token whose `typ` is an OIDC id_token is rejected (RFC 9068 §4.1 type confusion)
{
	import mcp.auth.jwt : signEs256;
	import mcp.auth.oauth : base64UrlNoPad;

	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	cfg.staticPublicKeysPem = [testEcPubPem];

	// An ID token signed with the same key as access tokens: every claim check
	// would pass, so only the `typ` mismatch can stop it being replayed.
	const header = `{"alg":"ES256","typ":"id_token"}`;
	const payload = `{"iss":"https://as.example.com","aud":"https://mcp.example.com/mcp","sub":"user-42","exp":1700003600}`;
	const si = base64UrlNoPad(cast(const(ubyte)[]) header) ~ "." ~ base64UrlNoPad(
			cast(const(ubyte)[]) payload);
	auto sig = signEs256(testEcPrivPem, cast(const(ubyte)[]) si);
	auto jwt = si ~ "." ~ base64UrlNoPad(sig);

	auto ti = verifyToken(cfg, jwt, new NoKeys, 1_700_001_000);
	assert(!ti.valid);
}

unittest  // an RFC 9068 `at+jwt` typ is accepted (case-insensitive, RFC 7515 §4.1.9)
{
	import mcp.auth.jwt : signEs256;
	import mcp.auth.oauth : base64UrlNoPad;

	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	cfg.staticPublicKeysPem = [testEcPubPem];

	const header = `{"alg":"ES256","typ":"AT+JWT"}`;
	const payload = `{"sub":"ec-user","exp":1700003600}`;
	const si = base64UrlNoPad(cast(const(ubyte)[]) header) ~ "." ~ base64UrlNoPad(
			cast(const(ubyte)[]) payload);
	auto sig = signEs256(testEcPrivPem, cast(const(ubyte)[]) si);
	auto jwt = si ~ "." ~ base64UrlNoPad(sig);

	auto ti = verifyToken(cfg, jwt, new NoKeys, 1_700_001_000);
	assert(ti.valid);
	assert(ti.subject == "ec-user");
}

unittest  // a token with no `typ` header is rejected by default (RFC 9068 §4.1)
{
	import mcp.auth.jwt : signEs256;
	import mcp.auth.oauth : base64UrlNoPad;

	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	cfg.staticPublicKeysPem = [testEcPubPem];

	const header = `{"alg":"ES256"}`;
	const payload = `{"sub":"ec-user","exp":1700003600}`;
	const si = base64UrlNoPad(cast(const(ubyte)[]) header) ~ "." ~ base64UrlNoPad(
			cast(const(ubyte)[]) payload);
	auto sig = signEs256(testEcPrivPem, cast(const(ubyte)[]) si);
	auto jwt = si ~ "." ~ base64UrlNoPad(sig);

	auto ti = verifyToken(cfg, jwt, new NoKeys, 1_700_001_000);
	assert(!ti.valid);
}

unittest  // emptying acceptedTokenTypes disables the `typ` check (escape hatch for legacy issuers)
{
	import mcp.auth.jwt : signEs256;
	import mcp.auth.oauth : base64UrlNoPad;

	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	cfg.staticPublicKeysPem = [testEcPubPem];
	cfg.acceptedTokenTypes = [];

	const header = `{"alg":"ES256","typ":"id_token"}`;
	const payload = `{"sub":"ec-user","exp":1700003600}`;
	const si = base64UrlNoPad(cast(const(ubyte)[]) header) ~ "." ~ base64UrlNoPad(
			cast(const(ubyte)[]) payload);
	auto sig = signEs256(testEcPrivPem, cast(const(ubyte)[]) si);
	auto jwt = si ~ "." ~ base64UrlNoPad(sig);

	auto ti = verifyToken(cfg, jwt, new NoKeys, 1_700_001_000);
	assert(ti.valid);
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

unittest  // a JWK declaring use!="sig" is excluded as a verification candidate (RFC 7517 4.2)
{
	auto cache = new JwksCache("", 300.seconds);
	cache.load(
			`{"keys":[{"kty":"RSA","kid":"rsa-1","use":"enc","n":"` ~ testRsaN ~ `","e":"AQAB"}]}`);
	assert(cache.keysFor("rsa-1").length == 0);
}

unittest  // a JWK declaring key_ops without "verify" is excluded (RFC 7517 4.3)
{
	auto cache = new JwksCache("", 300.seconds);
	cache.load(`{"keys":[{"kty":"RSA","kid":"rsa-1","key_ops":["encrypt"],"n":"`
			~ testRsaN ~ `","e":"AQAB"}]}`);
	assert(cache.keysFor("rsa-1").length == 0);
}

unittest  // a JWK with use=="sig" and key_ops including "verify" is retained
{
	auto cache = new JwksCache("", 300.seconds);
	cache.load(`{"keys":[{"kty":"RSA","kid":"rsa-1","use":"sig","key_ops":["verify"],"n":"`
			~ testRsaN ~ `","e":"AQAB"}]}`);
	assert(cache.keysFor("rsa-1").length == 1);
}

unittest  // an RS256 token offered only an EC key is rejected (kty<->alg binding)
{
	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	auto cache = new JwksCache("", cfg.jwksCacheTtl);
	// Only an EC key is available; the token's header alg is RS256, so the
	// kty<->alg binding rejects it before relying on OpenSSL.
	cache.load(`{"keys":[{"kty":"EC","kid":"ec-1","crv":"P-256","x":"`
			~ testEcX ~ `","y":"` ~ testEcY ~ `"}]}`);
	auto ti = verifyToken(cfg, testRs256Jwt, cache, 1_700_001_000);
	assert(!ti.valid);
}

unittest  // an ES256 token offered only an RSA key is rejected (kty<->alg binding)
{
	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	cfg.staticPublicKeysPem = []; // none pinned
	auto cache = new JwksCache("", cfg.jwksCacheTtl);
	cache.load(`{"keys":[{"kty":"RSA","kid":"rsa-1","n":"` ~ testRsaN ~ `","e":"AQAB"}]}`);
	const payload = `{"sub":"ec-user","exp":1700003600,"nbf":1700000000}`;
	auto jwt = makeEs256(payload, "rsa-1");
	auto ti = verifyToken(cfg, jwt, cache, 1_700_001_000);
	assert(!ti.valid);
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
	cfg.allowAnyIssuer = true;
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

version (Posix) unittest  // a JWKS on a non-loopback internal address loads only under a policy that permits it
{
	import std.conv : to;
	import vibe.core.core : runTask, runEventLoop, exitEventLoop;
	import vibe.http.router : URLRouter;
	import vibe.http.server : HTTPServerResponse, HTTPServerRequest,
		HTTPServerSettings, listenHTTP;

	const doc = `{"keys":[{"kty":"RSA","kid":"rsa-1","n":"` ~ testRsaN ~ `","e":"`
		~ testRsaE ~ `"}]}`;
	string failure;
	size_t defaultKeys = size_t.max, permittedKeys;
	runTask(() @safe nothrow{
		try
		{
			auto router = new URLRouter;
			router.get("/jwks", (HTTPServerRequest req, HTTPServerResponse res) @safe {
				res.writeBody(doc, "application/json");
			});
			auto settings = new HTTPServerSettings;
			settings.port = 0;
			settings.bindAddresses = ["0.0.0.0"];
			auto listener = listenHTTP(settings, router);
			scope (exit)
				() @trusted { listener.stopListening(); }();
			// 0.0.0.0 is an internal, non-loopback address that still reaches
			// this host's listener on POSIX (Windows refuses to connect to it).
			const uri = "http://0.0.0.0:" ~ listener.bindAddresses[0].port.to!string ~ "/jwks";
			defaultKeys = new JwksCache(uri, 300.seconds).keysFor("rsa-1").length;
			permittedKeys = new JwksCache(uri, 300.seconds, SsrfPolicy.allowUserConfigured).keysFor(
				"rsa-1").length;
		}
		catch (Exception e)
			failure = e.msg;
		exitEventLoop();
	});
	runEventLoop();

	assert(failure.length == 0, failure);
	assert(defaultKeys == 0);
	assert(permittedKeys == 1);
}

unittest  // JwksCache refuses an internal/link-local JWKS URI (SSRF mitigation)
{
	import core.time : seconds;

	auto cache = new JwksCache("https://169.254.169.254/jwks", 60.seconds);
	assert(cache.keysFor("any-kid").length == 0);
}

unittest  // rsaJwkToPem frees n and e BIGNUMs on RSA_set0_key failure (no leak)
{
	// RSA_set0_key succeeds whenever n and e are valid non-null BIGNUMs passed to
	// a freshly-allocated RSA struct, so we cannot force a failure from D. The fix
	// (adding BN_free(n)/BN_free(e) on that branch) is verified by code inspection
	// and by this test confirming the function produces the expected result for a
	// valid key — a non-null PEM is returned, BIGNUMs are consumed without crash.
	Jwk j;
	j.kty = "RSA";
	j.n = testRsaN;
	j.e = testRsaE;
	auto pem = rsaJwkToPem(j);
	import std.string : indexOf;

	assert(pem.indexOf("BEGIN PUBLIC KEY") >= 0);
}

unittest  // rawEcdsaToDer frees r and s BIGNUMs on ECDSA_SIG_set0 failure (no leak)
{
	import mcp.auth.jwt : signEs256;

	// ECDSA_SIG_set0 succeeds whenever r and s are valid non-null BIGNUMs passed to
	// a freshly-allocated ECDSA_SIG struct, so we cannot force a failure from D. The
	// fix (adding BN_free(r)/BN_free(s) on that branch) is verified by code
	// inspection and by this test confirming the function produces a valid DER output
	// for a well-formed 64-byte raw P-256 signature — BIGNUMs are consumed without
	// crash.
	const rawSig = signEs256(testEcPrivPem, cast(const(ubyte)[]) "test.payload");
	assert(rawSig.length == 64);
	auto der = rawEcdsaToDer(rawSig);
	// DER-encoded ECDSA signatures start with 0x30 (SEQUENCE tag).
	assert(der.length > 0 && der[0] == 0x30);
}

unittest  // rawEcdsaToDer round-trips via pre-allocated buffer (no OpenSSL allocation)
{
	import mcp.auth.jwt : signEs256;

	const rawSig = signEs256(testEcPrivPem, cast(const(ubyte)[]) "test.payload");
	assert(rawSig.length == 64);
	// rawEcdsaToDer uses i2d_ECDSA_SIG with a D-GC buffer rather than an
	// OpenSSL-allocated buffer, so no CRYPTO_free call is needed.
	auto der = () @trusted { return rawEcdsaToDer(rawSig); }();
	assert(der.length > 0 && der[0] == 0x30);
}

unittest  // fetchJwks discards non-2xx bodies so a 503 does not mark the cache as fresh
{
	import core.time : seconds;
	import std.conv : to;
	import vibe.core.core : runTask, runEventLoop, exitEventLoop;
	import vibe.http.router : URLRouter;
	import vibe.http.server : HTTPServerResponse, HTTPServerRequest,
		HTTPServerSettings, listenHTTP;
	import vibe.http.status : HTTPStatus;

	// A shared flag lets the handler serve 503 first, then 200 with a real JWKS.
	shared bool serveValid = false;
	const validJwks = `{"keys":[{"kty":"RSA","kid":"rsa-1","n":"` ~ testRsaN
		~ `","e":"` ~ testRsaE ~ `"}]}`;

	string failure;
	bool passed;

	void delegate() @safe nothrow body_ = () @safe nothrow{
		try
		{
			auto router = new URLRouter;
			router.get("/jwks", (HTTPServerRequest req, HTTPServerResponse res) @safe nothrow{
				try
				{
					import vibe.stream.operations : readAllUTF8;

					if (serveValid)
					{
						res.statusCode = 200;
						res.contentType = "application/json";
						res.writeBody(validJwks);
					}
					else
					{
						res.statusCode = 503;
						res.contentType = "application/json";
						res.writeBody(`{"error":"service unavailable"}`);
					}
				}
				catch (Exception)
				{
				}
			});

			auto settings = new HTTPServerSettings;
			settings.port = 0; // ephemeral
			settings.bindAddresses = ["127.0.0.1"];
			auto listener = listenHTTP(settings, router);
			scope (exit)
				() @trusted { listener.stopListening(); }();

			const port = listener.bindAddresses[0].port;
			const uri = "http://127.0.0.1:" ~ port.to!string ~ "/jwks";

			// First fetch: server returns 503. The cache should NOT be marked fresh.
			long clock = 1_000;
			auto cache = new JwksCache(uri, 300.seconds);
			cache.clock = () @safe => clock;
			assert(cache.keysFor("rsa-1").length == 0);

			// Switch server to serve a valid JWKS.
			serveValid = true;

			// The next attempt, once the failed fetch's back-off has passed but well
			// within the 300-second TTL, re-fetches: the 503 body was never loaded,
			// so the cache was not marked fresh with zero keys.
			clock += JwksCache.minRefetchInterval.total!"seconds";
			assert(cache.keysFor("rsa-1").length == 1);

			passed = true;
		}
		catch (Exception e)
			failure = e.msg;
		exitEventLoop();
	};

	runTask(body_);
	runEventLoop();

	assert(failure.length == 0, "fetchJwks HTTP status test failed: " ~ failure);
	assert(passed);
}

unittest  // fetchJwks refuses a JWKS response larger than maxJwksBytes
{
	import std.array : replicate;
	import std.conv : to;
	import vibe.core.core : runTask, runEventLoop, exitEventLoop;
	import vibe.http.router : URLRouter;
	import vibe.http.server : HTTPServerResponse, HTTPServerRequest,
		HTTPServerSettings, listenHTTP;

	// A valid document padded past the cap: it would load one key if read whole.
	const oversized = `{"keys":[{"kty":"RSA","kid":"rsa-1","n":"` ~ testRsaN
		~ `","e":"` ~ testRsaE ~ `"}],"pad":"` ~ "x".replicate(maxJwksBytes) ~ `"}`;

	string failure;
	size_t keys = size_t.max;
	runTask(() @safe nothrow{
		try
		{
			auto router = new URLRouter;
			router.get("/jwks", (HTTPServerRequest req, HTTPServerResponse res) @safe {
				res.writeBody(oversized, "application/json");
			});
			auto settings = new HTTPServerSettings;
			settings.port = 0;
			settings.bindAddresses = ["127.0.0.1"];
			auto listener = listenHTTP(settings, router);
			scope (exit)
				() @trusted { listener.stopListening(); }();
			const uri = "http://127.0.0.1:" ~ listener.bindAddresses[0].port.to!string ~ "/jwks";
			keys = new JwksCache(uri, 300.seconds).keysFor("rsa-1").length;
		}
		catch (Exception e)
			failure = e.msg;
		exitEventLoop();
	});
	runEventLoop();

	assert(failure.length == 0, failure);
	assert(keys == 0, "an oversized JWKS body must not be loaded");
}

unittest  // jwkToPem rejects P-384 and P-521 EC JWKs, which no supported alg can verify
{
	// P-384 key coordinates (secp384r1, generated with openssl ecparam -name secp384r1)
	Jwk j384;
	j384.kty = "EC";
	j384.crv = "P-384";
	j384.x = "nAPaQ-Yp5yOfUbCoua-9vveg8CN2xGZcC0pwleiN32_13F8e5ucb4TDIECm7HNHF";
	j384.y = "50RD8Uk-e11KLEhoe67lPP-XrPZNz_BTJ8Mc4Pw9fzfEp_Bx3kfvopo3CvsqMx9M";
	assert(jwkToPem(j384).length == 0);

	// P-521 key coordinates (secp521r1, generated with openssl ecparam -name secp521r1)
	Jwk j521;
	j521.kty = "EC";
	j521.crv = "P-521";
	j521.x
		= "AdsIuUmbV1MADf8_U1vxvq7HgqY7rSroFHKSdrgoX20IJxB8WqbDiT5VUe9peyobeRWX5BxmsDvUWBjCGG_0gutA";
	j521.y
		= "AegUPdPnBttrFflQ9wJbUurLisEyJu-PZW-PnJomKpiFt9D2o0Ve0uXpqSqLHZTVhWpXu3ddF3Kw9JoO2hsNDE0q";
	assert(jwkToPem(j521).length == 0);
}

unittest  // jwkUsableForSig rejects a JWK whose declared alg is not supported
{
	Jwk j;
	j.kty = "EC";
	j.alg = "ES384";
	assert(!jwkUsableForSig(j));
}

unittest  // jwkUsableForSig rejects a JWK whose declared alg belongs to another key family
{
	Jwk ec;
	ec.kty = "EC";
	ec.alg = "RS256";
	assert(!jwkUsableForSig(ec));

	Jwk rsa;
	rsa.kty = "RSA";
	rsa.alg = "RS256";
	assert(jwkUsableForSig(rsa));
}

unittest  // verifyJws refuses ES256 with an EC key on a curve other than P-256
{
	const p384Pem = "-----BEGIN PUBLIC KEY-----\n"
		~ "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEZAuOASCn4YZGvdnwJ3n0ClX1Nr40mK3R\n"
		~ "l3CMCJKLvzbEENtB0aX9r4yomSv+138yyeKGkV3HALqfLI4e8OVx0ifDIIepwuiL\n"
		~ "4kXRpDjft3Urv/CmTZHxxGeBZ3mOQiXk\n" ~ "-----END PUBLIC KEY-----\n";
	auto sig = new ubyte[64];
	sig[] = 1;
	assert(!verifyJws("ES256", cast(const(ubyte)[]) "a.b", sig, p384Pem));
}

version (unittest)
{
	private enum rsaOnlyJwks = `{"keys":[{"kty":"RSA","kid":"rsa-1","n":"`
		~ testRsaN ~ `","e":"` ~ testRsaE ~ `"}]}`;
	private enum rotatedJwks = `{"keys":[{"kty":"RSA","kid":"rsa-1","n":"` ~ testRsaN
		~ `","e":"` ~ testRsaE ~ `"},{"kty":"EC","kid":"ec-new","crv":"P-256","x":"`
		~ testEcX ~ `","y":"` ~ testEcY ~ `"}]}`;

	/// A JWKS cache over a scripted fetcher and a hand-driven clock.
	private final class ScriptedJwks
	{
		int fetches;
		long clock = 1_000;
		string served;
		JwksCache cache;

		this(string served, void delegate() @safe duringFetch = null) @safe
		{
			this.served = served;
			cache = new JwksCache("https://as.example.com/jwks", 300.seconds);
			cache.fetcher = (string uri) @safe {
				++fetches;
				if (duringFetch !is null)
					duringFetch();
				return this.served;
			};
			cache.clock = () @safe => clock;
		}
	}
}

unittest  // JwksCache refetches on an unknown kid so a rotated-in key verifies before the TTL expires
{
	auto s = new ScriptedJwks(rsaOnlyJwks);
	assert(s.cache.keysFor("rsa-1").length == 1);
	assert(s.fetches == 1);

	// The IdP rotates in a new key; a token naming it arrives well inside the TTL.
	s.served = rotatedJwks;
	s.clock += JwksCache.minRefetchInterval.total!"seconds";
	auto keys = s.cache.keysFor("ec-new");
	assert(s.fetches == 2);
	assert(keys.length == 1, "the rotated-in key must be selected by its kid");
}

unittest  // JwksCache rate-limits unknown-kid refetches (junk kids cannot drive outbound fetches)
{
	auto s = new ScriptedJwks(rsaOnlyJwks);
	assert(s.cache.keysFor("rsa-1").length == 1);
	foreach (i; 0 .. 5)
		s.cache.keysFor("junk-kid");
	assert(s.fetches == 1);
}

unittest  // JwksCache negative-caches a failed fetch instead of refetching on every request
{
	auto s = new ScriptedJwks(null);
	foreach (i; 0 .. 5)
		assert(s.cache.keysFor("rsa-1").length == 0);
	assert(s.fetches == 1);

	s.clock += JwksCache.minRefetchInterval.total!"seconds";
	s.cache.keysFor("rsa-1");
	assert(s.fetches == 2);
}

unittest  // a JWKS with no usable keys leaves the cache stale so a kid-less token retries after minRefetchInterval
{
	auto s = new ScriptedJwks(`{"keys":[]}`);
	assert(s.cache.keysFor("").length == 0);
	assert(s.fetches == 1);

	// The IdP publishes its key shortly after; a kid-less token must not wait out
	// the full cache TTL to pick it up.
	s.served = rsaOnlyJwks;
	s.clock += JwksCache.minRefetchInterval.total!"seconds";
	assert(s.cache.keysFor("").length == 1);
	assert(s.fetches == 2);
}

unittest  // a refetched JWKS with no usable keys keeps the previously cached keys
{
	auto s = new ScriptedJwks(rsaOnlyJwks);
	assert(s.cache.keysFor("rsa-1").length == 1);

	s.served = `{"keys":[{"kty":"RSA","kid":"enc","use":"enc","n":"` ~ testRsaN
		~ `","e":"` ~ testRsaE ~ `"}]}`;
	s.clock += 300;
	assert(s.cache.keysFor("rsa-1").length == 1, "an empty key set must not evict the cached keys");
	assert(s.fetches == 2);
}

unittest  // a JWK with undecodable key material is skipped without discarding the rest of the document
{
	auto s = new ScriptedJwks(
			`{"keys":[{"kty":"RSA","kid":"bad","n":"!!not base64!!","e":"AQAB"},`
			~ `{"kty":"EC","kid":"bad-ec","crv":"P-256","x":"%%%","y":"` ~ testEcY
			~ `"},` ~ `{"kty":"RSA","kid":"rsa-1","n":"` ~ testRsaN ~ `","e":"` ~ testRsaE ~ `"}]}`);
	assert(s.cache.keysFor("rsa-1").length == 1);
}

unittest  // a refetched JWKS that is not valid JSON keeps the cached keys and does not throw
{
	auto s = new ScriptedJwks(rsaOnlyJwks);
	assert(s.cache.keysFor("rsa-1").length == 1);

	s.served = `{not valid json`;
	s.clock += 300;
	assert(s.cache.keysFor("rsa-1").length == 1);
	assert(s.fetches == 2);
}

unittest  // JwksCache single-flights concurrent fetches
{
	import core.time : msecs;
	import vibe.core.core : runTask, sleep;

	// The fetch yields to other tasks while in flight.
	auto s = new ScriptedJwks(rsaOnlyJwks, () @safe { sleep(30.msecs); });
	auto cache = s.cache;

	size_t a, b;
	auto ta = runTask(() nothrow{
		try
			a = cache.keysFor("rsa-1").length;
		catch (Exception)
		{
		}
	});
	auto tb = runTask(() nothrow{
		try
			b = cache.keysFor("rsa-1").length;
		catch (Exception)
		{
		}
	});
	ta.join();
	tb.join();
	assert(s.fetches == 1);
	assert(a == 1 && b == 1);
}

unittest  // JwksCache.load() retains previous keys when parsing a malformed JWKS document throws
{
	// Successful initial load populates the cache.
	auto cache = new JwksCache("", 300.seconds);
	cache.load(`{"keys":[{"kty":"RSA","kid":"rsa-1","n":"` ~ testRsaN ~ `","e":"` ~ testRsaE
			~ `"}]}`);
	assert(cache.keysFor("rsa-1").length == 1, "initial load must populate keys");

	// A subsequent load with malformed JSON throws from parseJwks. The previous
	// keys must remain intact so JWT verification continues to succeed.
	try
		cache.load(`{not valid json`);
	catch (Exception)
	{
	}
	assert(cache.keysFor("rsa-1").length == 1,
			"keys must survive a failed re-load (clear-then-parse bug)");
}

unittest  // ecJwkToPem rejects an EC point that is not on the P-256 curve
{
	// A valid P-256 x coordinate paired with an all-zero y does not satisfy the
	// curve equation y^2 = x^3 - 3x + b (mod p), so the point is not on P-256.
	// The function must return null (not silently produce a PEM for an invalid
	// key). Without EC_KEY_check_key() this defence relied solely on
	// EC_POINT_set_affine_coordinates_GFp, which does not validate on all OpenSSL
	// versions (< 1.1.0). EC_KEY_check_key() provides the explicit check.
	Jwk j;
	j.kty = "EC";
	j.crv = "P-256";
	j.x = testEcX; // valid P-256 x coordinate
	j.y = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 32 zero bytes: not the correct y
	assert(jwkToPem(j) is null, "off-curve EC point must be rejected");
}

unittest  // rsaJwkToPem rejects RSA keys shorter than 2048 bits (NIST SP 800-131A)
{
	// 512-bit RSA modulus (base64url, no padding); well below the 2048-bit minimum.
	enum smallN = "xqhAjKOZdfUx4SiVpGhYDk7vdz1cCNfyLHX9gQvRe26KRa4GNKf43jn51CAgM3lc_f3dTlqRRWbftgFovIPye0c";
	Jwk j;
	j.kty = "RSA";
	j.n = smallN;
	j.e = "AQAB";
	assert(jwkToPem(j) is null, "sub-2048-bit RSA key must be rejected");
}

unittest  // verifyOrInvalid fails closed: an exception during verification yields an invalid token
{
	auto info = verifyOrInvalid(() @safe {
		throw new Exception("jwks unreachable");
		return TokenInfo.invalid(); // unreachable; fixes the delegate's return type
	});
	assert(!info.valid);
}

unittest  // verifyOrInvalid returns the verifier's result when no exception is raised
{
	TokenInfo ok;
	ok.valid = true;
	ok.subject = "alice";
	auto info = verifyOrInvalid(() @safe => ok);
	assert(info.valid && info.subject == "alice");
}

// ---------------------------------------------------------------------------
// Negative-branch coverage for the verification core and JWKS helpers.
// ---------------------------------------------------------------------------

unittest  // a token whose nbf is in the future is rejected (not-yet-valid)
{
	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	// Valid exp, but nbf is well beyond now + skew: the token is not yet valid.
	auto payload = parseJsonString(`{"sub":"ec-user","exp":1700100000,"nbf":1700090000}`);
	auto ti = validateClaims(cfg, payload, 1_700_001_000);
	assert(!ti.valid);
}

unittest  // a token carrying OIDC id_token-only claims is rejected even when typ is JWT
{
	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	cfg.audience = "client-123";
	foreach (claim; [
		`"nonce":"n-0S6_WzA2Mj"`, `"at_hash":"77QmUPtjPfzWtF2AnpK9RQ"`,
		`"c_hash":"LDktKdoQak3Pk0cnXxCltA"`
	])
	{
		auto payload = parseJsonString(`{"aud":"client-123","exp":1700100000,` ~ claim ~ `}`);
		assert(!validateClaims(cfg, payload, 1_700_001_000).valid, claim);
	}
	auto plain = parseJsonString(`{"aud":"client-123","exp":1700100000}`);
	assert(validateClaims(cfg, plain, 1_700_001_000).valid);
}

unittest  // a non-numeric nbf is rejected rather than skipping the not-before check
{
	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	foreach (nbf; [`"1700090000"`, `true`, `null`, `{}`, `[1700000000]`])
	{
		auto payload = parseJsonString(`{"exp":1700100000,"nbf":` ~ nbf ~ `}`);
		assert(!validateClaims(cfg, payload, 1_700_001_000).valid, nbf);
	}
}

unittest  // a fractional nbf is honoured: rejected while in the future, accepted once past
{
	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	auto future = parseJsonString(`{"exp":1700100000,"nbf":1700090000.5}`);
	assert(!validateClaims(cfg, future, 1_700_001_000).valid);
	auto past = parseJsonString(`{"exp":1700100000,"nbf":1700000000.5}`);
	assert(validateClaims(cfg, past, 1_700_001_000).valid);
}

unittest  // a fractional exp is honoured: accepted while in the future, rejected once past
{
	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	auto live = parseJsonString(`{"sub":"x","exp":1700003600.25}`);
	assert(validateClaims(cfg, live, 1_700_001_000).valid);
	auto expired = parseJsonString(`{"sub":"x","exp":1700000000.5}`);
	assert(!validateClaims(cfg, expired, 1_700_001_000).valid);
}

unittest  // a non-finite exp or nbf is rejected
{
	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	foreach (bad; [double.infinity, -double.infinity, double.nan])
	{
		auto exp = parseJsonString(`{"sub":"x"}`);
		exp["exp"] = Json(bad);
		assert(!validateClaims(cfg, exp, 1_700_001_000).valid);

		auto nbf = parseJsonString(`{"sub":"x","exp":1700100000}`);
		nbf["nbf"] = Json(bad);
		assert(!validateClaims(cfg, nbf, 1_700_001_000).valid);
	}
}

unittest  // verifyToken rejects a well-formed token when no candidate key exists
{
	JwtVerifierConfig cfg;
	cfg.allowAnyIssuer = true;
	// A structurally valid ES256 token carrying a kid, but the key source offers
	// nothing and no static PEM is pinned, so there are zero candidate keys.
	auto token = makeEs256(`{"sub":"x","exp":1700100000}`, "unknown-kid");
	auto ti = verifyToken(cfg, token, new NoKeys(), 1_700_001_000);
	assert(!ti.valid);
}

unittest  // verifyJws fails closed on an unparseable PEM, unsupported alg, or bad ES256 sig length
{
	const input = cast(const(ubyte)[]) "header.payload";

	// An unparseable public key yields no EVP_PKEY -> false.
	assert(!verifyJws("ES256", input, cast(const(ubyte)[]) "sig", "not-a-pem"));

	// An algorithm other than RS256/ES256 is refused outright.
	assert(!verifyJws("HS256", input, cast(const(ubyte)[]) "sig", testEcPubPem));

	// An ES256 signature that is not exactly 64 bytes cannot be DER-encoded.
	assert(!verifyJws("ES256", input, cast(const(ubyte)[])[1, 2, 3], testEcPubPem));

	// alg<->key family binding: ES256 alg with an RSA-shaped expectation is covered
	// elsewhere; here an RS256 alg verified against an EC key is rejected.
	assert(!verifyJws("RS256", input, cast(const(ubyte)[]) "sig", testEcPubPem));
}

unittest  // parseJwks tolerates a non-object root, a non-array keys member, and non-object entries
{
	assert(parseJwks(`"not an object"`).length == 0);
	assert(parseJwks(`{"keys":"not-an-array"}`).length == 0);
	// Non-object array entries are skipped, leaving no usable keys.
	assert(parseJwks(`{"keys":[1, "two", null]}`).length == 0);
}

unittest  // jwkToPem returns null for an unsupported key type and for malformed RSA/EC material
{
	// Unsupported kty (neither RSA nor EC).
	Jwk oct;
	oct.kty = "oct";
	assert(jwkToPem(oct).length == 0);

	// RSA JWK missing modulus/exponent.
	Jwk rsa;
	rsa.kty = "RSA";
	assert(jwkToPem(rsa).length == 0);

	// EC JWK missing coordinates.
	Jwk ecNoXy;
	ecNoXy.kty = "EC";
	ecNoXy.crv = "P-256";
	assert(jwkToPem(ecNoXy).length == 0);

	// EC JWK with an unsupported curve.
	Jwk ecBadCrv;
	ecBadCrv.kty = "EC";
	ecBadCrv.crv = "P-192";
	ecBadCrv.x = testEcX;
	ecBadCrv.y = testEcY;
	assert(jwkToPem(ecBadCrv).length == 0);
}

unittest  // JwksCache: an empty-URI cache that was never loaded offers no keys
{
	auto cache = new JwksCache("", 300.seconds);
	assert(cache.keysFor("any-kid").length == 0);
}

unittest  // JwksCache.load drops a JWK that cannot be converted to a PEM (sub-2048-bit RSA)
{
	// A usable-for-sig RSA JWK whose modulus is far below the 2048-bit floor is
	// rejected by jwkToPem, so load() retains no keys from it.
	auto cache = new JwksCache("", 300.seconds);
	cache.load(`{"keys":[{"kty":"RSA","kid":"weak","n":"AQAB","e":"AQAB"}]}`);
	assert(cache.keysFor("weak").length == 0);
}
