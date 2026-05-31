module mcp.auth.jwt;

import core.stdc.config : c_long;

import deimos.openssl.bio;
import deimos.openssl.pem;
import deimos.openssl.evp;
import deimos.openssl.ecdsa;
import deimos.openssl.bn;

import mcp.auth.oauth : base64UrlNoPad;

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
private void bnToFixed(const(BIGNUM)* bn, ubyte[] dst) @trusted
{
	import core.stdc.string : memset;

	const n = BN_num_bytes(bn);
	memset(dst.ptr, 0, dst.length);
	if (n <= 0 || n > dst.length)
		return;
	ubyte[64] tmp;
	BN_bn2bin(bn, tmp.ptr);
	dst[$ - n .. $] = tmp[0 .. n];
}

/// Build a signed ES256 JWT client assertion (RFC 7523) for OAuth client
/// authentication: `iss`/`sub` = client id, `aud` = the token endpoint.
string makeClientAssertion(string clientId, string audience, string privateKeyPem,
		long now, long lifetimeSeconds = 300, string jti = "") @safe
{
	import std.conv : to;

	const header = `{"alg":"ES256","typ":"JWT"}`;
	const theJti = jti.length ? jti : ("jti-" ~ now.to!string);
	const payload = `{"iss":"` ~ clientId ~ `","sub":"` ~ clientId ~ `","aud":"` ~ audience
		~ `","jti":"` ~ theJti ~ `","iat":` ~ now.to!string ~ `,"exp":` ~ (
				now + lifetimeSeconds).to!string ~ `}`;
	const signingInput = base64UrlNoPad(cast(const(ubyte)[]) header) ~ "."
		~ base64UrlNoPad(cast(const(ubyte)[]) payload);
	auto sig = signEs256(privateKeyPem, cast(const(ubyte)[]) signingInput);
	return signingInput ~ "." ~ base64UrlNoPad(sig);
}

/// The OAuth `client_assertion_type` for a JWT bearer client assertion.
enum jwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

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
