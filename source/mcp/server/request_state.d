/// An opt-in codec that secures the MRTR (SEP-2322) opaque `requestState` the
/// server hands a client in an `InputRequiredResult` and the (untrusted) client
/// echoes back verbatim on retry.
///
/// Per SEP-2322 a server MUST treat the echoed `requestState` as untrusted
/// input, SHOULD encrypt/sign it for integrity + confidentiality, and — when the
/// state carries data specific to the original user — MUST cryptographically
/// bind it to that user and verify the echoed state belongs to the currently
/// authenticated user (replay/hijack defense). This codec makes those a
/// one-liner: the server wraps outgoing state and verifies incoming state
/// transparently, so tool/prompt/task handlers keep calling
/// `inputRequired!T` / `requestStateAs!T` against plaintext.
///
/// Two wire modes share one envelope:
///   payload = {"s":<stateJson>,"exp":<unixSeconds>,"b":<bindTagHex>}
///   - signed (HMAC-SHA256): "v1."  ~ b64url(payload) ~ "." ~ b64url(mac)
///   - encrypted (AES-256-GCM): "v1e." ~ b64url(nonce ~ ciphertext ~ tag)
/// The bind tag is HMAC-SHA256(key, subject [~ "\0" ~ tool]) hex; in the
/// encrypted mode it is also fed as GCM AAD. Verification is fail-closed: a bad
/// MAC, a GCM auth failure, an expired blob, a wrong-subject bind, or an
/// unparseable envelope all yield `Nullable!string.init` (the dispatch path
/// then re-elicits).
module mcp.server.request_state;

import core.time : Duration, minutes, seconds;

import std.string : representation;
import std.typecons : Nullable, nullable;

import vibe.data.json : Json, parseJsonString;

import deimos.openssl.evp;
import deimos.openssl.hmac;
import deimos.openssl.rand;
import deimos.openssl.crypto;

import mcp.auth.oauth : base64UrlNoPad;

@safe:

/// base64url-decode without padding.
private ubyte[] base64UrlDecode(string seg) @safe
{
	import std.base64 : Base64URLNoPadding;

	return () @trusted { return Base64URLNoPadding.decode(seg); }();
}

/// Current wall-clock time in unix seconds.
private long currentUnixTime() @safe
{
	import std.datetime.systime : Clock;

	return Clock.currTime.toUnixTime;
}

/// How the codec protects the envelope. `signed` (HMAC-SHA256) gives integrity
/// and authenticity but leaves the inner state readable on the wire; `encrypted`
/// (AES-256-GCM) additionally gives confidentiality.
enum RequestStateMode
{
	/// HMAC-SHA256 over the payload. Tamper-evident, not confidential.
	signed,
	/// AES-256-GCM over the payload. Tamper-evident and confidential.
	encrypted,
}

/// What the codec binds the state to, so an echoed blob can only be redeemed by
/// the identity it was issued for (SEP-2322 user-binding MUST).
enum RequestStateBinding
{
	/// No binding. The blob round-trips for any (or no) authenticated subject.
	none,
	/// Bind to the authenticated subject (`ctx.auth().subject`).
	authSubject,
	/// Bind to the authenticated subject AND the tool/prompt name, so a blob
	/// issued by one tool cannot be replayed into another.
	authSubjectAndTool,
}

/// Configuration handed to `McpServer.secureRequestState`. The `key` is the
/// operator-supplied secret (>= 32 bytes); an empty `key` makes the server
/// generate a single-process ephemeral key (verification fails across instances
/// or restarts — see `secureRequestState`).
struct RequestStateSecurity
{
	/// The shared secret. HMAC key in `signed` mode; in `encrypted` mode its
	/// first 32 bytes are the AES-256 key and the whole key is the bind-tag HMAC
	/// key. MUST be >= 32 bytes when supplied.
	ubyte[] key;

	/// Wire protection mode. Defaults to `signed` (HMAC-SHA256).
	RequestStateMode mode = RequestStateMode.signed;

	/// How long an issued blob stays valid. An echoed blob past `exp` fails
	/// verification and re-elicits. Defaults to 5 minutes.
	Duration ttl = 5.minutes;

	/// Identity binding. Defaults to `authSubject`.
	RequestStateBinding bindTo = RequestStateBinding.authSubject;
}

/// The codec the dispatch path installs when an operator enables
/// `secureRequestState`. `encode` wraps a handler's plaintext state for the
/// wire; `decode` verifies an echoed blob and returns the inner state, or null
/// when verification fails (the caller then treats it as no state and
/// re-elicits). All crypto is fail-closed.
final class RequestStateCodec
{
	private const ubyte[] key;
	private const RequestStateMode mode;
	private const Duration ttl;
	private const RequestStateBinding bindTo;

	this(RequestStateSecurity sec) @safe
	{
		this.key = sec.key.idup;
		this.mode = sec.mode;
		this.ttl = sec.ttl;
		this.bindTo = sec.bindTo;
	}

	/// Wrap `stateJson` (the handler's plaintext requestState) into a wire blob
	/// bound to `subject`/`toolName` (per the configured binding) and stamped with
	/// an expiry `ttl` from now. The result is what the client sees and echoes
	/// back; `decode` is its inverse.
	string encode(string stateJson, string subject, string toolName) @safe
	{
		const exp = currentUnixTime() + cast(long) ttl.total!"seconds";
		const bindTagHex = bindTag(subject, toolName);

		Json env = Json.emptyObject;
		env["s"] = stateJson;
		env["exp"] = Json(exp);
		env["b"] = bindTagHex;
		const payload = (() @trusted => env.toString())();
		const payloadBytes = cast(const(ubyte)[]) payload.representation;

		final switch (mode)
		{
		case RequestStateMode.signed:
			const mac = hmacSha256(key, payloadBytes);
			return "v1." ~ base64UrlNoPad(payloadBytes) ~ "." ~ base64UrlNoPad(mac);
		case RequestStateMode.encrypted:
			ubyte[12] nonce;
			randomBytes(nonce[]);
			const aad = cast(const(ubyte)[]) bindTagHex.representation;
			const sealed = aesGcmSeal(aesKey(), nonce[], payloadBytes, aad);
			return "v1e." ~ base64UrlNoPad(nonce[] ~ sealed);
		}
	}

	/// Verify an echoed `wire` blob against the current `subject`/`toolName` and
	/// return the inner plaintext state, or `Nullable!string.init` on any failure
	/// (bad MAC, GCM auth failure, expired, wrong-subject bind, or unparseable).
	/// Fail-closed: the caller re-elicits on null.
	Nullable!string decode(string wire, string subject, string toolName) @safe
	{
		try
		{
			final switch (mode)
			{
			case RequestStateMode.signed:
				return decodeSigned(wire, subject, toolName);
			case RequestStateMode.encrypted:
				return decodeEncrypted(wire, subject, toolName);
			}
		}
		catch (Exception)
			return Nullable!string.init;
	}

	private Nullable!string decodeSigned(string wire, string subject, string toolName) @safe
	{
		import std.array : split;

		auto parts = wire.split('.');
		if (parts.length != 3 || parts[0] != "v1")
			return Nullable!string.init;
		const payloadBytes = base64UrlDecode(parts[1]);
		const presentedMac = base64UrlDecode(parts[2]);
		const expectedMac = hmacSha256(key, payloadBytes);
		if (!constantTimeEquals(presentedMac, expectedMac))
			return Nullable!string.init;
		return openEnvelope(payloadBytes, subject, toolName);
	}

	private Nullable!string decodeEncrypted(string wire, string subject, string toolName) @safe
	{
		if (wire.length < 4 || wire[0 .. 4] != "v1e.")
			return Nullable!string.init;
		const blob = base64UrlDecode(wire[4 .. $]);
		// nonce(12) ~ ciphertext ~ tag(16)
		if (blob.length < 12 + 16)
			return Nullable!string.init;
		const nonce = blob[0 .. 12];
		const ctAndTag = blob[12 .. $];
		const aad = cast(const(ubyte)[]) bindTag(subject, toolName).representation;
		auto opened = aesGcmOpen(aesKey(), nonce, ctAndTag, aad);
		if (opened.isNull)
			return Nullable!string.init;
		return openEnvelope(opened.get, subject, toolName);
	}

	/// Parse the decrypted/verified payload, check expiry, and confirm the bind
	/// tag matches the current identity. Returns the inner state or null.
	private Nullable!string openEnvelope(const(ubyte)[] payloadBytes, string subject,
			string toolName) @safe
	{
		const payload = (() @trusted => (cast(const(char)[]) payloadBytes).idup)();
		const env = parseJsonString(payload);
		if (env.type != Json.Type.object)
			return Nullable!string.init;
		if ("s" !in env || "exp" !in env || "b" !in env)
			return Nullable!string.init;
		if (env["exp"].type != Json.Type.int_)
			return Nullable!string.init;
		if (env["exp"].get!long < currentUnixTime())
			return Nullable!string.init;
		const presentedBind = env["b"].get!string;
		const expectedBind = bindTag(subject, toolName);
		if (!constantTimeEquals(cast(const(ubyte)[]) presentedBind.representation,
				cast(const(ubyte)[]) expectedBind.representation))
			return Nullable!string.init;
		return nullable(env["s"].get!string);
	}

	/// The bind tag (hex HMAC) for an identity. Empty subject (stdio / in-process
	/// / no auth) or `bindTo == none` yields the tag over an empty subject, so
	/// binding is a no-op without an authenticated identity (documented).
	private string bindTag(string subject, string toolName) @safe
	{
		if (bindTo == RequestStateBinding.none)
			subject = "";
		string material = subject;
		if (bindTo == RequestStateBinding.authSubjectAndTool)
			material = subject ~ "\0" ~ toolName;
		const mac = hmacSha256(key, cast(const(ubyte)[]) material.representation);
		return toHex(mac);
	}

	/// The 32-byte AES-256 key derived from the configured secret (its first 32
	/// bytes; the secret is required to be >= 32 bytes).
	private const(ubyte)[] aesKey() @safe
	{
		return key[0 .. 32];
	}
}

// ===========================================================================
// OpenSSL @trusted shims (raw C pointers confined here, like jwt_verifier.d)
// ===========================================================================

/// HMAC-SHA256(key, data) -> 32-byte MAC.
private ubyte[] hmacSha256(const(ubyte)[] key, const(ubyte)[] data) @trusted
{
	ubyte[32] mac;
	uint macLen;
	// A zero-length key would make OpenSSL fall back to a constant; callers always
	// pass a >= 32-byte key (or an ephemeral 32-byte one), so this is well-defined.
	const k = key.length ? key.ptr : (cast(const(ubyte)*) "".ptr);
	auto r = HMAC(EVP_sha256(), k, cast(int) key.length, data.length ? data.ptr
			: null, data.length, mac.ptr, &macLen);
	if (r is null || macLen != 32)
		return null;
	return mac.dup;
}

/// Fill `dst` with cryptographically secure random bytes.
private void randomBytes(ubyte[] dst) @trusted
{
	if (dst.length == 0)
		return;
	if (RAND_bytes(dst.ptr, cast(int) dst.length) != 1)
		throw new Exception("RAND_bytes failed");
}

/// Constant-time byte comparison (timing-safe). Differing lengths compare
/// unequal without short-circuiting on the common prefix.
private bool constantTimeEquals(const(ubyte)[] a, const(ubyte)[] b) @trusted
{
	if (a.length != b.length)
		return false;
	if (a.length == 0)
		return true;
	return CRYPTO_memcmp(a.ptr, b.ptr, a.length) == 0;
}

/// AES-256-GCM seal: encrypt `plaintext` under `key`/`nonce` with `aad`
/// authenticated, returning ciphertext ~ 16-byte tag.
private ubyte[] aesGcmSeal(const(ubyte)[] key, const(ubyte)[] nonce,
		const(ubyte)[] plaintext, const(ubyte)[] aad) @trusted
{
	auto ctx = EVP_CIPHER_CTX_new();
	if (ctx is null)
		throw new Exception("EVP_CIPHER_CTX_new failed");
	scope (exit)
		EVP_CIPHER_CTX_free(ctx);

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), null, null, null) != 1)
		throw new Exception("EncryptInit failed");
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, cast(int) nonce.length, null) != 1)
		throw new Exception("set ivlen failed");
	if (EVP_EncryptInit_ex(ctx, null, null, key.ptr, nonce.ptr) != 1)
		throw new Exception("EncryptInit key failed");

	int len;
	if (aad.length)
		if (EVP_EncryptUpdate(ctx, null, &len, aad.ptr, cast(int) aad.length) != 1)
			throw new Exception("aad update failed");

	auto ct = new ubyte[plaintext.length];
	if (plaintext.length)
		if (EVP_EncryptUpdate(ctx, ct.ptr, &len, plaintext.ptr, cast(int) plaintext.length) != 1)
			throw new Exception("encrypt update failed");
	const ctLen = len;

	int finalLen;
	if (EVP_EncryptFinal_ex(ctx, ct.ptr + ctLen, &finalLen) != 1)
		throw new Exception("encrypt final failed");

	ubyte[16] tag;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.ptr) != 1)
		throw new Exception("get tag failed");

	return ct[0 .. ctLen + finalLen].dup ~ tag.dup;
}

/// AES-256-GCM open: verify and decrypt `ctAndTag` (ciphertext ~ 16-byte tag)
/// under `key`/`nonce` with `aad`. Returns null on auth failure.
private Nullable!(ubyte[]) aesGcmOpen(const(ubyte)[] key, const(ubyte)[] nonce,
		const(ubyte)[] ctAndTag, const(ubyte)[] aad) @trusted
{
	if (ctAndTag.length < 16)
		return Nullable!(ubyte[]).init;
	const ct = ctAndTag[0 .. $ - 16];
	auto tag = ctAndTag[$ - 16 .. $].dup;

	auto ctx = EVP_CIPHER_CTX_new();
	if (ctx is null)
		return Nullable!(ubyte[]).init;
	scope (exit)
		EVP_CIPHER_CTX_free(ctx);

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), null, null, null) != 1)
		return Nullable!(ubyte[]).init;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, cast(int) nonce.length, null) != 1)
		return Nullable!(ubyte[]).init;
	if (EVP_DecryptInit_ex(ctx, null, null, key.ptr, nonce.ptr) != 1)
		return Nullable!(ubyte[]).init;

	int len;
	if (aad.length)
		if (EVP_DecryptUpdate(ctx, null, &len, aad.ptr, cast(int) aad.length) != 1)
			return Nullable!(ubyte[]).init;

	auto pt = new ubyte[ct.length];
	if (ct.length)
		if (EVP_DecryptUpdate(ctx, pt.ptr, &len, ct.ptr, cast(int) ct.length) != 1)
			return Nullable!(ubyte[]).init;
	const ptLen = len;

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.ptr) != 1)
		return Nullable!(ubyte[]).init;

	int finalLen;
	// A nonzero return authenticates the tag; zero means the ciphertext/AAD/tag
	// were tampered with, in which case we MUST NOT release the plaintext.
	if (EVP_DecryptFinal_ex(ctx, pt.ptr + ptLen, &finalLen) <= 0)
		return Nullable!(ubyte[]).init;

	return nullable(pt[0 .. ptLen + finalLen].dup);
}

/// Lowercase hex of `data`.
private string toHex(const(ubyte)[] data) @safe
{
	import std.format : format;

	string s;
	foreach (b; data)
		s ~= format("%02x", b);
	return s;
}

/// Generate a 32-byte ephemeral key (used when the operator supplies none).
package ubyte[] generateEphemeralKey() @safe
{
	auto k = new ubyte[32];
	randomBytes(k);
	return k;
}

// ===========================================================================
// Unit tests
// ===========================================================================

version (unittest)
{
	private RequestStateCodec signedCodec(RequestStateBinding b = RequestStateBinding.authSubject) @safe
	{
		RequestStateSecurity sec;
		sec.key = new ubyte[32];
		foreach (i; 0 .. 32)
			sec.key[i] = cast(ubyte) i;
		sec.mode = RequestStateMode.signed;
		sec.bindTo = b;
		return new RequestStateCodec(sec);
	}

	private RequestStateCodec encryptedCodec(RequestStateBinding b = RequestStateBinding
			.authSubject) @safe
	{
		RequestStateSecurity sec;
		sec.key = new ubyte[32];
		foreach (i; 0 .. 32)
			sec.key[i] = cast(ubyte)(0x40 + i);
		sec.mode = RequestStateMode.encrypted;
		sec.bindTo = b;
		return new RequestStateCodec(sec);
	}
}

unittest  // signed mode round-trips the inner state for the same subject
{
	auto codec = signedCodec();
	const wire = codec.encode(`{"step":1}`, "alice", "tool");
	auto got = codec.decode(wire, "alice", "tool");
	assert(!got.isNull);
	assert(got.get == `{"step":1}`);
}

unittest  // encrypted mode round-trips and hides the plaintext on the wire
{
	import std.algorithm : canFind;

	auto codec = encryptedCodec();
	const wire = codec.encode(`{"secret":"hunter2"}`, "alice", "tool");
	assert(!wire.canFind("hunter2"));
	auto got = codec.decode(wire, "alice", "tool");
	assert(!got.isNull);
	assert(got.get == `{"secret":"hunter2"}`);
}

unittest  // signed: flipping one wire byte fails verification (tamper)
{
	auto codec = signedCodec();
	auto wire = codec.encode(`{"step":1}`, "alice", "tool").dup;
	// Flip a byte inside the base64url payload segment.
	wire[5] = wire[5] == 'A' ? 'B' : 'A';
	auto got = codec.decode(wire.idup, "alice", "tool");
	assert(got.isNull);
}

unittest  // encrypted: flipping one wire byte fails GCM auth (tamper)
{
	auto codec = encryptedCodec();
	auto wire = codec.encode(`{"step":1}`, "alice", "tool").dup;
	wire[$ - 2] = wire[$ - 2] == 'A' ? 'B' : 'A';
	auto got = codec.decode(wire.idup, "alice", "tool");
	assert(got.isNull);
}

unittest  // expired blob (exp in the past) fails verification
{
	RequestStateSecurity sec;
	sec.key = new ubyte[32];
	sec.mode = RequestStateMode.signed;
	sec.bindTo = RequestStateBinding.none;
	sec.ttl = (-3600).seconds; // already expired at issue time
	auto codec = new RequestStateCodec(sec);
	const wire = codec.encode(`{"step":1}`, "", "tool");
	assert(codec.decode(wire, "", "tool").isNull);
}

unittest  // cross-user replay: a blob bound to alice is rejected for bob
{
	auto codec = signedCodec();
	const wire = codec.encode(`{"step":1}`, "alice", "tool");
	assert(codec.decode(wire, "bob", "tool").isNull);
}

unittest  // same-subject binding still verifies after a cross-user rejection
{
	auto codec = signedCodec();
	const wire = codec.encode(`{"step":1}`, "alice", "tool");
	assert(!codec.decode(wire, "alice", "tool").isNull);
}

unittest  // no-auth (empty subject) makes authSubject binding a no-op
{
	auto codec = signedCodec(RequestStateBinding.authSubject);
	const wire = codec.encode(`{"step":1}`, "", "tool");
	auto got = codec.decode(wire, "", "tool");
	assert(!got.isNull);
	assert(got.get == `{"step":1}`);
}

unittest  // authSubjectAndTool rejects a blob replayed into another tool
{
	auto codec = signedCodec(RequestStateBinding.authSubjectAndTool);
	const wire = codec.encode(`{"step":1}`, "alice", "toolA");
	assert(codec.decode(wire, "alice", "toolB").isNull);
	assert(!codec.decode(wire, "alice", "toolA").isNull);
}

unittest  // binding none ignores the subject entirely
{
	auto codec = signedCodec(RequestStateBinding.none);
	const wire = codec.encode(`{"step":1}`, "alice", "tool");
	assert(!codec.decode(wire, "bob", "tool").isNull);
}

unittest  // encrypted cross-user replay is rejected via the AAD bind tag
{
	auto codec = encryptedCodec();
	const wire = codec.encode(`{"step":1}`, "alice", "tool");
	assert(codec.decode(wire, "bob", "tool").isNull);
	assert(!codec.decode(wire, "alice", "tool").isNull);
}

unittest  // a garbage / non-envelope wire string decodes to null, not a throw
{
	auto codec = signedCodec();
	assert(codec.decode("not-a-valid-blob", "alice", "tool").isNull);
	assert(codec.decode("", "alice", "tool").isNull);
	assert(codec.decode("v1e.@@@", "alice", "tool").isNull);
}
