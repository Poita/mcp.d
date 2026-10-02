/// Outbound webhook delivery for the MCP Events extension: the pluggable HTTP
/// transport (SSRF-hardened by default), the Standard Webhooks request signing
/// (symmetric `v1,` HMAC, plus secret-rotation dual-signatures and an optional
/// asymmetric `v1a,` signer), and a pure lexical SSRF pre-flight. The delivery
/// orchestration (verification, retry, watermark, deliveryStatus) lives in
/// `mcp.server.events_runtime`; this module is the I/O + crypto seam it drives,
/// abstracted behind `WebhookTransport` so the engine is unit-testable without a
/// network.
module mcp.server.webhook_delivery;

import std.typecons : Nullable, nullable;
import vibe.data.json : Json;

import mcp.protocol.events : DeliveryErrorCategory;

@safe:

/// The MCP-specific header (not part of Standard Webhooks) that carries the
/// subscription id so a receiver can select the verifying secret before parsing
/// the body.
enum string subscriptionIdHeader = "X-MCP-Subscription-Id";

/// An optional asymmetric (`v1a,`) signer over a webhook delivery. Mirrors
/// Standard Webhooks' `sign(msgId, timestamp, payload)` and returns the full
/// `v1a,<base64>` token (or "" to skip) — so
/// `standardwebhooks.ed25519.AsymmetricWebhook.sign` is a drop-in.
alias V1aSigner = string delegate(string msgId, long ts, string payload) @safe;

/// The outcome of one outbound webhook HTTP attempt.
struct WebhookHttpResult
{
	bool ok; /// true on a 2xx response
	int statusCode; /// HTTP status (0 when no response was received)
	string body; /// response body (used to read a verification challenge echo)
	Nullable!DeliveryErrorCategory error; /// failure category when !ok

	static WebhookHttpResult success(int status, string body = "") @safe
	{
		WebhookHttpResult r;
		r.ok = true;
		r.statusCode = status;
		r.body = body;
		return r;
	}

	static WebhookHttpResult failure(DeliveryErrorCategory cat, int status = 0, string body = "") @safe
	{
		WebhookHttpResult r;
		r.ok = false;
		r.statusCode = status;
		r.body = body;
		r.error = cat;
		return r;
	}
}

/// A pluggable outbound webhook transport: POST/GET a request to a callback URL.
/// The default (`SecureWebhookTransport`) applies delivery-time SSRF hardening;
/// tests inject a fake that records requests and returns canned responses.
interface WebhookTransport
{
	/// POST `body` with `headers` to `url`. `allowPrivate` permits non-globally-
	/// routable hosts (development/tests only).
	WebhookHttpResult post(string url, string[string] headers, string body, bool allowPrivate) @safe;

	/// GET `url` (used to fetch a receiver's well-known document).
	WebhookHttpResult get(string url, bool allowPrivate) @safe;
}

/// The default transport: every request goes through the SSRF-hardened connector
/// (`mcp.protocol.ssrf.secureRequestHTTP`) — resolve-time IP validation against the
/// IANA special-purpose registries, connect to the validated IP with the original
/// Host/SNI, and no redirect following. Failures map to a `DeliveryErrorCategory`
/// (never the raw endpoint response, which could be a probing oracle).
final class SecureWebhookTransport : WebhookTransport
{
	import core.time : Duration, seconds;
	import vibe.http.common : HTTPMethod;

	private Duration requestTimeout_;

	/// `requestTimeout` bounds each HTTP attempt as a whole — connect, send, and
	/// reading the response — however slowly the callback trickles bytes. The
	/// runtime keeps it well under the delivery lease so a slow callback can never
	/// hold a leased job open past its lease (which would let another worker
	/// re-deliver it).
	this(Duration requestTimeout = 10.seconds) @safe
	{
		requestTimeout_ = requestTimeout;
	}

	WebhookHttpResult post(string url, string[string] headers, string body, bool allowPrivate) @safe
	{
		return request(url, HTTPMethod.POST, headers, body, allowPrivate);
	}

	WebhookHttpResult get(string url, bool allowPrivate) @safe
	{
		return request(url, HTTPMethod.GET, null, null, allowPrivate);
	}

	// One request under the connector's overall `requestTimeout_` deadline, so a
	// drip-fed response cannot outlive it. Only the status decides the outcome;
	// the body is read raw (no UTF-8 validation) and at most
	// `maxWebhookResponseBytes` of it, the rest dropped with the connection.
	private WebhookHttpResult request(string url, HTTPMethod method,
			string[string] headers, string body, bool allowPrivate) @safe
	{
		import vibe.http.client : HTTPClientRequest, HTTPClientResponse;
		import mcp.protocol.ssrf : FetchOptions, secureRequestHTTP, SsrfPolicy;

		const policy = allowPrivate ? SsrfPolicy.allowUserConfigured : SsrfPolicy.blockInternal;
		WebhookHttpResult result;
		bool answered;
		try
		{
			secureRequestHTTP(url, policy, (scope HTTPClientRequest req) {
				req.method = method;
				if (method == HTTPMethod.POST)
				{
					req.contentType = "application/json";
					foreach (k, v; headers)
						req.headers[k] = v;
					req.writeBody(cast(const(ubyte)[])
						body);
				}
			}, (scope HTTPClientResponse res) {
				bool truncated;
				auto rbody = readBoundedBody(res.bodyReader, maxWebhookResponseBytes, truncated);
				if (truncated)
					res.disconnect();
				if (res.statusCode / 100 == 2)
					result = WebhookHttpResult.success(res.statusCode, rbody);
				else
					result = WebhookHttpResult.failure(categoryForStatus(res.statusCode),
						res.statusCode);
				answered = true;
			}, FetchOptions(requestTimeout_));
		}
		catch (Exception e)
		{
			if (!answered)
				result = WebhookHttpResult.failure(categoryForException(e.msg));
		}
		return result;
	}
}

/// The most of a callback's response body a delivery reads: ample for a
/// verification echo or a well-known receiver document.
enum size_t maxWebhookResponseBytes = 64 * 1024;

/// Read at most `cap` bytes of `stream` as raw bytes (no UTF-8 validation),
/// setting `truncated` when more remained unread.
string readBoundedBody(S)(S stream, size_t cap, out bool truncated) @trusted
{
	import std.algorithm : min;

	ubyte[] buf;
	ubyte[4096] chunk;
	while (!stream.empty)
	{
		if (buf.length >= cap)
		{
			truncated = true;
			break;
		}
		const n = cast(size_t) min(stream.leastSize, chunk.length, cap - buf.length);
		stream.read(chunk[0 .. n]);
		buf ~= chunk[0 .. n];
	}
	return cast(string) buf;
}

/// Map a non-2xx HTTP status to its delivery-error category. Only a 5xx is a
/// server-side failure; any other final status — a 4xx, a redirect (deliveries
/// never follow one), or a stray 1xx — means the endpoint is misconfigured for
/// receiving deliveries, which the wire's `http_4xx` category reports.
DeliveryErrorCategory categoryForStatus(int status) @safe pure nothrow @nogc
{
	return (status / 100 == 5) ? DeliveryErrorCategory.http5xx : DeliveryErrorCategory.http4xx;
}

/// Best-effort classification of a connector exception message into a category.
/// The category never carries the raw message — it is a fixed enum value.
DeliveryErrorCategory categoryForException(string msg) @safe
{
	import std.algorithm : canFind;
	import std.uni : toLower;

	auto m = toLower(msg);
	if (m.canFind("tls") || m.canFind("ssl") || m.canFind("certificate"))
		return DeliveryErrorCategory.tlsError;
	if (m.canFind("timeout") || m.canFind("timed out"))
		return DeliveryErrorCategory.timeout;
	return DeliveryErrorCategory.connectionRefused;
}

/// The keys, identity and clock a delivery is signed with.
struct DeliverySigning
{
	string secret; /// current Standard Webhooks `whsec_` secret
	string previousSecret; /// rotated-out secret, also signed with during its grace window ("" if none)
	long previousSecretGraceUntilMs; /// end of the rotation grace window (ms since epoch)
	long nowMs; /// current time (ms since epoch), checked against the grace window
	string messageId; /// `webhook-id`
	long timestamp; /// `webhook-timestamp` (seconds since epoch)
	string subscriptionId; /// sent as `X-MCP-Subscription-Id`
	V1aSigner v1aSigner; /// optional asymmetric signer appending a `v1a,` signature
}

/// Build the signed Standard Webhooks request headers for a delivery of `body`:
/// the `webhook-id`/`-timestamp`/`-signature` triplet (symmetric `v1,` HMAC over
/// the raw body), the MCP `X-MCP-Subscription-Id` header, plus — during a secret
/// rotation grace window — a second `v1,` signature under the previous secret,
/// and — when an asymmetric signer is supplied — an appended `v1a,` signature.
string[string] signDeliveryHeaders(DeliverySigning signing, string body) @safe
{
	import standardwebhooks : Webhook;

	const msgId = signing.messageId;
	const ts = signing.timestamp;
	auto wh = Webhook(signing.secret);
	auto headers = wh.signHeaders(msgId, ts, body);
	string sig = headers["webhook-signature"];

	// Secret rotation: dual-sign with the prior secret during the grace window so
	// a receiver not yet updated verifies under either (Standard Webhooks
	// multi-signature).
	if (signing.previousSecret.length && signing.nowMs < signing.previousSecretGraceUntilMs)
	{
		auto prev = Webhook(signing.previousSecret);
		auto ph = prev.signHeaders(msgId, ts, body);
		sig = sig ~ " " ~ ph["webhook-signature"];
	}

	// Optional asymmetric server identity: append the signer's `v1a,<sig>` token
	// (over the same signed content). The signer mirrors Standard Webhooks'
	// `sign(msgId, ts, payload)`, so `standardwebhooks.ed25519.AsymmetricWebhook`
	// drops straight in (wired by the events-ed25519 build configuration).
	if (signing.v1aSigner !is null)
	{
		const token = signing.v1aSigner(msgId, ts, body);
		if (token.length)
			sig = sig ~ " " ~ token;
	}

	headers["webhook-signature"] = sig;
	headers[subscriptionIdHeader] = signing.subscriptionId;
	return headers;
}

/// Whether a callback host is permitted at subscribe/delivery time by lexical
/// inspection alone (a literal IP is classified directly; a registered name is
/// permitted here and validated at connect time by the SSRF-hardened transport).
/// `allowPrivate` permits non-globally-routable literals (development/tests).
bool callbackHostAllowed(string url, bool allowPrivate) @safe
{
	import mcp.protocol.ssrf : classifyHostLexical, AddressClass;

	const host = hostOf(url);
	if (host.length == 0)
		return false;
	if (allowPrivate)
		return true;
	// A registered name classifies as public_ lexically; the connector re-checks
	// the resolved IP at delivery time, so only reject literals that are provably
	// internal here.
	return classifyHostLexical(host) == AddressClass.public_;
}

/// The host of `url` (no scheme, userinfo, port, or path), or "" if it does not
/// parse. Uses vibe's URL parser — the same one `mcp.protocol.ssrf` uses — which also
/// strips the brackets from an IPv6 literal, the form `classifyHostLexical` wants.
private string hostOf(string url) @safe
{
	import vibe.inet.url : URL;

	try
		return URL(url).host;
	catch (Exception)
		return "";
}

/// Whether `body` is a valid challenge echo for `expected` — a JSON object whose
/// `challenge` equals `expected`, compared in constant time so a partial-match
/// timing side-channel cannot leak the nonce.
bool challengeEchoed(string body, string expected) @safe
{
	import vibe.data.json : parseJsonString;

	Json j;
	try
		j = parseJsonString(body);
	catch (Exception)
		return false;
	if (j.type != Json.Type.object || "challenge" !in j || j["challenge"].type != Json.Type.string)
		return false;
	return constantTimeEquals(j["challenge"].get!string, expected);
}

/// Constant-time string comparison (length-independent in its content compare),
/// to avoid leaking how much of a nonce matched.
bool constantTimeEquals(scope const(char)[] a, scope const(char)[] b) @safe pure nothrow @nogc
{
	if (a.length != b.length)
		return false;
	uint diff;
	foreach (i; 0 .. a.length)
		diff |= (a[i] ^ b[i]);
	return diff == 0;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

version (unittest)
{
	// "whsec_" + base64 of 32 zero bytes — a valid Standard Webhooks secret.
	private enum testSecret = "whsec_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
}

unittest  // signDeliveryHeaders produces verifiable Standard Webhooks headers
{
	import standardwebhooks : Webhook;

	const 
	body = `{"eventId":"evt_1","name":"n","timestamp":"t","data":{}}`;
	DeliverySigning signing = {
		secret: testSecret, messageId: "evt_1", timestamp: 1_739_980_800,
		subscriptionId: "sub_abc"
	};
	auto headers = signDeliveryHeaders(signing, body);
	assert(headers["webhook-id"] == "evt_1");
	assert(headers[subscriptionIdHeader] == "sub_abc");
	// An off-the-shelf Standard Webhooks verifier accepts the signed delivery.
	auto wh = Webhook(testSecret);
	auto verified = wh.verifyIgnoringTimestamp(body, headers);
	assert(verified == body);
}

unittest  // a rotated secret dual-signs so either secret verifies during the grace window
{
	import standardwebhooks : Webhook;

	enum prev = "whsec_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=";
	const 
	body = `{"x":1}`;
	DeliverySigning signing = {
		secret: testSecret, previousSecret: prev, previousSecretGraceUntilMs: 2_000_000,
		nowMs: 1_000_000, messageId: "evt", timestamp: 1700, subscriptionId: "sub"
	};
	auto headers = signDeliveryHeaders(signing, body);
	// both the new and the previous secret verify the delivery
	assert(Webhook(testSecret).verifyIgnoringTimestamp(body, headers) == body);
	assert(Webhook(prev).verifyIgnoringTimestamp(body, headers) == body);
}

unittest  // the rotation dual-signature is dropped once the grace window has passed
{
	import standardwebhooks : Webhook;
	import std.algorithm : canFind;

	enum prev = "whsec_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=";
	const 
	body = `{"x":1}`;
	// nowMs (3_000_000) is past graceUntilMs (2_000_000): only the new secret signs.
	DeliverySigning signing = {
		secret: testSecret, previousSecret: prev, previousSecretGraceUntilMs: 2_000_000,
		nowMs: 3_000_000, messageId: "evt", timestamp: 1700, subscriptionId: "sub"
	};
	auto headers = signDeliveryHeaders(signing, body);
	assert(Webhook(testSecret).verifyIgnoringTimestamp(body, headers) == body);
	// a single signature (no space-delimited second one)
	assert(!headers["webhook-signature"].canFind(' '));
}

unittest  // an asymmetric signer appends a v1a, signature alongside the v1, HMAC
{
	import std.algorithm : canFind;

	const 
	body = `{"x":1}`;
	DeliverySigning signing = {
		secret: testSecret, messageId: "evt", timestamp: 1700, subscriptionId: "sub",
		v1aSigner: (string id, long ts, string p) @safe => "v1a,ZmFrZQ=="
	};
	auto headers = signDeliveryHeaders(signing, body);
	assert(headers["webhook-signature"].canFind("v1a,ZmFrZQ=="));
	assert(headers["webhook-signature"].canFind("v1,"));
}

version (unittest)
{
	// Serve one canned HTTP response per connection on a loopback port and run
	// `client` against it inside the event loop. `respond` writes the response.
	private void withLoopbackServer(void delegate(scope TCPConnection conn) @safe respond,
			void delegate(ushort port) @safe client) @trusted
	{
		import vibe.core.core : runTask, runEventLoop, exitEventLoop;
		import vibe.core.net : listenTCP;

		auto listener = listenTCP(0, (TCPConnection conn) @safe nothrow{
			try
			{
				// Consume the request head and body before answering.
				ubyte[1] b;
				string head;
				while (!head.endsWith("\r\n\r\n"))
				{
					conn.read(b[]);
					head ~= cast(char) b[0];
				}
				auto cl = head.toLower.findSplitAfter("content-length:")[1];
				const len = cl.length ? cl.until("\r").to!string
					.strip
					.to!size_t : 0;
				foreach (_; 0 .. len)
					conn.read(b[]);
				respond(conn);
			}
			catch (Exception)
			{
			}
		}, "127.0.0.1");
		const port = listener.bindAddress.port;
		runTask(() nothrow{
			try
			{
				client(port);
				listener.stopListening();
			}
			catch (Exception)
			{
			}
			exitEventLoop();
		});
		runEventLoop();
	}

	import vibe.core.net : TCPConnection;
	import std.algorithm : endsWith, findSplitAfter, until;
	import std.string : strip;
	import std.uni : toLower;
	import std.conv : to;
}

unittest  // a drip-fed response body is cut off at the request deadline
{
	import core.time : Duration, msecs, MonoTime, seconds;
	import vibe.core.core : sleep;

	WebhookHttpResult result;
	Duration took;
	withLoopbackServer((scope TCPConnection conn) @safe {
		conn.write("HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n");
		foreach (_; 0 .. 100_000)
		{
			conn.write("x");
			conn.flush();
			sleep(20.msecs);
		}
	}, (ushort port) @safe {
		auto t = new SecureWebhookTransport(300.msecs);
		const start = MonoTime.currTime;
		result = t.post("http://127.0.0.1:" ~ port.to!string ~ "/hook", null, "{}", true);
		took = MonoTime.currTime - start;
	});
	assert(took < 3.seconds);
	assert(!result.ok && result.error.get == DeliveryErrorCategory.timeout);
}

unittest  // a 2xx response whose body is not UTF-8 still counts as delivered
{
	WebhookHttpResult result;
	withLoopbackServer((scope TCPConnection conn) @safe {
		conn.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n");
		conn.write(cast(const(ubyte)[])[0xff, 0xfe]);
		conn.flush();
	}, (ushort port) @safe {
		import core.time : seconds;

		auto t = new SecureWebhookTransport(5.seconds);
		result = t.post("http://127.0.0.1:" ~ port.to!string ~ "/hook", null, "{}", true);
	});
	assert(result.ok && result.statusCode == 200);
}

unittest  // a response body is read only up to the cap
{
	import core.time : seconds;
	import std.array : replicate;

	WebhookHttpResult result;
	withLoopbackServer((scope TCPConnection conn) @safe {
		enum size = 4 * 1024 * 1024;
		conn.write("HTTP/1.1 200 OK\r\nContent-Length: " ~ size.to!string ~ "\r\n\r\n");
		const chunk = "y".replicate(64 * 1024);
		foreach (_; 0 .. size / chunk.length)
			conn.write(chunk);
		conn.flush();
	}, (ushort port) @safe {
		auto t = new SecureWebhookTransport(5.seconds);
		result = t.post("http://127.0.0.1:" ~ port.to!string ~ "/hook", null, "{}", true);
	});
	assert(result.ok && result.body.length <= maxWebhookResponseBytes);
}

unittest  // categoryForStatus splits 4xx and 5xx
{
	assert(categoryForStatus(404) == DeliveryErrorCategory.http4xx);
	assert(categoryForStatus(503) == DeliveryErrorCategory.http5xx);
}

unittest  // categoryForStatus reports a redirect or informational final status as http4xx
{
	assert(categoryForStatus(301) == DeliveryErrorCategory.http4xx);
	assert(categoryForStatus(307) == DeliveryErrorCategory.http4xx);
	assert(categoryForStatus(101) == DeliveryErrorCategory.http4xx);
	assert(categoryForStatus(500) == DeliveryErrorCategory.http5xx);
}

unittest  // categoryForException classifies common failures
{
	assert(categoryForException("TLS handshake failed") == DeliveryErrorCategory.tlsError);
	assert(categoryForException("operation timed out") == DeliveryErrorCategory.timeout);
	assert(categoryForException("connection refused") == DeliveryErrorCategory.connectionRefused);
}

unittest  // callbackHostAllowed rejects a URL with no host even when private hosts are allowed
{
	assert(!callbackHostAllowed("https:///hooks", true));
	assert(!callbackHostAllowed("not a url", true));
}

unittest  // callbackHostAllowed rejects internal literals but permits public names
{
	assert(!callbackHostAllowed("https://127.0.0.1/hooks", false));
	assert(!callbackHostAllowed("https://10.0.0.1/hooks", false));
	assert(!callbackHostAllowed("https://[::1]/hooks", false));
	assert(callbackHostAllowed("https://proxy.example.com/hooks", false));
	// allowPrivate is the dev/test escape hatch
	assert(callbackHostAllowed("https://127.0.0.1/hooks", true));
}

unittest  // hostOf strips scheme, userinfo, port and path
{
	assert(hostOf("https://user@host.example:8443/path?q=1") == "host.example");
	assert(hostOf("https://[2001:db8::1]:443/x") == "2001:db8::1");
	assert(hostOf("https://plain.example") == "plain.example");
}

unittest  // challengeEchoed accepts a matching echo and rejects mismatches
{
	assert(challengeEchoed(`{"challenge":"nonce123"}`, "nonce123"));
	assert(!challengeEchoed(`{"challenge":"wrong"}`, "nonce123"));
	assert(!challengeEchoed(`not json`, "nonce123"));
	assert(!challengeEchoed(`{"other":"x"}`, "nonce123"));
}

unittest  // constantTimeEquals matches std equality semantics
{
	assert(constantTimeEquals("abc", "abc"));
	assert(!constantTimeEquals("abc", "abd"));
	assert(!constantTimeEquals("abc", "abcd"));
}
