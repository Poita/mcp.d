/// Server-side execution for the MCP Events extension. `EventsRuntime` holds the
/// registered event types, serves `events/poll`, fans `emit()`ed events out to
/// active push streams (and, in the webhook engine, to subscribers), and drives
/// the poll-lease lifecycle that fires `on_subscribe`/`on_unsubscribe`. It mirrors
/// the role `TaskRuntime` plays for `@task`: the server obtains one from
/// `enableEvents()` and the UDA reflection layer registers types against it.
module mcp.server.events_runtime;

import core.time : Duration, seconds, minutes, msecs;
import std.typecons : Nullable, nullable;
import std.algorithm : sort;
import vibe.data.json : Json;

import mcp.protocol.events;
import mcp.protocol.errors : McpException, notFound, unsupported, invalidParams,
	forbidden, resourceExhausted, internalError, toErrorJson;
import mcp.server.event_context : EventContext, EventResult, Event, EventBatch,
	FetchContext, SubContext;
import mcp.server.event_store : EmitBuffer, EmitBufferOptions,
	WebhookSubscription, WebhookSubscriptionStore,
	InMemoryWebhookSubscriptionStore, Delivery, DeliveryQueue, InMemoryDeliveryQueue, nowUnixMs;
import mcp.server.webhook_delivery : WebhookTransport, SecureWebhookTransport,
	WebhookHttpResult, V1aSigner, signDeliveryHeaders, callbackHostAllowed, challengeEchoed;

/// Grace window during which a rotated webhook secret is dual-signed alongside
/// the new one, so in-flight deliveries verify under either (Standard Webhooks
/// multi-signature). Five minutes covers a delivery's retry window.
private enum long secretRotationGraceMs = 5 * 60 * 1000;

@safe:

/// Author-supplied "check for changes since cursor" function — the single
/// function backing poll (and poll-driven push) for an event type.
alias EventCheck = EventResult delegate(EventContext ctx) @safe;

/// Broadcast-emit filter: whether a subscription (its arguments carried by `ctx`)
/// receives `ev`. Absent => every subscription for the event name receives it.
alias EventMatch = bool delegate(EventContext ctx, EventOccurrence ev) @safe;

/// Broadcast-emit transform: shape `ev` for a subscription (e.g. redact per its
/// arguments). Absent => the event is delivered as emitted.
alias EventTransform = EventOccurrence delegate(EventContext ctx, EventOccurrence ev) @safe;

/// Subscription lifecycle hook (subscribe/unsubscribe), invoked across all
/// delivery modes so the author sets up/tears down upstream listeners once.
alias EventLifecycle = void delegate(EventContext ctx, string subscriptionId) @safe;

/// One registered event type: its declared descriptor plus the author's check
/// function, optional broadcast `match`/`transform` shaping, and lifecycle hooks.
/// `emitOnly` types have no check function — poll is served from the ring buffer.
struct EventRegistration
{
	EventType descriptor; /// name/description/inputSchema/payloadSchema/_meta (delivery is computed)
	EventCheck check; /// null for emit-only
	EventMatch match; /// optional broadcast filter
	EventTransform transform; /// optional broadcast payload shaper
	EventLifecycle onSubscribe; /// optional upstream setup
	EventLifecycle onUnsubscribe; /// optional upstream teardown
	bool emitOnly; /// true => no check function; poll reads the ring buffer
	Nullable!Duration pollInterval; /// suggested client poll cadence
	DeliveryMode[] disabledModes; /// modes the author opted out of
}

/// A strongly-typed handle to an event type defined via `EventsRuntime.define`.
/// `A` is the subscription-argument type (filters/config; → inputSchema), `P` the
/// payload type (→ payloadSchema). Setters wrap typed delegates into the runtime's
/// type-erased registration and are chainable; `publish` marshals a typed payload.
final class EventHandle(A, P)
{
	import vibe.data.json : JsonSerializer;
	import vibe.data.serialization : serializeWithPolicy, deserializeWithPolicy;
	import mcp.api.reflection : EnumByNamePolicy;

	private EventsRuntime rt_;
	private EventRegistration reg_;

	private this(EventsRuntime rt, EventRegistration reg) @safe
	{
		rt_ = rt;
		reg_ = reg;
	}

	/// The event type name.
	string name() const @safe nothrow
	{
		return reg_.descriptor.name;
	}

	/// Publish a typed payload: fans out to node-local stream/poll subscribers and
	/// enqueues webhook deliveries. Reach is the scope of the injected registries
	/// (stream/poll are always node-local; webhook is as wide as the store).
	void publish(P payload) @safe
	{
		EventOccurrence occ;
		occ.name = reg_.descriptor.name;
		occ.data = serializePayload(payload);
		rt_.emit(occ);
	}

	/// Publish a typed payload carrying an upstream identity: `eventId` (used for
	/// dedup) and the occurrence `timestamp`. Use when re-publishing an event that
	/// already has its own id/time — a bridge from Slack/GitHub/an SSE feed — where
	/// the no-arg `publish` would otherwise mint a fresh id and stamp the current
	/// time. An empty `timestamp` is filled with the current time by the runtime.
	void publish(P payload, string eventId, string timestamp = "") @safe
	{
		EventOccurrence occ;
		occ.name = reg_.descriptor.name;
		occ.data = serializePayload(payload);
		occ.eventId = eventId;
		occ.timestamp = timestamp;
		rt_.emit(occ);
	}

	/// Attach the pull/fetch handler — drain events since `ctx.cursor` and return a
	/// typed batch. Backs poll directly and stream/webhook via the runtime's loop.
	EventHandle onFetch(EventBatch!P delegate(A args, scope FetchContext ctx) @safe fetch) @safe
	{
		reg_.check = (EventContext ctx) @safe {
			FetchContext fc;
			fc.cursor = ctx.cursor;
			fc.maxAgeMs = ctx.maxAgeMs;
			fc.principal = ctx.principal;
			return toResult(fetch(argsOf(ctx.arguments), fc));
		};
		reg_.emitOnly = false;
		rt_.register(reg_);
		return this;
	}

	/// Per-subscription filter: whether a subscription with `args` receives `payload`.
	EventHandle match(bool delegate(A args, P payload) @safe pred) @safe
	{
		reg_.match = (EventContext ctx, EventOccurrence ev) @safe {
			return pred(argsOf(ctx.arguments), deserializePayload(ev.data));
		};
		rt_.register(reg_);
		return this;
	}

	/// Per-subscription transform: shape the delivered occurrence for a subscription
	/// with `args` (e.g. redact a field the subscriber may not see), returning the
	/// `EventOccurrence` to deliver. Mirrors `match` so payload shaping is typed —
	/// no need to drop to the raw `register()` escape hatch. The shaper receives the
	/// decoded `payload`; build the result from `EventOccurrence.fromPayload` (or
	/// shape a copy of the emitted occurrence).
	EventHandle transform(EventOccurrence delegate(A args, P payload) @safe shaper) @safe
	{
		reg_.transform = (EventContext ctx, EventOccurrence ev) @safe {
			auto shaped = shaper(argsOf(ctx.arguments), deserializePayload(ev.data));
			// Preserve the routing/identity fields the runtime owns when the author left
			// them unset, so a shaper that only rewrites `data` keeps the event's id,
			// name, timestamp and cursor.
			if (shaped.eventId.length == 0)
				shaped.eventId = ev.eventId;
			if (shaped.name.length == 0)
				shaped.name = ev.name;
			if (shaped.timestamp.length == 0)
				shaped.timestamp = ev.timestamp;
			if (shaped.cursor.isNull)
				shaped.cursor = ev.cursor;
			return shaped;
		};
		rt_.register(reg_);
		return this;
	}

	/// Build an `EventOccurrence` carrying a typed payload, stamped with this type's
	/// name so it is routable by `emit`. Use inside a `transform` shaper, or to set
	/// identity fields (`eventId`/`timestamp`) before `publish`ing the occurrence.
	/// The runtime fills any identity/routing fields left unset.
	EventOccurrence fromPayload(P payload) @safe
	{
		EventOccurrence o;
		o.name = reg_.descriptor.name;
		o.data = serializePayload(payload);
		return o;
	}

	/// Fired when a subscription for this type first appears for a given
	/// `(principal, arguments)` — provision the upstream source here.
	///
	/// NODE-LOCAL: the lifecycle refcount that drives this hook lives in this
	/// `EventsRuntime` instance, so the 0->1 transition is per-node. Webhook
	/// subscriptions are shared across a cluster via the subscription store, so on a
	/// multi-node deployment `onSubscribe` fires once per node that first sees the
	/// key — not once cluster-wide. A cluster-coherent (shared-store atomic) refcount
	/// is future work; today, write the hook to be idempotent across nodes.
	EventHandle onSubscribe(void delegate(A args, scope SubContext ctx) @safe hook) @safe
	{
		reg_.onSubscribe = (EventContext ctx, string id) @safe {
			hook(argsOf(ctx.arguments), subContext(ctx, id));
		};
		rt_.register(reg_);
		return this;
	}

	/// Fired when the last subscription for a given `(principal, arguments)` goes away.
	///
	/// NODE-LOCAL: like `onSubscribe`, the 1->0 transition is per-node — the refcount
	/// is held in this `EventsRuntime` instance, not in the shared store. On a
	/// multi-node deployment this fires once per node as each node's last local
	/// subscription lapses, not once cluster-wide. Cluster-coherent teardown via a
	/// shared-store atomic refcount is future work.
	EventHandle onUnsubscribe(void delegate(A args, scope SubContext ctx) @safe hook) @safe
	{
		reg_.onUnsubscribe = (EventContext ctx, string id) @safe {
			hook(argsOf(ctx.arguments), subContext(ctx, id));
		};
		rt_.register(reg_);
		return this;
	}

	/// Suggested client poll cadence for this type.
	EventHandle pollInterval(Duration d) @safe
	{
		reg_.pollInterval = d;
		rt_.register(reg_);
		return this;
	}

	/// Restrict delivery: opt this type out of the given modes. The advertised
	/// `delivery` list becomes the server-available modes minus these (and minus any
	/// server-wide `EventsOptions.disabledModes`). Chainable.
	EventHandle disable(DeliveryMode[] modes...) @safe
	{
		reg_.disabledModes = modes.dup;
		rt_.register(reg_);
		return this;
	}

	/// Convenience: deliver this type ONLY by webhook — equivalent to
	/// `disable(DeliveryMode.poll, DeliveryMode.push)`.
	EventHandle webhookOnly() @safe
	{
		return disable(DeliveryMode.poll, DeliveryMode.push);
	}

	private EventResult toResult(EventBatch!P batch) @safe
	{
		EventOccurrence[] occs;
		foreach (e; batch.events)
		{
			EventOccurrence o;
			o.eventId = e.eventId;
			o.name = reg_.descriptor.name;
			o.timestamp = e.timestamp;
			o.data = serializePayload(e.payload);
			if (e.cursor.length)
				o.cursor = e.cursor;
			rt_.stamp(o); // fill eventId/timestamp when the author left them empty
			occs ~= o;
		}
		EventResult r;
		r.events = occs;
		r.cursor = batch.cursor;
		r.truncated = batch.truncated;
		r.hasMore = batch.hasMore;
		return r;
	}

	private SubContext subContext(EventContext ctx, string id) @safe
	{
		SubContext sc;
		sc.principal = ctx.principal;
		sc.subscriptionId = id;
		return sc;
	}

	// Deserialize subscription arguments leniently: arguments are partial filters,
	// so a field absent from the request keeps its `A.init` default rather than
	// erroring (vibe's whole-object deserialize requires every non-optional field).
	// Each present field is assigned individually, through `EnumByNamePolicy` so any
	// enum field round-trips by its schema-declared member name.
	private A argsOf(Json j) @safe
	{
		import std.traits : FieldNameTuple;

		A result;
		if (j.type == Json.Type.object)
			static foreach (f; FieldNameTuple!A)
				() @trusted {
					if (auto p = f in j)
						__traits(getMember, result, f) = deserializeWithPolicy!(JsonSerializer,
								EnumByNamePolicy, typeof(__traits(getMember, result, f)))(*p);
				}();
		return result;
	}

	// Marshal the payload `P` to/from JSON through `EnumByNamePolicy`, so any enum —
	// `P` itself or one nested in a field/array — is (de)serialized by its member
	// name, matching the derived payloadSchema and the @tool/@task marshalling.
	private static Json serializePayload(P payload) @safe
	{
		return () @trusted {
			return serializeWithPolicy!(JsonSerializer, EnumByNamePolicy)(payload);
		}();
	}

	private static P deserializePayload(Json data) @safe
	{
		return () @trusted {
			return deserializeWithPolicy!(JsonSerializer, EnumByNamePolicy, P)(data);
		}();
	}
}

/// When a webhook subscription's delivery is suspended: once at least
/// `minAttempts` deliveries were attempted in the current `window` and the share
/// that failed reached `failureRatePercent`. A rate over a meaningful sample means
/// a brief endpoint blip does not suspend a healthy subscription and a low-traffic
/// one is not suspended on a handful of failures. A successful refresh
/// reactivates a suspended subscription. `minAttempts == 0` never suspends.
struct WebhookSuspension
{
	Duration window = 60.minutes;
	int minAttempts = 100;
	int failureRatePercent = 95;
}

/// Tuning for the events runtime. Bundled per the project's settings-struct
/// convention rather than spread across the factory's parameters.
struct EventsOptions
{
	EmitBufferOptions emitBuffer; /// ring-buffer retention for emit-only poll
	Duration defaultPollInterval = 30.seconds; /// seeds `nextPollMs` when a type sets none
	Duration pollLeaseTtl = 5.minutes; /// poll subscription lease window (drives on_unsubscribe)
	Duration webhookTtlCap = 30.minutes; /// max granted webhook TTL (clamps suggestions down)
	Duration webhookMinTtl = 1.minutes; /// min granted webhook TTL (clamps tiny suggestions up)
	bool allowNoExpiry; /// permit `ttlMs:null` no-expiry grants (requires a durable store)
	bool webhookEnabled = true; /// advertise/serve webhook delivery
	DeliveryMode[] disabledModes; /// modes disabled for ALL types (a type may narrow further, not re-enable)
	int webhookMaxSubscriptionsPerPrincipal = 1000; /// cap on live webhook subscriptions one principal may hold (0 = unlimited)
	string[] callbackAllowlist; /// callback URL prefixes treated as pre-verified
	bool wellKnownReceiverVerification = true; /// honour a receiver-published /.well-known/mcp-webhook-receiver.json
	Duration wellKnownCacheTtl = 10.minutes; /// how long a fetched (or absent) receiver document is cached per origin
	bool allowPrivateCallbackHosts; /// permit non-globally-routable callback IPs (tests/dev)
	string assumePrincipal; /// when set, requests with no authenticated principal are treated as this one
	int webhookMaxAttempts = 5; /// bounded delivery attempts per event
	size_t webhookMaxBodyBytes = 256 * 1024; /// delivery bodies over this are abandoned (with a gap signal), never POSTed
	WebhookSuspension webhookSuspension; /// failure-rate policy that suspends delivery (active=false)
	Duration webhookRetryBase = 30.seconds; /// exponential-backoff base between attempts (5 attempts span 7.5 min)
	DeliveryQueue deliveryQueue; /// webhook outbox (default in-memory); shared/durable for multi-node
	Duration workerInterval = 5.seconds; /// cadence of the periodic worker `enableEvents` starts (0 = the author runs it)
	Duration deliveryLease = 1.minutes; /// how long a worker claims a leased delivery job
	Duration webhookHttpTimeout = 10.seconds; /// per-attempt HTTP bound (default transport); also the worst-case-retry budget input
	WebhookTransport webhookTransport; /// outbound HTTP (default SSRF-hardened); tests inject a fake
	void delegate(void delegate() @safe job) @safe deliveryExecutor; /// runs a delivery (default: a fiber)
	void delegate(Duration d) @safe deliverySleep; /// inter-attempt sleep (default: vibe sleep)
	V1aSigner v1aSigner; /// optional asymmetric (`v1a,`) signer; auto-wired from `webhookSigningKey`
	string webhookSigningKey; /// `whsk_` ed25519 signing key — requires the `library-ed25519` build
	Json webhookSigningJwks = Json.undefined; /// JWKS published at the server-identity well-known path
	string delegate() @safe nowIso; /// injectable ISO-8601 clock
	long delegate() @safe nowMs; /// injectable ms-epoch clock
}

/// The system clock as an ISO-8601 UTC timestamp.
string systemNowIso() @safe
{
	import std.datetime.systime : Clock;

	return () @trusted { return Clock.currTime().toUTC().toISOExtString(); }();
}

/// Format a millisecond epoch instant as an ISO-8601 UTC timestamp (used for the
/// webhook `refreshBefore` grant).
string isoFromMs(long ms) @safe
{
	import std.datetime.systime : SysTime, unixTimeToStdTime;
	import std.datetime.timezone : UTC;
	import core.time : msecs;

	auto t = SysTime(unixTimeToStdTime(ms / 1000), UTC());
	t += (ms % 1000).msecs;
	return t.toISOExtString();
}

/// A poll subscription's ephemeral lease: poll has no explicit goodbye, so the
/// SDK leases `(principal, name, arguments)` to drive `on_subscribe` (first sight)
/// and `on_unsubscribe` (lease expiry without renewal). Never persisted.
private struct PollLease
{
	string name;
	string principal;
	Json arguments;
	string subscriptionId;
	long expiresAtMs;
}

/// A refcount of the live subscriptions sharing one `(principal, name, arguments)`
/// across all delivery modes. `onSubscribe` fires on 0->1, `onUnsubscribe` on
/// 1->0, so an upstream source is provisioned/torn down exactly once.
private struct LifeRef
{
	int refs;
	string name;
	string principal;
	Json arguments;
	string subscriptionId;
}

/// A per-`(principal, url)` negative cache entry for endpoint verification: an
/// unverified endpoint that failed (or has not yet completed) its challenge is not
/// re-probed until `nextProbeMs`, with the window doubling (capped) per failure so
/// an endpoint that never verifies is not POSTed a fresh challenge on every emit.
private struct VerifyBackoff
{
	long nextProbeMs; /// earliest ms-epoch at which another verification probe is allowed
	long windowMs; /// current backoff window, doubled on each successive failure
}

/// A cached `/.well-known/mcp-webhook-receiver.json` for one callback origin: the
/// path prefixes it declares as accepting MCP webhook deliveries (empty when the
/// origin publishes none), and when it was fetched.
private struct WellKnownReceivers
{
	string[] prefixes;
	long fetchedAtMs;
}

/// One position a webhook subscription has deliveries in flight at, with how many
/// of them are still unsettled. Kept per subscription in enqueue order so the
/// watermark advances to a position only once every earlier one has settled.
private struct OutstandingCursor
{
	string cursor;
	int remaining;
}

/// The path of the receiver-published document that declares which paths under
/// a callback origin accept MCP webhook deliveries.
enum string wellKnownReceiverPath = "/.well-known/mcp-webhook-receiver.json";

/// The verification backoff bounds: the first probe after a failure waits this long,
/// doubling on each failure up to the cap.
private enum long verifyBackoffBaseMs = 30 * 1000;
private enum long verifyBackoffCapMs = 30 * 60 * 1000;

/// A live push delivery target — one open `events/stream`. The transport supplies
/// `deliver`, which writes a `notifications/events/*` frame (already tagged with
/// the subscription id) on the stream.
final class PushStream
{
	string name;
	Json arguments;
	string principal;
	Json subscriptionId; /// the events/stream request's JSON-RPC id
	Nullable!string cursor; /// last position delivered on this stream
	long lastHeartbeatMs; /// when a heartbeat was last sent (used by the stdio ticker)
	void delegate(string method, Json taggedParams) @safe deliver;
	bool terminated; /// set once the server ended the stream (`terminatePush`)
	void delegate() @safe onTerminated; /// transport hook run after the terminated frame: write the final result, drop the stream
}

/// Handle returned by `openPushStream`. `close()` unregisters the stream and fires
/// `on_unsubscribe`; it is idempotent.
final class PushHandle
{
	private EventsRuntime rt_;
	private PushStream stream_;
	private bool closed_;

	private this(EventsRuntime rt, PushStream stream) @safe
	{
		rt_ = rt;
		stream_ = stream;
	}

	/// The push stream this handle controls.
	PushStream stream() @safe nothrow
	{
		return stream_;
	}

	/// Stop delivering and release the subscription (fires `on_unsubscribe` once).
	void close() @safe
	{
		if (closed_)
			return;
		closed_ = true;
		rt_.closePushStream(stream_);
	}
}

/// Server-side events lifecycle. Construction is via `McpServer.enableEvents`.
final class EventsRuntime
{
	private EventRegistration[string] types_;
	private EmitBuffer buffer_;
	private WebhookSubscriptionStore webhookStore_;
	private DeliveryQueue deliveryQueue_;
	private EventsOptions opts_;
	private void delegate() @safe onListChanged_;
	private PushStream[] pushStreams_;
	private PollLease[string] pollLeases_; // lease key -> lease record
	private LifeRef[string] lifeRefs_; // (principal\0name\0args) -> live-subscription refcount
	private bool[string] verifiedEndpoints_; // (principal\0url) -> verified, in-memory cache
	private WellKnownReceivers[string] wellKnown_; // callback origin -> cached receiver document
	private OutstandingCursor[][string] outstanding_; // subscription id -> in-flight positions, enqueue order
	private long[string] nextFetchAt_; // subscription id -> when the poll-driven loop next fetches
	private VerifyBackoff[string] pendingVerification_; // (principal\0url) -> next-probe backoff

	this(WebhookSubscriptionStore webhookStore = null, EventsOptions opts = EventsOptions.init) @safe
	{
		webhookStore_ = (webhookStore is null) ? new InMemoryWebhookSubscriptionStore()
			: webhookStore;
		opts_ = opts;
		if (opts_.deliveryQueue is null)
			opts_.deliveryQueue = new InMemoryDeliveryQueue();
		deliveryQueue_ = opts_.deliveryQueue;
		if (opts_.nowIso is null)
			opts_.nowIso = () @safe => systemNowIso();
		if (opts_.nowMs is null)
			opts_.nowMs = () @safe => nowUnixMs();
		clampDeliveryLease();
		if (opts_.webhookTransport is null)
			opts_.webhookTransport = new SecureWebhookTransport(opts_.webhookHttpTimeout);
		if (opts_.deliveryExecutor is null)
			opts_.deliveryExecutor = (void delegate() @safe job) @safe {
			import vibe.core.core : runTask;

			runTask(() nothrow @safe {
				try
					job();
				catch (Exception e)
				{
					// Log rather than discard: a swallowed delivery exception otherwise
					// vanishes with no trace of why a webhook never arrived.
					try
						() @trusted {
						import std.stdio : stderr;

						stderr.writeln("[mcp.events] delivery task threw: ", e.msg);
					}();
					catch (Exception)
					{
					}
				}
			});
		};
		if (opts_.deliverySleep is null)
			opts_.deliverySleep = (Duration d) @safe {
			import vibe.core.core : sleep;

			sleep(d);
		};
		wireV1aSigner();
		buffer_ = new EmitBuffer(opts_.emitBuffer);
		buffer_.nowMs = opts_.nowMs;
	}

	// A delivery worker holds one lease across a job's whole bounded retry loop,
	// renewing it around each attempt. The lease must comfortably exceed the
	// worst-case single attempt — one max backoff plus one HTTP timeout — or a
	// concurrent drain could re-lease the job mid-attempt and double-deliver.
	// Clamp the lease up to that worst case (with headroom) rather than trusting a
	// too-short configured value.
	private void clampDeliveryLease() @safe
	{
		const worstAttemptMs = backoffFor(opts_.webhookMaxAttempts).total!"msecs"
			+ opts_.webhookHttpTimeout.total!"msecs";
		// Two attempts' worth of headroom so a renewal that lands late still holds.
		const floorMs = worstAttemptMs * 2;
		if (opts_.deliveryLease.total!"msecs" < floorMs)
			opts_.deliveryLease = floorMs.msecs;
	}

	// Auto-wire the asymmetric (`v1a,`) signer from a configured `whsk_`
	// `webhookSigningKey`. The ed25519 backend lives in the `standardwebhooks:ed25519`
	// subpackage (libsodium), pulled in only by the opt-in `library-ed25519` build
	// configuration (the `MCPWebhookEd25519` version); the default build stays
	// libsodium-free. An author who supplies their own `v1aSigner` overrides this.
	private void wireV1aSigner() @safe
	{
		if (opts_.v1aSigner !is null || opts_.webhookSigningKey.length == 0)
			return;
		version (MCPWebhookEd25519)
		{
			import standardwebhooks.ed25519 : AsymmetricWebhook;

			auto asym = AsymmetricWebhook(opts_.webhookSigningKey);
			opts_.v1aSigner = (string id, long ts, string body) @safe => asym.sign(id, ts, body);
			if (opts_.webhookSigningJwks.type != Json.Type.object)
				opts_.webhookSigningJwks = ed25519Jwks(asym.publicKeyEncoded());
		}
		else
			throw new Exception("EventsOptions.webhookSigningKey is set but the SDK was built "
					~ "without the ed25519 backend. Build mcp-d with the \"library-ed25519\" "
					~ "configuration (or define version MCPWebhookEd25519) to enable v1a signing, "
					~ "or supply your own EventsOptions.v1aSigner.");
	}

	/// Register a callback the server uses to push `notifications/events/list_changed`.
	void onListChanged(void delegate() @safe cb) @safe
	{
		onListChanged_ = cb;
	}

	/// Register (or replace) an event type.
	void register(EventRegistration reg) @safe
	{
		types_[reg.descriptor.name] = reg;
	}

	/// Define a strongly-typed event type with subscription-argument type `A` and
	/// payload type `P`, deriving `inputSchema` from `A` and `payloadSchema` from
	/// `P`. Returns a typed `EventHandle` for attaching a fetch handler / lifecycle
	/// hooks / `match`, and for `publish`. The typed surface is the primary author
	/// API; `register(EventRegistration)` remains the dynamic (raw-`Json`) escape
	/// hatch. A freshly-defined type is emit-only until `onFetch` is set.
	EventHandle!(A, P) define(A, P)(string name, string description = "", string title = "") @safe
	{
		import mcp.protocol.schema : jsonSchemaOf;

		EventRegistration reg;
		reg.descriptor.name = name;
		reg.descriptor.description = description;
		reg.descriptor.title = title;
		reg.descriptor.inputSchema = jsonSchemaOf!A;
		reg.descriptor.payloadSchema = jsonSchemaOf!P;
		reg.emitOnly = true;
		register(reg);
		return new EventHandle!(A, P)(this, reg);
	}

	/// Whether `name` is a registered event type.
	bool has(string name) @safe
	{
		return (name in types_) !is null;
	}

	/// Whether `name` is an emit-only type (poll served from the ring buffer).
	bool isEmitOnly(string name) @safe
	{
		auto p = name in types_;
		return p !is null && p.emitOnly;
	}

	/// The backing webhook subscription store.
	WebhookSubscriptionStore webhookStore() @safe nothrow
	{
		return webhookStore_;
	}

	/// The effective delivery modes for a registered type: poll, push, and (when
	/// enabled) webhook, minus any the author disabled. Emit-only types still
	/// support poll (served from the ring buffer).
	private static bool isDisabled(DeliveryMode m, const DeliveryMode[] disabled) @safe
	{
		foreach (d; disabled)
			if (d == m)
				return true;
		return false;
	}

	DeliveryMode[] effectiveDelivery(string name) @safe
	{
		auto p = name in types_;
		if (p is null)
			return null;
		DeliveryMode[] modes = [DeliveryMode.poll, DeliveryMode.push];
		if (opts_.webhookEnabled)
			modes ~= DeliveryMode.webhook;
		DeliveryMode[] result;
		foreach (m; modes)
		{
			if (isDisabled(m, opts_.disabledModes)) // server-wide policy
				continue;
			if (isDisabled(m, p.disabledModes)) // per-event opt-out
				continue;
			result ~= m;
		}
		return result;
	}

	/// Build the `events/list` result (single page — the registry is in-memory).
	EventListResult list() @safe
	{
		EventListResult r;
		foreach (name, reg; types_)
		{
			EventType t = reg.descriptor;
			t.name = name;
			t.delivery = effectiveDelivery(name);
			r.events ~= t;
		}
		// Deterministic order so list output is stable across calls.
		r.events.sort!((a, b) => a.name < b.name);
		return r;
	}

	/// Notify connected clients that the event-type set changed.
	void notifyListChanged() @safe
	{
		if (onListChanged_ !is null)
			onListChanged_();
	}

	/// Serve one `events/poll`: run the type's check function (or read the ring
	/// buffer for an emit-only type), honouring `maxAgeMs`/`maxEvents`. Also drives
	/// the poll lease that fires `on_subscribe` on first sight of this key.
	PollResult poll(string name, Json arguments, string principal,
			Nullable!string cursor, Nullable!long maxAgeMs, Nullable!long maxEvents) @safe
	{
		principal = resolvePrincipal(principal);
		auto p = name in types_;
		if (p is null)
			throw notFound("Unknown event type: " ~ name, "event");

		touchPollLease(*p, name, arguments, principal);

		return runPoll(*p, name, arguments, principal, cursor, maxAgeMs, maxEvents);
	}

	// The poll body without lease bookkeeping: read the ring buffer (emit-only) or
	// run the check function, and shape the result. Push streams advance through
	// this too, so a stream never takes out a poll lease.
	private PollResult runPoll(ref EventRegistration p, string name, Json arguments,
			string principal, Nullable!string cursor, Nullable!long maxAgeMs,
			Nullable!long maxEvents) @safe
	{
		auto ctx = new EventContext(cursor, arguments, principal, maxAgeMs);
		PollResult out_;
		if (p.emitOnly || p.check is null)
		{
			auto er = buffer_.readSince(name, cursor, maxAgeMs, maxEvents);
			er.events = applyShaping(p, ctx, er.events);
			out_.events = er.events;
			out_.cursor = er.cursor;
			out_.truncated = er.truncated;
			out_.hasMore = er.hasMore;
		}
		else
		{
			auto er = p.check(ctx);
			out_.events = er.events;
			out_.cursor = er.cursor;
			out_.truncated = er.truncated;
			out_.hasMore = er.hasMore;
		}
		out_.nextPollMs = nextPollMsFor(p);
		return out_;
	}

	/// Broadcast an emitted event: append it to the ring buffer (assigning a
	/// cursor) and fan it out to every active push stream whose subscription
	/// matches, applying the type's `match`/`transform` per subscription. The
	/// webhook engine additionally enqueues deliveries (see the webhook section).
	void emit(EventOccurrence occ) @safe
	{
		stamp(occ);
		auto reg = occ.name in types_;
		// Only emit-only types are buffer-backed: stamp the ring-buffer seq cursor for
		// them. A check-backed type owns its own cursor scheme, so a buffer seq must
		// never reach its streams (the stdio ticker feeds s.cursor back to check()).
		if (regIsEmitOnly(reg))
		{
			const cursor = buffer_.append(occ.name, occ);
			occ.cursor = cursor;
		}
		// Iterate a snapshot: a failing/slow subscriber may schedule its own removal,
		// mutating pushStreams_ mid-fan-out.
		foreach (s; pushStreams_.dup)
		{
			if (s.name != occ.name)
				continue;
			deliverToStreamSafely(reg, s, occ);
		}
		routeToWebhooks(reg, occ);
	}

	/// Emit an event to a single subscription by its push-stream id. Used when the
	/// server already knows which subscription the event belongs to.
	void emit(EventOccurrence occ, Json subscriptionId) @safe
	{
		stamp(occ);
		auto reg = occ.name in types_;
		if (regIsEmitOnly(reg))
		{
			const cursor = buffer_.append(occ.name, occ);
			occ.cursor = cursor;
		}
		foreach (s; pushStreams_.dup)
		{
			if (s.name == occ.name && s.subscriptionId == subscriptionId)
				deliverToStreamSafely(reg, s, occ);
		}
	}

	/// Open a push stream for a subscription: validate it, fire `on_subscribe`,
	/// register it for emit routing, and return a handle whose `close()` tears it
	/// down. The transport supplies `deliver` and drives the heartbeat/poll loop.
	PushHandle openPushStream(string name, Json arguments, string principal,
			Json subscriptionId, void delegate(string method, Json taggedParams) @safe deliver) @safe
	{
		principal = resolvePrincipal(principal);
		auto p = name in types_;
		if (p is null)
			throw notFound("Unknown event type: " ~ name, "event");
		bool pushOffered;
		foreach (m; effectiveDelivery(name))
			if (m == DeliveryMode.push)
				pushOffered = true;
		if (!pushOffered)
			throw unsupported("Event type does not offer push delivery: " ~ name,
					"deliveryMode", "push");

		auto s = new PushStream();
		s.name = name;
		s.arguments = (arguments.type == Json.Type.object) ? arguments : Json.emptyObject;
		s.principal = principal;
		s.subscriptionId = subscriptionId;
		s.deliver = deliver;
		pushStreams_ ~= s;

		acquireLifecycle(*p, name, s.arguments, principal, subscriptionIdString(subscriptionId));
		return new PushHandle(this, s);
	}

	/// Remove a push stream and fire its `on_unsubscribe`. Called by `PushHandle.close`.
	package void closePushStream(PushStream stream) @safe
	{
		size_t w;
		bool removed;
		foreach (s; pushStreams_)
		{
			if (s is stream)
			{
				removed = true;
				continue;
			}
			pushStreams_[w++] = s;
		}
		pushStreams_ = pushStreams_[0 .. w];
		if (removed)
			releaseLifecycle(stream.name, stream.arguments, stream.principal);
	}

	/// Advance a push stream on a check-backed type: run the check function from
	/// the stream's cursor and deliver what it returns. A gap (`truncated`) re-sends
	/// `notifications/events/active` with `truncated: true` and the fresh cursor
	/// before the events; a throwing check sends a recoverable
	/// `notifications/events/error` and the stream stays open. Emit-only streams
	/// receive their events live from `emit` and need no advancing. Both transports
	/// call this on their poll cadence.
	void advancePushStream(PushStream s) @safe
	{
		if (s.terminated)
			return;
		auto reg = s.name in types_;
		if (regIsEmitOnly(reg))
			return;
		PollResult r;
		try
			r = runPoll(*reg, s.name, s.arguments, s.principal, s.cursor,
					Nullable!long.init, Nullable!long.init);
		catch (Exception e)
		{
			Json err = (cast(McpException) e) !is null ? toErrorJson(cast(McpException) e)
				: toErrorJson(internalError(e.msg));
			s.deliver(eventsErrorNotification, withSubscriptionId(eventErrorParams(err), s.subscriptionId));
			return;
		}
		if (r.truncated)
			s.deliver(eventsActiveNotification, withSubscriptionId(activeParams(r.cursor, true), s.subscriptionId));
		foreach (ev; r.events)
			s.deliver(eventsEventNotification, withSubscriptionId(ev.toJson(), s.subscriptionId));
		if (!r.cursor.isNull)
			s.cursor = r.cursor;
	}

	/// End a push stream from the server side: deliver `notifications/events/
	/// terminated` carrying `error`, release the subscription (firing
	/// `on_unsubscribe`), and run the transport's `onTerminated` hook so it writes
	/// the final `StreamEventsResult` and drops the stream. Idempotent.
	void terminatePush(PushStream s, Json error) @safe
	{
		if (s.terminated)
			return;
		s.terminated = true;
		try
			s.deliver(eventsTerminatedNotification, withSubscriptionId(terminatedParams(error), s.subscriptionId));
		catch (Exception)
		{
			// The client is already gone; the stream is released regardless.
		}
		closePushStream(s);
		if (s.onTerminated !is null)
			s.onTerminated();
	}

	/// End every subscription to event type `name` — push streams and webhook
	/// subscriptions alike — with `error` (e.g. `NotFound {kind: "event"}` when
	/// the type is removed). Poll holds no server-side subscription to end.
	void terminateEventType(string name, Json error) @safe
	{
		terminateMatching((PushStream s) @safe => s.name == name,
				(WebhookSubscription w) @safe => w.name == name, error);
	}

	/// End every subscription `principal` holds — to event type `name`, or to
	/// every type when `name` is empty — with `error` (typically `-32012 Forbidden`
	/// once access is revoked).
	void terminatePrincipal(string principal, string name, Json error) @safe
	{
		terminateMatching((PushStream s) @safe => s.principal == principal
				&& (name.length == 0 || s.name == name),
				(WebhookSubscription w) @safe => w.principal == principal
				&& (name.length == 0 || w.name == name), error);
	}

	private void terminateMatching(bool delegate(PushStream) @safe pushPred,
			bool delegate(WebhookSubscription) @safe webhookPred, Json error) @safe
	{
		foreach (s; pushStreams_.dup)
			if (pushPred(s))
				terminatePush(s, error);
		foreach (w; webhookStore_.all())
			if (webhookPred(w))
				terminateWebhook(w.id, error);
	}

	/// Expire poll leases whose window has elapsed, firing `on_unsubscribe` for
	/// each. The transport/timer calls this periodically; a well-behaved poller
	/// renews its lease before it lapses.
	void sweepPollLeases() @safe
	{
		const now = opts_.nowMs();
		PollLease[] expired;
		foreach (key, lease; pollLeases_)
			if (now >= lease.expiresAtMs)
				expired ~= lease;
		foreach (lease; expired)
		{
			pollLeases_.remove(leaseKey(lease.name, lease.arguments, lease.principal));
			releaseLifecycle(lease.name, lease.arguments, lease.principal);
		}
	}

	// --- webhook subscription management -----------------------------------

	/// Idempotently subscribe (or refresh) a webhook subscription on the key
	/// `(principal, url, name, arguments)`. Validates the callback URL (https) and
	/// the `whsec_` secret, negotiates a TTL grant, rotates the secret with a grace
	/// window, and upserts the stored subscription. Fires `on_subscribe` only for a
	/// genuinely new subscription. (Endpoint verification and outbound delivery are
	/// performed by the webhook delivery engine.)
	SubscribeResult subscribeWebhook(SubscribeParams p, string principal) @safe
	{
		principal = resolvePrincipal(principal);
		if (principal.length == 0)
			throw forbidden("events/subscribe requires an authenticated principal");
		auto reg = p.name in types_;
		if (reg is null)
			throw notFound("Unknown event type: " ~ p.name, "event");
		if (!offersWebhook(p.name))
			throw unsupported("Event type does not offer webhook delivery: " ~ p.name,
					"deliveryMode", "webhook");
		validateCallbackUrl(p.delivery.url);
		validateWhsecSecret(p.delivery.secret);

		const id = webhookId(principal, p.delivery.url, p.name, p.arguments);
		const now = opts_.nowMs();
		auto existing = webhookStore_.get(id);
		// A lapsed subscription no longer holds state the client can refresh: it is
		// torn down and the call creates a fresh one from the supplied cursor.
		if (!existing.isNull && existing.get.isExpired(now))
		{
			removeWebhookState(existing.get);
			existing = Nullable!WebhookSubscription.init;
		}
		const isNew = existing.isNull;

		// Cap the number of live webhook subscriptions a single principal may hold,
		// so an authenticated caller cannot exhaust server memory (and the outbound
		// delivery budget) by subscribing without bound. A refresh of an existing
		// subscription reuses its slot and is never rejected.
		if (isNew && opts_.webhookMaxSubscriptionsPerPrincipal > 0)
		{
			int held;
			foreach (s; webhookStore_.all())
				if (s.principal == principal)
					held++;
			if (held >= opts_.webhookMaxSubscriptionsPerPrincipal)
				throw resourceExhausted("Too many webhook subscriptions for this principal",
						"webhookSubscriptions", opts_.webhookMaxSubscriptionsPerPrincipal);
		}

		WebhookSubscription sub = isNew ? WebhookSubscription.init : existing.get;
		sub.id = id;
		sub.principal = principal;
		sub.name = p.name;
		sub.arguments = p.arguments;
		sub.url = p.delivery.url;
		// Secret rotation: keep the prior secret for a grace window so in-flight
		// deliveries verify under either (Standard Webhooks multi-signature).
		if (!isNew && sub.secret.length && sub.secret != p.delivery.secret)
		{
			sub.previousSecret = sub.secret;
			sub.previousSecretGraceUntilMs = now + secretRotationGraceMs;
		}
		sub.secret = p.delivery.secret;
		// The cursor is client-owned. On a fresh subscription the supplied cursor is
		// the replay point; on a refresh of a live subscription the client's value is
		// at or behind the server's safe-to-persist watermark (advanced by acked
		// deliveries), so it is a no-op rather than a regression.
		if (isNew)
		{
			sub.cursor = p.cursor;
			sub.fetchCursor = p.cursor;
		}

		auto grant = grantTtl(p, now);
		sub.noExpiry = grant.isNull;
		sub.expiresAtMs = grant.isNull ? 0 : grant.get;
		const reactivated = !sub.active;
		sub.active = true;
		if (!sub.verified && urlAllowlisted(p.delivery.url))
			sub.verified = true;
		webhookStore_.put(sub);

		if (isNew)
			acquireLifecycle(*reg, p.name, p.arguments, principal, id);
		// A fresh subscription replays from its cursor (or bootstraps a fresh one);
		// the backfill reports whether delivery starts later than that cursor.
		const truncated = isNew ? backfillWebhook(sub, reg, p.maxAgeMs) : false;
		// A successful refresh is the client's liveness signal: deliveries queued
		// while suspended resume now rather than at the next worker pass.
		if (reactivated)
			opts_.deliveryExecutor(() @safe { drainDeliveries(); });

		SubscribeResult r;
		r.id = id;
		r.refreshBefore = grant.isNull ? Nullable!string.init : nullable(isoFromMs(grant.get));
		r.cursor = sub.cursor;
		r.truncated = truncated;
		// On a refresh, surface delivery health so the client can detect problems
		// without a separate monitoring channel.
		if (!isNew)
			r.deliveryStatus = deliveryStatusFor(sub);
		return r;
	}

	/// Build the optional `deliveryStatus` from a subscription's recorded health.
	private DeliveryStatus deliveryStatusFor(WebhookSubscription sub) @safe
	{
		DeliveryStatus st;
		st.active = sub.active;
		if (sub.lastDeliveryAtMs)
			st.lastDeliveryAt = isoFromMs(sub.lastDeliveryAtMs);
		if (sub.lastErrorCat >= 0)
			st.lastError = cast(DeliveryErrorCategory) sub.lastErrorCat;
		if (sub.failedSinceMs)
			st.failedSince = isoFromMs(sub.failedSinceMs);
		return st;
	}

	/// Eagerly tear down a webhook subscription resolved by the same key. Fires
	/// `on_unsubscribe`. Throws `NotFound` when no matching subscription exists.
	void unsubscribeWebhook(UnsubscribeParams p, string principal) @safe
	{
		principal = resolvePrincipal(principal);
		if (principal.length == 0)
			throw forbidden("events/unsubscribe requires an authenticated principal");
		const id = webhookId(principal, p.url, p.name, p.arguments);
		auto existing = webhookStore_.get(id);
		if (existing.isNull)
			throw notFound("No matching subscription", "subscription");
		removeWebhookState(existing.get);
	}

	/// Drop every webhook subscription whose grant has lapsed, firing
	/// `on_unsubscribe` for each. The periodic worker calls this; a lapsed
	/// subscription found by a refresh is dropped there directly.
	void sweepWebhookSubscriptions() @safe
	{
		const now = opts_.nowMs();
		foreach (sub; webhookStore_.all())
			if (sub.isExpired(now))
				removeWebhookState(sub);
	}

	// Forget a webhook subscription everywhere: the store, the lifecycle refcount
	// (firing `on_unsubscribe` on the last reference), and this node's in-flight
	// bookkeeping.
	private void removeWebhookState(WebhookSubscription sub) @safe
	{
		webhookStore_.remove(sub.id);
		outstanding_.remove(sub.id);
		nextFetchAt_.remove(sub.id);
		releaseLifecycle(sub.name, sub.arguments, sub.principal);
	}

	/// Replay for a fresh webhook subscription: enqueue every event since its
	/// cursor (from the ring buffer for an emit-only type, from the check function
	/// otherwise), bounded by `maxAgeMs`, and settle the subscription's cursors. A
	/// null cursor bootstraps: nothing is replayed and the subscription starts from
	/// the current position. Returns whether delivery starts later than the
	/// supplied cursor (the response's `truncated`).
	private bool backfillWebhook(ref WebhookSubscription sub, EventRegistration* reg,
			Nullable!long maxAgeMs) @safe
	{
		EventResult er;
		if (regIsEmitOnly(reg))
			er = buffer_.readSince(sub.name, sub.cursor, maxAgeMs, Nullable!long.init);
		else
		{
			auto ctx = new EventContext(sub.fetchCursor, sub.arguments, sub.principal, maxAgeMs);
			try
				er = reg.check(ctx);
			catch (Exception)
				return false; // the upstream is unavailable: no replay, delivery continues live
			foreach (ref occ; er.events)
				if (occ.cursor.isNull)
					occ.cursor = er.cursor; // a batch-cursor event settles with its batch
		}
		sub.fetchCursor = er.cursor;
		// With nothing to replay the reported position is already safe to persist;
		// otherwise the watermark stays put until the replayed deliveries settle.
		if (er.events.length == 0)
			sub.cursor = er.cursor;
		webhookStore_.put(sub);
		bool any;
		foreach (occ; er.events)
			any |= enqueueForWebhook(sub, reg, occ, regIsEmitOnly(reg));
		if (any)
			opts_.deliveryExecutor(() @safe { drainDeliveries(); });
		return er.truncated;
	}

	/// The poll-driven webhook pass: for every live subscription to a check-backed
	/// type whose cadence has come round, run the check function from the
	/// subscription's fetch position and enqueue what it returns. A quiet fetch
	/// with nothing in flight advances the watermark (so the client's cursor moves
	/// during quiet periods); a fetch that reports `truncated` posts a `gap`
	/// envelope. Emit-only types are not polled — `emit` routes them live.
	void pollWebhookSubscriptions() @safe
	{
		if (!opts_.webhookEnabled)
			return;
		const now = opts_.nowMs();
		bool any;
		foreach (sub; webhookStore_.all())
		{
			if (sub.isExpired(now) || !sub.active)
				continue;
			auto reg = sub.name in types_;
			if (regIsEmitOnly(reg))
				continue;
			if (auto next = sub.id in nextFetchAt_)
				if (now < *next)
					continue;
			nextFetchAt_[sub.id] = now + nextPollMsFor(*reg);
			auto ctx = new EventContext(sub.fetchCursor, sub.arguments, sub.principal);
			EventResult er;
			try
				er = reg.check(ctx);
			catch (Exception)
				continue; // transient upstream failure: try again next pass
			foreach (ref occ; er.events)
				if (occ.cursor.isNull)
					occ.cursor = er.cursor;
			sub.fetchCursor = er.cursor;
			if (er.events.length == 0 && (sub.id in outstanding_) is null)
				sub.cursor = er.cursor;
			webhookStore_.put(sub);
			if (er.truncated && !er.cursor.isNull)
				postGap(sub, er.cursor.get);
			foreach (occ; er.events)
				any |= enqueueForWebhook(sub, reg, occ, false);
		}
		if (any)
			opts_.deliveryExecutor(() @safe { drainDeliveries(); });
	}

	// Enqueue one delivery of `occ` for `sub`, applying the type's `match`/
	// `transform` when `shape` is set (broadcast emits; a check function has
	// already applied the subscription's arguments), and tracking the position for
	// the watermark. Returns false when the filter dropped the event.
	private bool enqueueForWebhook(WebhookSubscription sub, EventRegistration* reg,
			EventOccurrence occ, bool shape) @safe
	{
		EventOccurrence shaped = occ;
		if (shape)
		{
			auto ctx = new EventContext(sub.cursor, sub.arguments, sub.principal);
			if (reg !is null && reg.match !is null && !reg.match(ctx, occ))
				return false;
			if (reg !is null && reg.transform !is null)
				shaped = reg.transform(ctx, occ);
		}
		trackOutstanding(sub.id, shaped.cursor);
		deliveryQueue_.enqueue(Delivery(sub.id ~ "/" ~ shaped.eventId, sub.id, shaped, 0));
		return true;
	}

	/// The deterministic subscription id for a key — a truncated SHA-256 of the
	/// canonical `(principal, url, name, arguments)` serialization. Stable across
	/// refreshes and restarts; a routing handle, not a capability.
	string webhookId(string principal, string url, string name, Json arguments) @safe
	{
		return "sub_" ~ sha256Hex(
				principal ~ "\0" ~ url ~ "\0" ~ name ~ "\0" ~ canonicalJsonString(arguments))[0
			.. 16];
	}

	private bool offersWebhook(string name) @safe
	{
		foreach (m; effectiveDelivery(name))
			if (m == DeliveryMode.webhook)
				return true;
		return false;
	}

	// Whether a callback URL is pre-verified by the configured allowlist. The match
	// is on the URL's parsed authority (scheme + host + port) using vibe's URL parser
	// — the same one the SSRF path uses — so a raw-byte prefix cannot pre-verify an
	// attacker's sibling domain (`hooks.example.com.evil.com`) or smuggle one through
	// userinfo (`https://hooks.example.com@evil.com/`). A URL carrying userinfo is
	// never allowlisted; an allowlist entry is treated as an origin plus a path
	// prefix matched against the parsed components, not as a byte prefix.
	private bool urlAllowlisted(string url) @safe
	{
		import std.algorithm : startsWith;

		string scheme, host, path;
		ushort port;
		bool hasUserinfo;
		if (!parseAuthority(url, scheme, host, port, path, hasUserinfo))
			return false;
		if (hasUserinfo)
			return false; // a userinfo-bearing URL is never pre-verified

		foreach (entry; opts_.callbackAllowlist)
		{
			string eScheme, eHost, ePath;
			ushort ePort;
			bool eUserinfo;
			if (!parseAuthority(entry, eScheme, eHost, ePort, ePath, eUserinfo))
				continue;
			if (eUserinfo)
				continue;
			// Authority must match exactly (scheme/host/port), then the entry's path is
			// a prefix of the URL's path so an origin entry covers everything under it.
			if (scheme != eScheme || host != eHost || port != ePort)
				continue;
			if (path.startsWith(ePath))
				return true;
		}
		return false;
	}

	// Parse a URL into its scheme, host, effective port, path and whether it carries
	// userinfo, via vibe's URL parser. Returns false (rejecting the URL) when it does
	// not parse or has no host.
	private static bool parseAuthority(string url, out string scheme,
			out string host, out ushort port, out string path, out bool hasUserinfo) @safe
	{
		import vibe.inet.url : URL;

		try
		{
			auto u = URL(url);
			scheme = u.schema;
			host = u.host;
			port = u.port; // effective port (scheme default when unset)
			path = u.pathString;
			hasUserinfo = u.username.length != 0 || u.password.length != 0;
		}
		catch (Exception)
			return false;
		return host.length != 0;
	}

	// Returns the absolute expiry (ms epoch), or null for a granted no-expiry.
	private Nullable!long grantTtl(SubscribeParams p, long now) @safe
	{
		const capMs = opts_.webhookTtlCap.total!"msecs";
		const minMs = opts_.webhookMinTtl.total!"msecs";
		if (!p.ttlMsPresent)
			return nullable(now + capMs); // server default
		if (p.ttlMs.isNull)
		{
			// No-expiry requested: granted only when the server allows it (a durable
			// store); otherwise the server returns a finite grant.
			if (opts_.allowNoExpiry)
				return Nullable!long.init;
			return nullable(now + capMs);
		}
		long suggest = p.ttlMs.get;
		if (suggest > capMs)
			suggest = capMs; // grant SHOULD be <= the suggestion and <= the cap
		if (suggest < minMs)
			suggest = minMs; // clamp an impractically short suggestion up to the floor
		return nullable(now + suggest);
	}

	private void validateCallbackUrl(string url) @safe
	{
		import std.algorithm : startsWith;

		if (url.startsWith("https://"))
			return;
		// A plain-http callback is permitted only in the dev/test configuration that
		// relaxes the SSRF host check AND only when the host classifies as
		// loopback/internal — never a public host, so a cleartext POST (payload plus
		// subscribe-time secret) cannot leave the local network even with the dev flag.
		// Production requires https everywhere.
		if (opts_.allowPrivateCallbackHosts && url.startsWith("http://") && isInternalHttpHost(url))
			return;
		throw invalidParams("delivery.url must be an https URL");
	}

	// Whether the host of an `http://` URL classifies as loopback or
	// private/link-local by the shared SSRF lexical classifier — i.e. not a public,
	// globally-routable host. Used to confine the dev cleartext-http allowance to the
	// local network.
	private static bool isInternalHttpHost(string url) @safe
	{
		import mcp.protocol.ssrf : classifyHostLexical, AddressClass;

		string scheme, host, path;
		ushort port;
		bool hasUserinfo;
		if (!parseAuthority(url, scheme, host, port, path, hasUserinfo))
			return false;
		return classifyHostLexical(host) != AddressClass.public_;
	}

	// Resolve the effective principal: the authenticated one, or the configured
	// `assumePrincipal` fallback for single-tenant/dev servers that authenticate
	// outside the SDK (or not at all).
	private string resolvePrincipal(string principal) @safe
	{
		return principal.length ? principal : opts_.assumePrincipal;
	}

	private void validateWhsecSecret(string secret) @safe
	{
		import std.algorithm : startsWith;
		import std.base64 : Base64;

		if (!secret.startsWith("whsec_"))
			throw invalidParams("delivery.secret must be a whsec_ Standard Webhooks secret");
		ubyte[] raw;
		try
			raw = Base64.decode(secret["whsec_".length .. $]);
		catch (Exception)
			throw invalidParams("delivery.secret is not valid base64");
		if (raw.length < 24 || raw.length > 64)
			throw invalidParams("delivery.secret must decode to 24..64 bytes");
	}

	// --- internals ---------------------------------------------------------

	private long nextPollMsFor(ref EventRegistration reg) @safe
	{
		const dur = reg.pollInterval.isNull ? opts_.defaultPollInterval : reg.pollInterval.get;
		return dur.total!"msecs";
	}

	private EventOccurrence[] applyShaping(ref EventRegistration reg,
			EventContext ctx, EventOccurrence[] events) @safe
	{
		if (reg.match is null && reg.transform is null)
			return events;
		EventOccurrence[] result;
		foreach (e; events)
		{
			if (reg.match !is null && !reg.match(ctx, e))
				continue;
			result ~= (reg.transform !is null) ? reg.transform(ctx, e) : e;
		}
		return result;
	}

	// True for an emit-only (buffer-backed) registration. A null registration is
	// treated as emit-only since it has no check function.
	private static bool regIsEmitOnly(EventRegistration* reg) @safe
	{
		return reg is null || reg.emitOnly || reg.check is null;
	}

	// Deliver to one stream, swallowing a throwing/disconnected subscriber so it can
	// neither abort the fan-out to its siblings nor skip the subsequent webhook
	// enqueue. The failing stream is scheduled for removal after the loop.
	private void deliverToStreamSafely(EventRegistration* reg, PushStream s, EventOccurrence occ) @safe
	{
		try
			deliverToStream(reg, s, occ);
		catch (Exception)
			closePushStream(s);
	}

	private void deliverToStream(EventRegistration* reg, PushStream s, EventOccurrence occ) @safe
	{
		auto ctx = new EventContext(s.cursor, s.arguments, s.principal);
		if (reg !is null && reg.match !is null && !reg.match(ctx, occ))
			return;
		EventOccurrence shaped = (reg !is null && reg.transform !is null) ? reg.transform(ctx,
				occ) : occ;
		// Only advance the stream cursor for buffer-backed types. For a check-backed
		// type the ring-buffer seq is foreign to the author's check(), and the stdio
		// ticker resumes that check() from s.cursor — so leave s.cursor for the
		// ticker's poll() to advance from check results.
		if (regIsEmitOnly(reg))
			s.cursor = shaped.cursor;
		auto params = withSubscriptionId(shaped.toJson(), s.subscriptionId);
		s.deliver(eventsEventNotification, params);
	}

	/// Fan an emitted event out to every live webhook subscription whose name
	/// matches (a suspended one included — its jobs wait for the refresh that
	/// reactivates it), applying the type's `match`/`transform` per subscription, by
	/// enqueuing a `Delivery` job per subscription and kicking a drain. Publish is
	/// thus decoupled from delivery: the job lives in the (possibly shared/durable)
	/// `DeliveryQueue`, so any node's worker can deliver it and a crashed node's
	/// job is re-leased — the multi-node path.
	private void routeToWebhooks(EventRegistration* reg, EventOccurrence occ) @safe
	{
		if (!opts_.webhookEnabled)
			return;
		const now = opts_.nowMs();
		bool any;
		foreach (sub; webhookStore_.all())
		{
			if (sub.name != occ.name || sub.isExpired(now))
				continue;
			any |= enqueueForWebhook(sub, reg, occ, true);
		}
		// Kick a drain on this node so the just-enqueued jobs deliver promptly
		// (workers on other nodes also lease from a shared queue independently).
		if (any)
			opts_.deliveryExecutor(() @safe { drainDeliveries(); });
	}

	/// Process one pass of the delivery queue: lease the ready jobs (claiming them
	/// for `deliveryLease`) and deliver + ack each. Called by the per-publish kick
	/// and by `startDeliveryWorker`. Safe to run on any node against a shared queue.
	void drainDeliveries() @safe
	{
		const leaseMs = opts_.deliveryLease.total!"msecs";
		foreach (job; deliveryQueue_.lease(opts_.nowMs(), leaseMs))
		{
			// Deliver each leased job in its own task so a slow job can't expire its
			// siblings' leases (they wait sequentially otherwise). Each task renews
			// its own lease around every attempt.
			opts_.deliveryExecutor(deliveryTask(job));
		}
	}

	// A delegate delivering `job`. Built by a call so each task closes over its own
	// copy: a closure created inside the lease loop would share the loop variable
	// and every deferred task would deliver the last leased job.
	private void delegate() @safe deliveryTask(Delivery job) @safe
	{
		return () @safe { deliverGuarded(job); };
	}

	// Run one job's bounded retry loop, settling it even when `deliverWithRetry`
	// throws unexpectedly (e.g. a custom store/queue raising). Without this a thrown
	// job would stay leased and silently re-lease forever. On an unexpected throw the
	// attempt count is advanced and the job is dead-lettered (acked) once the bound is
	// reached, so a persistently-throwing job cannot loop invisibly.
	private void deliverGuarded(Delivery job) @safe
	{
		bool settled;
		try
		{
			deliverWithRetry(job);
			settled = true;
		}
		catch (Exception)
		{
		}
		if (settled)
			return;
		const attempt = job.attempt + 1;
		if (attempt >= opts_.webhookMaxAttempts)
			deliveryQueue_.ack(job.jobId); // dead-letter: bound total attempts
		else
			deliveryQueue_.touch(job.jobId, attempt,
					opts_.nowMs() + opts_.deliveryLease.total!"msecs");
	}

	/// Run the periodic worker until `stop()` returns true: every `interval` it
	/// expires poll leases, sweeps lapsed webhook subscriptions, runs the
	/// poll-driven webhook pass, and drains the delivery queue. `enableEvents`
	/// starts one per server at `workerInterval`; a multi-node deployment shares a
	/// durable `DeliveryQueue` so any node's worker delivers (and re-leases a dead
	/// node's jobs).
	void startDeliveryWorker(Duration interval, bool delegate() @safe stop = null) @safe
	{
		opts_.deliveryExecutor(() @safe {
			while (stop is null || !stop())
			{
				tick();
				opts_.deliverySleep(interval);
			}
		});
	}

	/// One pass of the periodic work the worker loop performs.
	void tick() @safe
	{
		sweepPollLeases();
		sweepWebhookSubscriptions();
		pollWebhookSubscriptions();
		drainDeliveries();
	}

	/// Deliver one queued job to its subscription, verifying the endpoint first (if
	/// not already verified) and retrying with exponential backoff up to the bounded
	/// attempt count. The attempt count is persisted on the queued job, so a job
	/// re-leased after a crash resumes from where it left off and total attempts stay
	/// bounded across leases/nodes. The lease is renewed around each attempt. On
	/// success the subscription's watermark cursor advances; on exhaustion a signed
	/// `gap` envelope is posted so the client learns of the lost event. The job is
	/// acked (removed) only once its position is settled — success, 410/413
	/// abandonment, or after the gap signal — never on a mere transient failure (so
	/// it survives to be re-leased).
	private void deliverWithRetry(Delivery job) @safe
	{
		const subId = job.subscriptionId;
		const occ = job.occ;
		const leaseMs = opts_.deliveryLease.total!"msecs";
		auto s0 = webhookStore_.get(subId);
		if (s0.isNull)
		{
			deliveryQueue_.ack(job.jobId); // subscription gone; nothing to deliver
			return;
		}
		if (!s0.get.active)
		{
			// Delivery is suspended: leave the job queued (and immediately leasable)
			// so the refresh that reactivates the subscription resumes it.
			deliveryQueue_.touch(job.jobId, job.attempt, opts_.nowMs());
			return;
		}
		if (!ensureVerified(s0.get))
		{
			recordFailure(subId, DeliveryErrorCategory.challengeFailed);
			return; // not acked: the endpoint may verify before the next lease
		}
		// A body over the delivery-profile ceiling would be rejected with 413 by a
		// conformant receiver, so it is abandoned up front: its position settles
		// for the watermark and a gap envelope tells the client it was skipped.
		if (occ.toJson().toString().length > opts_.webhookMaxBodyBytes)
		{
			settlePosition(subId, occ.cursor);
			signalGap(s0.get, occ);
			deliveryQueue_.ack(job.jobId);
			return;
		}
		int attempt = job.attempt;
		for (;;)
		{
			attempt++;
			deliveryQueue_.touch(job.jobId, attempt, opts_.nowMs() + leaseMs);
			auto sn = webhookStore_.get(subId);
			if (sn.isNull)
			{
				deliveryQueue_.ack(job.jobId);
				return;
			}
			auto res = attemptDelivery(sn.get, occ);
			if (res.ok)
			{
				recordSuccess(subId, occ.cursor);
				deliveryQueue_.ack(job.jobId);
				return;
			}
			// A receiver that rejects with 410 Gone or 413 too-large does not want a
			// retry; abandon this event (its position is settled for the watermark).
			if (res.statusCode == 410 || res.statusCode == 413)
			{
				recordSuccess(subId, occ.cursor); // settled (abandoned), watermark advances
				deliveryQueue_.ack(job.jobId);
				return;
			}
			if (attempt >= opts_.webhookMaxAttempts)
			{
				const cat = res.error.isNull ? DeliveryErrorCategory.http5xx : res.error.get;
				recordFailure(subId, cat);
				settlePosition(subId, occ.cursor); // abandoned for watermark purposes
				signalGap(sn.get, occ); // tell the client the event was lost
				deliveryQueue_.ack(job.jobId);
				return;
			}
			opts_.deliverySleep(backoffFor(attempt));
			// Renew the lease after the inter-attempt sleep so a long retry loop never
			// lets its claim lapse (which would let a concurrent drain re-lease it).
			deliveryQueue_.renew(job.jobId, opts_.nowMs() + leaseMs);
		}
	}

	/// POST a signed `gap` control envelope to a subscription's callback so the
	/// client learns its watermark skipped `occ` (delivery was exhausted). Uses the
	/// same signing + SSRF-guarded path as a normal delivery.
	private void signalGap(WebhookSubscription sub, EventOccurrence occ) @safe
	{
		postGap(sub, occ.cursor.isNull ? "" : occ.cursor.get);
	}

	/// POST a signed `gap` control envelope carrying `cursor`, the fresh position
	/// the client should persist and treat as truncated.
	private void postGap(WebhookSubscription sub, string cursor) @safe
	{
		const 
		body = gapEnvelope(cursor).toString();
		const now = opts_.nowMs();
		auto headers = signDeliveryHeaders(sub.secret, sub.previousSecret,
				sub.previousSecretGraceUntilMs,
				now, controlMessageId("gap"), now / 1000, body, sub.id, opts_.v1aSigner);
		postToCallback(sub.url, headers, body);
	}

	/// Sign and POST one delivery attempt for `occ` to `sub`'s callback.
	private WebhookHttpResult attemptDelivery(WebhookSubscription sub, EventOccurrence occ) @safe
	{
		const 
		body = occ.toJson().toString();
		const now = opts_.nowMs();
		auto headers = signDeliveryHeaders(sub.secret, sub.previousSecret,
				sub.previousSecretGraceUntilMs,
				now, occ.eventId, now / 1000, body, sub.id, opts_.v1aSigner);
		return postToCallback(sub.url, headers, body);
	}

	/// Single chokepoint for every callback POST: a delivery-time SSRF host check
	/// (a non-globally-routable literal is rejected before any request leaves)
	/// ahead of the transport, which additionally pins the resolved IP.
	private WebhookHttpResult postToCallback(string url, string[string] headers, string body) @safe
	{
		import std.algorithm : startsWith;

		if (!callbackHostAllowed(url, opts_.allowPrivateCallbackHosts))
			return WebhookHttpResult.failure(DeliveryErrorCategory.connectionRefused);
		// Cleartext http is permitted only to a loopback/internal host (development);
		// a public host over http would leak the signed payload in cleartext, so it is
		// refused here even with the dev flag set — mirroring validateCallbackUrl.
		if (url.startsWith("http://") && !isInternalHttpHost(url))
			return WebhookHttpResult.failure(DeliveryErrorCategory.connectionRefused);
		return opts_.webhookTransport.post(url, headers, body, opts_.allowPrivateCallbackHosts);
	}

	/// Ensure the `(principal, url)` endpoint is verified before delivering.
	/// Verification is delivery-time-lazy: `events/subscribe` accepts a syntactically
	/// valid callback without a synchronous pre-flight, so it never raises the
	/// reserved `-32015 callbackEndpointError` itself. A callback that fails to verify
	/// or becomes unreachable is reflected after the fact in the subscription's
	/// `deliveryStatus` (`lastError`/`failedSince`, and `active=false` once suspended)
	/// — the delivery-time category surfaced to the client on its next refresh.
	/// An allowlist hit or a prior handshake (cached) passes immediately; otherwise a
	/// `verification` challenge is POSTed and the endpoint must echo the nonce. A
	/// negative cache backs off re-probing an endpoint that has not verified, so an
	/// unverified endpoint is not POSTed a fresh challenge on every matching emit
	/// (the window doubles per failure, capped) — bounding the verification flood an
	/// attacker-supplied unresponsive URL would otherwise drive.
	private bool ensureVerified(WebhookSubscription sub) @safe
	{
		if (sub.verified)
			return true;
		const key = sub.principal ~ "\0" ~ sub.url;
		if ((key in verifiedEndpoints_) !is null)
		{
			markVerified(sub.id);
			return true;
		}
		const now = opts_.nowMs();
		// A receiver that publishes its accepting paths at the callback origin has
		// already consented: no challenge POST is needed.
		if (opts_.wellKnownReceiverVerification && wellKnownCovers(sub.url, now))
		{
			verifiedEndpoints_[key] = true;
			pendingVerification_.remove(key);
			markVerified(sub.id);
			return true;
		}
		// Honour the negative-cache backoff: skip the probe (and the POST) until the
		// window elapses, so a never-verifying endpoint is not challenged every emit.
		if (auto b = key in pendingVerification_)
			if (now < b.nextProbeMs)
				return false;

		const nonce = randomNonce();
		const 
		body = verificationEnvelope(nonce).toString();
		auto headers = signDeliveryHeaders(sub.secret, "", 0, now,
				controlMessageId("verification"), now / 1000, body, sub.id, opts_.v1aSigner);
		auto res = postToCallback(sub.url, headers, body);
		if (res.ok && challengeEchoed(res.body, nonce))
		{
			verifiedEndpoints_[key] = true;
			pendingVerification_.remove(key);
			markVerified(sub.id);
			return true;
		}
		recordVerifyFailure(key, now);
		return false;
	}

	// Advance the verification negative-cache backoff for a `(principal, url)` after a
	// failed probe: the next probe is deferred by a window that doubles on each
	// successive failure, capped, so a persistently-unverified endpoint is probed at
	// an ever-decreasing rate rather than on every emit.
	private void recordVerifyFailure(string key, long now) @safe
	{
		import std.algorithm : min;

		long window = verifyBackoffBaseMs;
		if (auto b = key in pendingVerification_)
			window = min(b.windowMs * 2, verifyBackoffCapMs);
		pendingVerification_[key] = VerifyBackoff(now + window, window);
	}

	// Whether `url` falls under a path prefix its origin publishes in
	// `/.well-known/mcp-webhook-receiver.json`. The document is fetched over the
	// same SSRF-hardened path as deliveries and cached per origin (a missing or
	// malformed document is cached as "publishes none") for `wellKnownCacheTtl`,
	// so verifying many subscriptions against one gateway costs one GET.
	private bool wellKnownCovers(string url, long now) @safe
	{
		import std.algorithm : startsWith;

		string scheme, host, path;
		ushort port;
		bool hasUserinfo;
		if (!parseAuthority(url, scheme, host, port, path, hasUserinfo) || hasUserinfo)
			return false;
		import std.conv : to;

		const origin = scheme ~ "://" ~ host ~ ":" ~ port.to!string;
		auto entry = origin in wellKnown_;
		if (entry is null || now - entry.fetchedAtMs >= opts_.wellKnownCacheTtl.total!"msecs")
		{
			wellKnown_[origin] = WellKnownReceivers(fetchWellKnownReceivers(scheme, host, port), now);
			entry = origin in wellKnown_;
		}
		foreach (prefix; entry.prefixes)
			if (prefix.length && path.startsWith(prefix))
				return true;
		return false;
	}

	// GET the receiver document at the origin and return the prefixes it declares
	// (empty on any failure). The URL is rebuilt from parsed components, so the
	// fetch targets exactly the origin the callback resolves to.
	private string[] fetchWellKnownReceivers(string scheme, string host, ushort port) @safe
	{
		import std.conv : to;
		import vibe.data.json : parseJsonString;

		const docUrl = scheme ~ "://" ~ host ~ ":" ~ port.to!string ~ wellKnownReceiverPath;
		if (!callbackHostAllowed(docUrl, opts_.allowPrivateCallbackHosts))
			return null;
		WebhookHttpResult res;
		try
			res = opts_.webhookTransport.get(docUrl, opts_.allowPrivateCallbackHosts);
		catch (Exception)
			return null;
		if (!res.ok)
			return null;
		Json j;
		try
			j = parseJsonString(res.body);
		catch (Exception)
			return null;
		if (j.type != Json.Type.object || "receivers" !in j || j["receivers"].type != Json.Type.array)
			return null;
		string[] prefixes;
		foreach (i; 0 .. j["receivers"].length)
			if (j["receivers"][i].type == Json.Type.string)
				prefixes ~= j["receivers"][i].get!string;
		return prefixes;
	}

	/// Terminate a subscription (e.g. authorization revoked): POST a signed
	/// `terminated` control envelope to the callback, then drop the subscription.
	void terminateWebhook(string subId, Json error) @safe
	{
		auto sn = webhookStore_.get(subId);
		if (sn.isNull)
			return;
		auto sub = sn.get;
		const 
		body = terminatedEnvelope(error).toString();
		const now = opts_.nowMs();
		auto headers = signDeliveryHeaders(sub.secret, "", 0, now,
				controlMessageId("terminated"), now / 1000, body, sub.id, opts_.v1aSigner);
		opts_.deliveryExecutor(() @safe {
			postToCallback(sub.url, headers, body);
		});
		removeWebhookState(sub);
	}

	private void markVerified(string subId) @safe
	{
		auto sn = webhookStore_.get(subId);
		if (sn.isNull)
			return;
		auto sub = sn.get;
		if (!sub.verified)
		{
			sub.verified = true;
			webhookStore_.put(sub);
		}
	}

	private void recordSuccess(string subId, Nullable!string cursor) @safe
	{
		auto sn = webhookStore_.get(subId);
		if (sn.isNull)
			return;
		auto sub = sn.get;
		const now = opts_.nowMs();
		sub.lastDeliveryAtMs = now;
		sub.lastErrorCat = -1;
		sub.failedSinceMs = 0;
		rollWindow(sub, now);
		sub.windowAttempts++;
		clearExpiredRotation(sub, now);
		webhookStore_.put(sub);
		settlePosition(subId, cursor);
	}

	// Record a delivery at `cursor` as settled (acked or abandoned) and advance the
	// subscription's safe-to-persist watermark as far as the in-flight bookkeeping
	// allows: to a position only once every earlier position has settled, so an
	// out-of-order ack never lets the watermark skip an unacked event. A position
	// this node never tracked (a job enqueued on another node, or before a
	// restart) falls back to advancing when strictly ahead of the stored watermark.
	private void settlePosition(string subId, Nullable!string cursor) @safe
	{
		if (cursor.isNull)
			return;
		string[] safe;
		string candidate;
		if (settleOutstanding(subId, cursor.get, safe))
		{
			if (safe.length == 0)
				return; // an earlier position is still in flight
			candidate = safe[$ - 1];
		}
		else
			candidate = cursor.get;
		auto sn = webhookStore_.get(subId);
		if (sn.isNull)
			return;
		auto sub = sn.get;
		if (cursorAdvances(sub.cursor, candidate))
		{
			sub.cursor = candidate;
			webhookStore_.put(sub);
		}
	}

	// Note a delivery in flight at `cursor` for `subId`, in enqueue order.
	private void trackOutstanding(string subId, Nullable!string cursor) @safe
	{
		if (cursor.isNull)
			return;
		auto list = subId in outstanding_;
		if (list !is null && (*list).length && (*list)[$ - 1].cursor == cursor.get)
		{
			(*list)[$ - 1].remaining++;
			return;
		}
		outstanding_[subId] ~= OutstandingCursor(cursor.get, 1);
	}

	// Settle one in-flight delivery at `cursor`. Returns false when the position is
	// not tracked here; otherwise `safe` receives, in order, every position that
	// became safe to persist (possibly none, if an earlier one is still in flight).
	private bool settleOutstanding(string subId, string cursor, out string[] safe) @safe
	{
		auto list = subId in outstanding_;
		if (list is null)
			return false;
		size_t idx = size_t.max;
		foreach (i, ref e; *list)
			if (e.cursor == cursor)
			{
				idx = i;
				break;
			}
		if (idx == size_t.max)
			return false;
		(*list)[idx].remaining--;
		while ((*list).length && (*list)[0].remaining <= 0)
		{
			safe ~= (*list)[0].cursor;
			*list = (*list)[1 .. $];
		}
		if ((*list).length == 0)
			outstanding_.remove(subId);
		return true;
	}

	// Drop a rotated previous secret once its grace window has elapsed, so a
	// superseded secret is not retained indefinitely. Called opportunistically on
	// delivery; mutates `sub` in place (the caller persists it).
	private static void clearExpiredRotation(ref WebhookSubscription sub, long now) @safe
	{
		if (sub.previousSecret.length && now >= sub.previousSecretGraceUntilMs)
		{
			sub.previousSecret = "";
			sub.previousSecretGraceUntilMs = 0;
		}
	}

	// Whether `candidate` is strictly ahead of the stored watermark `current`, by
	// the ring-buffer sequence the cursors encode. An absent current advances to any
	// parseable candidate; a candidate that does not parse (e.g. a foreign cursor
	// scheme) is treated as advancing so author-supplied watermarks still settle.
	private bool cursorAdvances(Nullable!string current, string candidate) @safe
	{
		import mcp.server.event_store : tryParseSeq;

		if (current.isNull)
			return true;
		long curSeq, candSeq;
		if (!tryParseSeq(candidate, candSeq))
			return true;
		if (!tryParseSeq(current.get, curSeq))
			return true;
		return candSeq > curSeq;
	}

	private void recordFailure(string subId, DeliveryErrorCategory cat) @safe
	{
		auto sn = webhookStore_.get(subId);
		if (sn.isNull)
			return;
		auto sub = sn.get;
		const now = opts_.nowMs();
		sub.lastErrorCat = cast(int) cat;
		if (sub.failedSinceMs == 0)
			sub.failedSinceMs = now;
		rollWindow(sub, now);
		sub.windowAttempts++;
		sub.windowFailures++;
		const policy = opts_.webhookSuspension;
		if (policy.minAttempts > 0 && sub.windowAttempts >= policy.minAttempts
				&& sub.windowFailures * 100L >= sub.windowAttempts * cast(long) policy.failureRatePercent)
			sub.active = false;
		webhookStore_.put(sub);
	}

	// Start a fresh failure-rate sample window once the current one has elapsed
	// (a tumbling window: cheap, persisted in three fields, and a close enough
	// reading of "rolling" for a suspension heuristic).
	private void rollWindow(ref WebhookSubscription sub, long now) @safe
	{
		const windowMs = opts_.webhookSuspension.window.total!"msecs";
		if (sub.windowStartMs == 0 || now - sub.windowStartMs >= windowMs)
		{
			sub.windowStartMs = now;
			sub.windowAttempts = 0;
			sub.windowFailures = 0;
		}
	}

	private Duration backoffFor(int attempt) @safe
	{
		// Exponential: base * 2^(attempt-1).
		long mult = 1;
		foreach (_; 1 .. attempt)
			mult *= 2;
		return opts_.webhookRetryBase * mult;
	}

	/// The JWKS document for server-identity (`v1a,`) verification, published at
	/// `/.well-known/mcp-webhook-jwks.json`. Empty until a signing key is set.
	Json webhookJwks() @safe
	{
		return (opts_.webhookSigningJwks.type == Json.Type.object) ? opts_.webhookSigningJwks
			: Json.emptyObject;
	}

	private void stamp(ref EventOccurrence occ) @safe
	{
		if (occ.eventId.length == 0)
			occ.eventId = randomEventId();
		if (occ.timestamp.length == 0)
			occ.timestamp = opts_.nowIso();
	}

	private void touchPollLease(ref EventRegistration reg, string name,
			Json arguments, string principal) @safe
	{
		const key = leaseKey(name, arguments, principal);
		const now = opts_.nowMs();
		const fresh = (key in pollLeases_) is null;
		const subId = pollSubscriptionId(name, arguments);
		pollLeases_[key] = PollLease(name, principal, arguments, subId,
				now + opts_.pollLeaseTtl.total!"msecs");
		if (fresh)
			acquireLifecycle(reg, name, arguments, principal, subId);
	}

	// Acquire a lifecycle reference for `(principal, name, arguments)`. `onSubscribe`
	// fires only on the 0->1 transition, so the author provisions the upstream
	// source once however many poll/stream/webhook subscriptions share the key.
	private void acquireLifecycle(ref EventRegistration reg, string name,
			Json arguments, string principal, string subId) @safe
	{
		const key = leaseKey(name, arguments, principal);
		if (auto p = key in lifeRefs_)
		{
			p.refs++;
			return;
		}
		lifeRefs_[key] = LifeRef(1, name, principal, arguments, subId);
		fireLifecycle(reg.onSubscribe, arguments, principal, subId);
	}

	// Release a lifecycle reference; `onUnsubscribe` fires on the 1->0 transition.
	private void releaseLifecycle(string name, Json arguments, string principal) @safe
	{
		const key = leaseKey(name, arguments, principal);
		auto p = key in lifeRefs_;
		if (p is null)
			return;
		p.refs--;
		if (p.refs > 0)
			return;
		const rec = *p;
		lifeRefs_.remove(key);
		auto reg = name in types_;
		if (reg !is null)
			fireLifecycle(reg.onUnsubscribe, rec.arguments, rec.principal, rec.subscriptionId);
	}

	private void fireLifecycle(EventLifecycle hook, Json arguments,
			string principal, string subscriptionId) @safe
	{
		if (hook is null)
			return;
		auto ctx = new EventContext(Nullable!string.init, arguments, principal);
		hook(ctx, subscriptionId);
	}

	private string leaseKey(string name, Json arguments, string principal) @safe
	{
		return principal ~ "\0" ~ name ~ "\0" ~ canonicalJsonString(arguments);
	}

	private string pollSubscriptionId(string name, Json arguments) @safe
	{
		return "poll_" ~ sha256Hex(name ~ "\0" ~ canonicalJsonString(arguments))[0 .. 16];
	}
}

/// A stable, key-sorted serialization of `j`, so two semantically-equal JSON
/// values (objects differing only in key order) produce the same string — used
/// for argument equality in subscription keys and lease keys.
string canonicalJsonString(Json j) @safe
{
	import std.array : appender;

	auto a = appender!string();
	writeCanonical(a, j);
	return a.data;
}

private void writeCanonical(R)(ref R sink, Json j) @safe
{
	import std.array : array;
	import std.algorithm : sort, map;
	import std.conv : to;

	final switch (j.type)
	{
	case Json.Type.undefined:
	case Json.Type.null_:
		sink.put("null");
		break;
	case Json.Type.bool_:
		sink.put(j.get!bool ? "true" : "false");
		break;
	case Json.Type.int_:
		sink.put(to!string(j.get!long));
		break;
	case Json.Type.bigInt:
		sink.put(j.toString());
		break;
	case Json.Type.float_:
		sink.put(to!string(j.get!double));
		break;
	case Json.Type.string:
		sink.put(Json(j.get!string).toString()); // properly escaped
		break;
	case Json.Type.array:
		sink.put('[');
		foreach (i; 0 .. j.length)
		{
			if (i)
				sink.put(',');
			writeCanonical(sink, j[i]);
		}
		sink.put(']');
		break;
	case Json.Type.object:
		string[] keys;
		() @trusted {
			foreach (string k, Json v; cast() j)
				keys ~= k;
		}();
		keys.sort();
		sink.put('{');
		foreach (i, k; keys)
		{
			if (i)
				sink.put(',');
			sink.put(Json(k).toString());
			sink.put(':');
			writeCanonical(sink, j[k]);
		}
		sink.put('}');
		break;
	}
}

/// Lowercase hex SHA-256 of `s`. Used to derive stable subscription/lease ids.
string sha256Hex(string s) @safe
{
	import std.digest.sha : sha256Of;
	import std.digest : toHexString, LetterCase;
	import std.string : representation;

	auto digest = sha256Of(s.representation);
	return toHexString!(LetterCase.lower)(digest).idup;
}

version (MCPWebhookEd25519)
{
	/// Build the server-identity JWKS (one OKP Ed25519 key) published at
	/// `/.well-known/mcp-webhook-jwks.json`, from a `whpk_`-prefixed public key.
	private Json ed25519Jwks(string whpk) @safe
	{
		import std.base64 : Base64, Base64URLNoPadding;
		import std.string : startsWith;

		ubyte[] pub;
		if (whpk.startsWith("whpk_"))
			pub = Base64.decode(whpk["whpk_".length .. $]);
		Json jwk = Json.emptyObject;
		jwk["kty"] = "OKP";
		jwk["crv"] = "Ed25519";
		jwk["alg"] = "EdDSA";
		jwk["use"] = "sig";
		jwk["x"] = Base64URLNoPadding.encode(pub).idup;
		jwk["kid"] = sha256Hex(whpk)[0 .. 16];
		Json keys = Json.emptyArray;
		keys ~= jwk;
		Json set = Json.emptyObject;
		set["keys"] = keys;
		return set;
	}
}

/// 32 hex chars of CSPRNG bytes, the default `eventId` when the author supplies none.
string randomEventId() @safe
{
	import mcp.auth.csprng : cryptoRandomBytes;
	import std.digest : toHexString, LetterCase;

	return "evt_" ~ toHexString!(LetterCase.lower)(cryptoRandomBytes(16)).idup;
}

/// A single-use, short-lived hex nonce for an endpoint-verification challenge.
string randomNonce() @safe
{
	import mcp.auth.csprng : cryptoRandomBytes;
	import std.digest : toHexString, LetterCase;

	return toHexString!(LetterCase.lower)(cryptoRandomBytes(16)).idup;
}

/// The `webhook-id` of a control envelope: `msg_<type>_<random>`, so a receiver
/// can dedup a retried envelope without confusing it with an event delivery.
string controlMessageId(string type) @safe
{
	return "msg_" ~ type ~ "_" ~ randomNonce();
}

/// The subscription id as a string, whether the JSON-RPC id was an integer or a
/// string (used to label lifecycle-hook invocations).
string subscriptionIdString(Json id) @safe
{
	import std.conv : to;

	if (id.type == Json.Type.string)
		return id.get!string;
	if (id.type == Json.Type.int_)
		return to!string(id.get!long);
	return id.toString();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

version (unittest)
{
	import std.conv : to;

	// Build a runtime with deterministic clocks for tests.
	private EventsRuntime testRuntime(long delegate() @safe nowMs = null) @safe
	{
		EventsOptions o;
		long t = 1_000_000;
		o.nowMs = (nowMs is null) ? (() @safe => t) : nowMs;
		o.nowIso = () @safe => "2026-02-19T15:30:00Z";
		return new EventsRuntime(null, o);
	}
}

unittest  // canonicalJsonString is key-order independent
{
	auto a = canonicalJsonString(Json(["b": Json(1), "a": Json(2)]));
	auto b = canonicalJsonString(Json(["a": Json(2), "b": Json(1)]));
	assert(a == b);
	assert(a == `{"a":2,"b":1}`);
}

unittest  // sha256Hex is stable and lowercase hex
{
	auto h = sha256Hex("abc");
	assert(h.length == 64);
	assert(h == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

unittest  // controlMessageId is msg_<type>_<random> and unique per call
{
	import std.algorithm : startsWith;

	auto a = controlMessageId("gap");
	auto b = controlMessageId("gap");
	assert(a.startsWith("msg_gap_") && a.length == "msg_gap_".length + 32);
	assert(a != b);
}

unittest  // randomEventId is prefixed and unique
{
	auto a = randomEventId();
	auto b = randomEventId();
	assert(a.length > 4 && a[0 .. 4] == "evt_");
	assert(a != b);
}

unittest  // effectiveDelivery lists poll/push/webhook minus author-disabled modes
{
	auto rt = testRuntime();
	EventRegistration reg;
	reg.descriptor.name = "x";
	reg.disabledModes = [DeliveryMode.webhook];
	rt.register(reg);
	auto modes = rt.effectiveDelivery("x");
	assert(modes.length == 2);
	assert(modes[0] == DeliveryMode.poll && modes[1] == DeliveryMode.push);
}

unittest  // EventHandle.disable opts a typed event out of a delivery mode
{
	auto rt = testRuntime();
	rt.define!(DemoArgs, DemoPayload)("x").disable(DeliveryMode.poll);
	auto modes = rt.effectiveDelivery("x");
	assert(modes.length == 2);
	assert(modes[0] == DeliveryMode.push && modes[1] == DeliveryMode.webhook);
}

unittest  // EventHandle.webhookOnly leaves only webhook delivery
{
	auto rt = testRuntime();
	rt.define!(DemoArgs, DemoPayload)("x").webhookOnly();
	auto modes = rt.effectiveDelivery("x");
	assert(modes == [DeliveryMode.webhook]);
}

unittest  // EventsOptions.disabledModes applies server-wide, intersected with per-event
{
	EventsOptions o;
	o.nowMs = () @safe => 1_000_000L;
	o.nowIso = () @safe => "2026-02-19T15:30:00Z";
	o.disabledModes = [DeliveryMode.push]; // server policy: no push for any type
	auto rt = new EventsRuntime(null, o);

	EventRegistration a;
	a.descriptor.name = "a";
	rt.register(a);
	assert(rt.effectiveDelivery("a") == [
		DeliveryMode.poll, DeliveryMode.webhook
	]);

	EventRegistration b;
	b.descriptor.name = "b";
	b.disabledModes = [DeliveryMode.webhook]; // per-event narrows further
	rt.register(b);
	assert(rt.effectiveDelivery("b") == [DeliveryMode.poll]);
}

unittest  // list returns registered types sorted by name with computed delivery
{
	auto rt = testRuntime();
	EventRegistration a;
	a.descriptor.name = "b.event";
	EventRegistration b;
	b.descriptor.name = "a.event";
	rt.register(a);
	rt.register(b);
	auto r = rt.list();
	assert(r.events.length == 2);
	assert(r.events[0].name == "a.event" && r.events[1].name == "b.event");
	assert(r.events[0].delivery.length >= 1);
}

unittest  // poll on an unknown event type throws NotFound
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto rt = testRuntime();
	assertThrown!McpException(rt.poll("nope", Json.emptyObject, "",
			Nullable!string.init, Nullable!long.init, Nullable!long.init));
}

unittest  // poll carries nextPollMs even when hasMore requests an immediate re-poll
{
	auto rt = testRuntime();
	EventRegistration reg;
	reg.descriptor.name = "email.received";
	reg.check = (EventContext ctx) @safe {
		return EventResult.of([EventOccurrence("e1", "email.received", "t")], "c1", false, true);
	};
	rt.register(reg);
	auto r = rt.poll("email.received", Json.emptyObject, "", nullable("c0"),
			Nullable!long.init, Nullable!long.init);
	assert(r.hasMore);
	assert(r.nextPollMs == 30_000);
}

unittest  // poll runs a check function and returns its events + nextPollMs
{
	auto rt = testRuntime();
	EventRegistration reg;
	reg.descriptor.name = "email.received";
	reg.check = (EventContext ctx) @safe {
		if (ctx.isBootstrap())
			return EventResult.empty("c0");
		return EventResult.of([EventOccurrence("e1", "email.received", "t")], "c1");
	};
	rt.register(reg);

	auto boot = rt.poll("email.received", Json.emptyObject, "",
			Nullable!string.init, Nullable!long.init, Nullable!long.init);
	assert(boot.events.length == 0 && boot.cursor.get == "c0");
	assert(boot.nextPollMs == 30_000); // default poll interval

	auto next = rt.poll("email.received", Json.emptyObject, "", nullable("c0"),
			Nullable!long.init, Nullable!long.init);
	assert(next.events.length == 1 && next.cursor.get == "c1");
}

unittest  // emit-only poll reads the ring buffer
{
	auto rt = testRuntime();
	EventRegistration reg;
	reg.descriptor.name = "incident.created";
	reg.emitOnly = true;
	rt.register(reg);

	auto boot = rt.poll("incident.created", Json.emptyObject, "",
			Nullable!string.init, Nullable!long.init, Nullable!long.init);
	rt.emit(EventOccurrence("", "incident.created", "", Json([
		"severity": Json("P1")
	])));
	auto next = rt.poll("incident.created", Json.emptyObject, "", boot.cursor,
			Nullable!long.init, Nullable!long.init);
	assert(next.events.length == 1);
	assert(next.events[0].data["severity"].get!string == "P1");
	// emit() stamped an eventId and timestamp
	assert(next.events[0].eventId.length > 0 && next.events[0].timestamp.length > 0);
}

unittest  // emit fans out to a matching push stream
{
	auto rt = testRuntime();
	EventRegistration reg;
	reg.descriptor.name = "incident.created";
	reg.emitOnly = true;
	rt.register(reg);

	string deliveredMethod;
	Json deliveredParams;
	auto handle = rt.openPushStream("incident.created", Json.emptyObject,
			"user-1", Json(1), (string method, Json params) @safe {
		deliveredMethod = method;
		deliveredParams = params;
	});
	rt.emit(EventOccurrence("evt1", "incident.created", "t", Json(["x": Json(1)])));
	assert(deliveredMethod == eventsEventNotification);
	assert(deliveredParams["eventId"].get!string == "evt1");
	// the subscription id is carried in _meta
	assert(deliveredParams["_meta"][subscriptionIdMetaKey].get!int == 1);
	handle.close();
}

unittest  // advancePushStream delivers a recoverable error frame when the check throws, and stays open
{
	auto rt = testRuntime();
	bool fail = true;
	EventRegistration reg;
	reg.descriptor.name = "email.received";
	reg.check = (EventContext ctx) @safe {
		if (fail)
			throw new Exception("Gmail API 503");
		return EventResult.of([EventOccurrence("m1", "email.received", "t")], "c1");
	};
	rt.register(reg);
	string[] methods;
	Json[] params;
	auto handle = rt.openPushStream("email.received", Json.emptyObject, "u", Json(7),
			(string m, Json p) @safe { methods ~= m; params ~= p; });
	rt.advancePushStream(handle.stream);
	assert(methods == [eventsErrorNotification]);
	assert(params[0]["error"]["code"].get!int == -32603);
	assert(params[0]["error"]["message"].get!string == "Gmail API 503");
	assert(params[0]["_meta"][subscriptionIdMetaKey].get!int == 7);
	fail = false;
	rt.advancePushStream(handle.stream); // still open: the next advance delivers
	assert(methods[$ - 1] == eventsEventNotification);
	assert(handle.stream.cursor.get == "c1");
	handle.close();
}

unittest  // advancePushStream re-sends active{truncated:true} with the fresh cursor on a gap
{
	auto rt = testRuntime();
	EventRegistration reg;
	reg.descriptor.name = "email.received";
	reg.check = (EventContext ctx) @safe {
		return EventResult.of([EventOccurrence("m9", "email.received", "t")], "c9", true);
	};
	rt.register(reg);
	string[] methods;
	Json[] params;
	auto handle = rt.openPushStream("email.received", Json.emptyObject, "u", Json(1),
			(string m, Json p) @safe { methods ~= m; params ~= p; });
	rt.advancePushStream(handle.stream);
	assert(methods == [eventsActiveNotification, eventsEventNotification]);
	assert(params[0]["truncated"].get!bool && params[0]["cursor"].get!string == "c9");
	handle.close();
}

unittest  // terminatePush sends a terminated frame, releases the subscription, and runs the transport hook
{
	auto rt = testRuntime();
	int unsubs;
	EventRegistration reg;
	reg.descriptor.name = "incident.created";
	reg.emitOnly = true;
	reg.onUnsubscribe = (EventContext ctx, string id) @safe { unsubs++; };
	rt.register(reg);
	string[] methods;
	Json[] params;
	auto handle = rt.openPushStream("incident.created", Json.emptyObject, "u", Json(3),
			(string m, Json p) @safe { methods ~= m; params ~= p; });
	bool hooked;
	handle.stream.onTerminated = () @safe { hooked = true; };
	rt.terminatePush(handle.stream, toErrorJson(forbidden("Access revoked")));
	assert(methods == [eventsTerminatedNotification]);
	assert(params[0]["error"]["code"].get!int == -32012);
	assert(params[0]["_meta"][subscriptionIdMetaKey].get!int == 3);
	assert(unsubs == 1 && hooked && handle.stream.terminated);
	rt.emit(EventOccurrence("evt", "incident.created", "t"));
	assert(methods.length == 1); // nothing further is delivered
	rt.terminatePush(handle.stream, Json.emptyObject); // idempotent
	assert(methods.length == 1 && unsubs == 1);
}

unittest  // terminateEventType ends push streams and webhook subscriptions for the type
{
	auto ft = new FakeWebhookTransport();
	auto rt = engineRuntime(ft);
	string[] methods;
	auto handle = rt.openPushStream("n", Json.emptyObject, "u", Json(1),
			(string m, Json p) @safe { methods ~= m; });
	auto r = rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	rt.terminateEventType("n", toErrorJson(notFound("removed", "event")));
	assert(methods == [eventsTerminatedNotification]);
	assert(rt.webhookStore().get(r.id).isNull);
	auto terms = controlPostsOf(ft, "terminated");
	assert(terms.length == 1);
	assert(parseJsonString(terms[0].body)["error"]["data"]["kind"].get!string == "event");
}

unittest  // terminatePrincipal ends only that principal's subscriptions
{
	auto rt = testRuntime();
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	string[] a, b;
	rt.openPushStream("n", Json.emptyObject, "alice", Json(1), (string m, Json p) @safe { a ~= m; });
	rt.openPushStream("n", Json.emptyObject, "bob", Json(2), (string m, Json p) @safe { b ~= m; });
	rt.terminatePrincipal("alice", "", toErrorJson(forbidden("revoked")));
	assert(a == [eventsTerminatedNotification]);
	assert(b.length == 0);
	rt.emit(EventOccurrence("evt", "n", "t"));
	assert(a.length == 1 && b.length == 1); // bob still receives
}

unittest  // a closed push stream no longer receives events
{
	auto rt = testRuntime();
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	int count;
	auto handle = rt.openPushStream("n", Json.emptyObject, "", Json(1), (string m, Json p) @safe {
		count++;
	});
	rt.emit(EventOccurrence("a", "n", "t"));
	handle.close();
	rt.emit(EventOccurrence("b", "n", "t"));
	assert(count == 1);
}

unittest  // broadcast match/transform shape per-subscription push delivery
{
	auto rt = testRuntime();
	EventRegistration reg;
	reg.descriptor.name = "incident.created";
	reg.emitOnly = true;
	reg.match = (EventContext ctx, EventOccurrence ev) @safe {
		auto want = ctx.arguments["severity"];
		return want.type != Json.Type.string || ev.data["severity"].get!string == want.get!string;
	};
	reg.transform = (EventContext ctx, EventOccurrence ev) @safe {
		ev.data["shaped"] = true;
		return ev;
	};
	rt.register(reg);

	int p1Count, p2Count;
	rt.openPushStream("incident.created", Json(["severity": Json("P1")]), "u",
			Json(1), (string m, Json params) @safe {
		p1Count++;
		assert(params["data"]["shaped"].get!bool);
	});
	rt.openPushStream("incident.created", Json(["severity": Json("P2")]), "u",
			Json(2), (string m, Json p) @safe { p2Count++; });

	rt.emit(EventOccurrence("e", "incident.created", "t", Json([
		"severity": Json("P1")
	])));
	assert(p1Count == 1 && p2Count == 0); // only the P1 subscription matched
}

unittest  // targeted emit delivers to a single subscription by id
{
	auto rt = testRuntime();
	EventRegistration reg = {
		descriptor: EventType("slack.message"), emitOnly: true
	};
	rt.register(reg);
	int s1, s2;
	rt.openPushStream("slack.message", Json.emptyObject, "u", Json(1), (string m, Json p) @safe {
		s1++;
	});
	rt.openPushStream("slack.message", Json.emptyObject, "u", Json(2), (string m, Json p) @safe {
		s2++;
	});
	rt.emit(EventOccurrence("e", "slack.message", "t"), Json(2));
	assert(s1 == 0 && s2 == 1);
}

unittest  // emit does not pollute a check-backed type's push-stream cursor with a buffer seq
{
	auto rt = testRuntime();
	EventRegistration reg;
	reg.descriptor.name = "email.received";
	// A check-backed type owns a "c<n>" cursor scheme, not a ring-buffer seq.
	reg.check = (EventContext ctx) @safe => EventResult.empty("c-author");
	rt.register(reg);

	auto handle = rt.openPushStream("email.received", Json.emptyObject, "u",
			Json(1), (string m, Json p) @safe {});
	// Seed the stream with the author's own cursor, as the leading poll would.
	handle.stream.cursor = nullable("c-author");
	rt.emit(EventOccurrence("e1", "email.received", "t"));
	// The stream cursor must still be the author cursor, never a numeric buffer seq,
	// so the stdio ticker resumes the author's check() correctly.
	assert(handle.stream.cursor.get == "c-author");
	handle.close();
}

unittest  // a throwing push stream neither aborts a sibling stream nor the webhook enqueue
{
	auto ft = new FakeWebhookTransport();
	auto rt = engineRuntime(ft); // registers emit-only type "n", webhook enabled
	rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");

	bool siblingGotEvent;
	// A disconnected subscriber whose deliver throws.
	rt.openPushStream("n", Json.emptyObject, "u", Json(1), (string m, Json p) @safe {
		throw new Exception("client disconnected");
	});
	rt.openPushStream("n", Json.emptyObject, "u", Json(2), (string m, Json p) @safe {
		siblingGotEvent = true;
	});

	rt.emit(EventOccurrence("evt_1", "n", "t", Json(["x": Json(1)])));
	// The throwing stream did not stop the sibling from receiving the event ...
	assert(siblingGotEvent);
	// ... nor the webhook engine from enqueuing+delivering (verification + event POST).
	assert(ft.eventPosts().length == 1);
}

unittest  // poll lease fires on_subscribe on first sight and on_unsubscribe on expiry
{
	long now = 1_000_000;
	auto rt = testRuntime(() @safe => now);
	int subs, unsubs;
	EventRegistration reg;
	reg.descriptor.name = "slack.message";
	reg.check = (EventContext ctx) @safe => EventResult.empty("c");
	reg.onSubscribe = (EventContext ctx, string id) @safe { subs++; };
	reg.onUnsubscribe = (EventContext ctx, string id) @safe { unsubs++; };
	rt.register(reg);

	auto args = Json(["channel": Json("general")]);
	rt.poll("slack.message", args, "u", Nullable!string.init,
			Nullable!long.init, Nullable!long.init);
	rt.poll("slack.message", args, "u", nullable("c"), Nullable!long.init, Nullable!long.init);
	assert(subs == 1 && unsubs == 0); // one subscribe, renewed not re-fired

	now += 10 * 60 * 1000; // advance past the 5-minute lease
	rt.sweepPollLeases();
	assert(unsubs == 1);
}

unittest  // lifecycle is refcounted across modes: fires once per (principal,name,args)
{
	long now = 1_000_000;
	auto rt = testRuntime(() @safe => now);
	int subs, unsubs;
	EventRegistration reg;
	reg.descriptor.name = "slack.message";
	reg.emitOnly = true;
	reg.onSubscribe = (EventContext ctx, string id) @safe { subs++; };
	reg.onUnsubscribe = (EventContext ctx, string id) @safe { unsubs++; };
	rt.register(reg);

	auto args = Json(["channel": Json("general")]);
	// two push streams with the same (principal, args), plus a poll — one upstream.
	auto h1 = rt.openPushStream("slack.message", args, "u", Json(1), (string m, Json p) @safe {
	});
	auto h2 = rt.openPushStream("slack.message", args, "u", Json(2), (string m, Json p) @safe {
	});
	rt.poll("slack.message", args, "u", Nullable!string.init,
			Nullable!long.init, Nullable!long.init);
	assert(subs == 1 && unsubs == 0); // onSubscribe fired once at 0->1

	h1.close();
	assert(unsubs == 0); // streams + poll lease still hold refs
	h2.close();
	assert(unsubs == 0); // the poll lease still holds a ref
	now += 10 * 60 * 1000;
	rt.sweepPollLeases();
	assert(unsubs == 1); // onUnsubscribe fires once at 1->0
}

unittest  // notifyListChanged invokes the registered callback
{
	auto rt = testRuntime();
	int n;
	rt.onListChanged(() @safe { n++; });
	rt.notifyListChanged();
	assert(n == 1);
}

version (unittest)
{
	private struct DemoArgs
	{
		string severity;
	}

	private struct DemoPayload
	{
		string id;
		string severity;
	}
}

unittest  // typed define derives input + payload schemas from A and P
{
	auto rt = testRuntime();
	rt.define!(DemoArgs, DemoPayload)("incident.created", "An incident");
	auto t = rt.list().events[0];
	assert(t.name == "incident.created");
	assert(t.inputSchema.type == Json.Type.object);
	assert(("severity" in t.inputSchema["properties"]) !is null);
	assert(t.payloadSchema.type == Json.Type.object);
	assert(("id" in t.payloadSchema["properties"]) !is null);
}

unittest  // typed publish marshals the payload and fans out to a push stream
{
	auto rt = testRuntime();
	auto ev = rt.define!(DemoArgs, DemoPayload)("incident.created");
	Json delivered;
	rt.openPushStream("incident.created", Json.emptyObject, "u", Json(1),
			(string m, Json params) @safe { delivered = params; });
	ev.publish(DemoPayload("INC-1", "P1"));
	assert(delivered["data"]["id"].get!string == "INC-1");
	assert(delivered["data"]["severity"].get!string == "P1");
}

unittest  // typed publish(payload, id, timestamp) preserves an upstream identity
{
	auto rt = testRuntime();
	auto ev = rt.define!(DemoArgs, DemoPayload)("incident.created");
	Json delivered;
	rt.openPushStream("incident.created", Json.emptyObject, "u", Json(1),
			(string m, Json params) @safe { delivered = params; });
	ev.publish(DemoPayload("INC-1", "P1"), "upstream-42", "2026-02-19T15:30:00Z");
	assert(delivered["eventId"].get!string == "upstream-42");
	assert(delivered["timestamp"].get!string == "2026-02-19T15:30:00Z");
	assert(delivered["data"]["id"].get!string == "INC-1");
}

unittest  // fromPayload stamps the event name so the occurrence is routable
{
	auto rt = testRuntime();
	auto ev = rt.define!(DemoArgs, DemoPayload)("incident.created");
	auto occ = ev.fromPayload(DemoPayload("INC-1", "P1"));
	assert(occ.name == "incident.created");
	assert(occ.data["id"].get!string == "INC-1");
}

unittest  // typed onFetch backs events/poll with strongly-typed events
{
	auto rt = testRuntime();
	auto ev = rt.define!(DemoArgs, DemoPayload)("incident.created");
	ev.onFetch((DemoArgs args, scope FetchContext ctx) @safe {
		if (ctx.isBootstrap)
			return EventBatch!DemoPayload.empty("c0");
		return EventBatch!DemoPayload.of([
			Event!DemoPayload(DemoPayload("INC-1", args.severity), "c1")
		], "c1");
	});

	auto args = Json(["severity": Json("P1")]);
	auto boot = rt.poll("incident.created", args, "", Nullable!string.init,
			Nullable!long.init, Nullable!long.init);
	assert(boot.events.length == 0 && boot.cursor.get == "c0");

	auto next = rt.poll("incident.created", args, "", nullable("c0"),
			Nullable!long.init, Nullable!long.init);
	assert(next.events.length == 1);
	assert(next.events[0].data["id"].get!string == "INC-1");
	assert(next.events[0].data["severity"].get!string == "P1");
	assert(next.events[0].eventId.length > 0); // stamped
}

unittest  // typed match filters typed publish fan-out per subscription
{
	auto rt = testRuntime();
	auto ev = rt.define!(DemoArgs, DemoPayload)("incident.created");
	ev.match((DemoArgs args, DemoPayload p) @safe {
		return args.severity.length == 0 || p.severity == args.severity;
	});
	int p1, p2;
	rt.openPushStream("incident.created", Json(["severity": Json("P1")]), "u",
			Json(1), (string m, Json params) @safe { p1++; });
	rt.openPushStream("incident.created", Json(["severity": Json("P2")]), "u",
			Json(2), (string m, Json params) @safe { p2++; });
	ev.publish(DemoPayload("INC-1", "P1"));
	assert(p1 == 1 && p2 == 0);
}

unittest  // typed transform shapes the delivered payload per subscription
{
	auto rt = testRuntime();
	auto ev = rt.define!(DemoArgs, DemoPayload)("incident.created");
	// Redact the severity for a subscriber that did not ask for it.
	ev.transform((DemoArgs args, DemoPayload p) @safe {
		if (args.severity.length == 0)
			p.severity = "redacted";
		return ev.fromPayload(p);
	});
	Json delivered;
	rt.openPushStream("incident.created", Json.emptyObject, "u", Json(1),
			(string m, Json params) @safe { delivered = params; });
	ev.publish(DemoPayload("INC-1", "P1"));
	// The shaped payload is delivered; the runtime-owned identity fields survive.
	assert(delivered["data"]["id"].get!string == "INC-1");
	assert(delivered["data"]["severity"].get!string == "redacted");
	assert(delivered["eventId"].get!string.length > 0);
	assert(delivered["name"].get!string == "incident.created");
}

version (unittest)
{
	private enum Severity
	{
		low,
		high
	}

	private struct EnumArgs
	{
		Severity minSeverity;
	}

	private struct EnumPayload
	{
		string id;
		Severity severity;
	}
}

unittest  // enum fields in A and P round-trip by NAME across poll/publish/match
{
	auto rt = testRuntime();
	auto ev = rt.define!(EnumArgs, EnumPayload)("alert.raised");

	// The derived schemas advertise enums as string member names.
	auto t = rt.list().events[0];
	assert(t.inputSchema["properties"]["minSeverity"]["type"].get!string == "string");
	assert(t.payloadSchema["properties"]["severity"]["type"].get!string == "string");

	// A typed match reads both the args enum and the payload enum; publish marshals
	// the payload enum by name; poll/onFetch read the args enum by name.
	ev.match((EnumArgs args, EnumPayload p) @safe {
		return p.severity >= args.minSeverity;
	});

	int high, low;
	rt.openPushStream("alert.raised", Json(["minSeverity": Json("high")]), "u",
			Json(1), (string m, Json params) @safe {
		high++;
		// the payload enum is delivered as its name, matching the schema
		assert(params["data"]["severity"].get!string == "high");
	});
	rt.openPushStream("alert.raised", Json(["minSeverity": Json("low")]), "u",
			Json(2), (string m, Json params) @safe { low++; });

	ev.publish(EnumPayload("INC-1", Severity.high));
	// the high payload clears both subscriptions' thresholds
	assert(high == 1 && low == 1);

	// A low-severity payload is filtered out of the high-threshold subscription.
	ev.publish(EnumPayload("INC-2", Severity.low));
	assert(high == 1 && low == 2);
}

unittest  // typed onFetch reads an enum arg by name and emits an enum payload by name
{
	auto rt = testRuntime();
	auto ev = rt.define!(EnumArgs, EnumPayload)("alert.raised");
	ev.onFetch((EnumArgs args, scope FetchContext ctx) @safe {
		if (ctx.isBootstrap)
			return EventBatch!EnumPayload.empty("c0");
		return EventBatch!EnumPayload.of([
			Event!EnumPayload(EnumPayload("INC-1", args.minSeverity), "c1")
		], "c1");
	});

	auto args = Json(["minSeverity": Json("high")]);
	rt.poll("alert.raised", args, "", Nullable!string.init,
			Nullable!long.init, Nullable!long.init);
	auto next = rt.poll("alert.raised", args, "", nullable("c0"),
			Nullable!long.init, Nullable!long.init);
	assert(next.events.length == 1);
	// the enum arg was read by name and the enum payload emitted by name
	assert(next.events[0].data["severity"].get!string == "high");
}

unittest  // openPushStream throws Unsupported when push is disabled for the type
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto rt = testRuntime();
	EventRegistration reg;
	reg.descriptor.name = "x";
	reg.emitOnly = true;
	reg.disabledModes = [DeliveryMode.push];
	rt.register(reg);
	assertThrown!McpException(rt.openPushStream("x", Json.emptyObject, "",
			Json(1), (string m, Json p) @safe {}));
}

version (unittest)
{
	// A syntactically valid whsec_ secret: "whsec_" + base64 of 32 zero bytes.
	private enum testSecret = "whsec_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

	private SubscribeParams webhookSub(string name, string url, Json args = Json.emptyObject) @safe
	{
		SubscribeParams p;
		p.name = name;
		p.arguments = args;
		p.delivery = WebhookDelivery(url, testSecret);
		return p;
	}
}

unittest  // subscribeWebhook requires an authenticated principal
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto rt = testRuntime();
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	assertThrown!McpException(rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), ""));
}

unittest  // subscribeWebhook rejects a non-https callback URL
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto rt = testRuntime();
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	assertThrown!McpException(rt.subscribeWebhook(webhookSub("n", "http://proxy/hooks"), "user-1"));
}

unittest  // subscribeWebhook rejects a malformed whsec_ secret
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto rt = testRuntime();
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	SubscribeParams p;
	p.name = "n";
	p.delivery = WebhookDelivery("https://proxy/hooks", "not-a-whsec");
	assertThrown!McpException(rt.subscribeWebhook(p, "user-1"));
}

unittest  // subscribeWebhook grants a finite refreshBefore and a stable id
{
	auto rt = testRuntime();
	EventRegistration reg;
	reg.descriptor.name = "incident.created";
	reg.emitOnly = true;
	int subs;
	reg.onSubscribe = (EventContext ctx, string id) @safe { subs++; };
	rt.register(reg);

	auto r1 = rt.subscribeWebhook(webhookSub("incident.created", "https://proxy/hooks"), "user-1");
	assert(r1.id.length > 4 && r1.id[0 .. 4] == "sub_");
	assert(!r1.refreshBefore.isNull); // finite grant
	assert(subs == 1);

	// A refresh with the same key reuses the id and does not re-fire on_subscribe.
	auto r2 = rt.subscribeWebhook(webhookSub("incident.created", "https://proxy/hooks"), "user-1");
	assert(r2.id == r1.id);
	assert(subs == 1);
}

unittest  // subscribeWebhook clamps a suggested TTL down to the cap
{
	EventsOptions o;
	o.nowMs = () @safe => 1_000_000L;
	o.nowIso = () @safe => "t";
	o.webhookTtlCap = 1.minutes; // 60s cap
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	auto p = webhookSub("n", "https://proxy/hooks");
	p.ttlMsPresent = true;
	p.ttlMs = 3_600_000; // 1h suggestion, exceeds the 60s cap
	auto r = rt.subscribeWebhook(p, "user-1");
	// granted expiry is now + cap = 1_000_000 + 60_000
	assert(r.refreshBefore.get == isoFromMs(1_060_000));
}

unittest  // subscribeWebhook grants no-expiry only when allowed
{
	EventsOptions o;
	o.nowMs = () @safe => 0L;
	o.nowIso = () @safe => "t";
	o.allowNoExpiry = true;
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	auto p = webhookSub("n", "https://proxy/hooks");
	p.ttlMsPresent = true; // ttlMs left null => request no expiry
	auto r = rt.subscribeWebhook(p, "user-1");
	assert(r.refreshBefore.isNull); // granted no expiry

	// A server that disallows no-expiry returns a finite grant instead.
	EventsOptions o2;
	o2.nowMs = () @safe => 0L;
	o2.nowIso = () @safe => "t";
	o2.allowNoExpiry = false;
	auto rt2 = new EventsRuntime(null, o2);
	rt2.register(reg);
	auto r2 = rt2.subscribeWebhook(p, "user-1");
	assert(!r2.refreshBefore.isNull);
}

unittest  // subscribeWebhook rotates the secret with a grace window
{
	auto rt = testRuntime();
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	auto p1 = webhookSub("n", "https://proxy/hooks");
	auto r = rt.subscribeWebhook(p1, "user-1");
	auto p2 = webhookSub("n", "https://proxy/hooks");
	p2.delivery.secret = "whsec_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=";
	rt.subscribeWebhook(p2, "user-1");
	auto stored = rt.webhookStore().get(r.id).get;
	assert(stored.secret == p2.delivery.secret);
	assert(stored.previousSecret == p1.delivery.secret);
	assert(stored.previousSecretGraceUntilMs > 0);
}

unittest  // subscribeWebhook caps live subscriptions per principal with resourceExhausted
{
	import std.exception : assertNotThrown, collectException;
	import mcp.protocol.errors : McpException, ErrorCode;

	EventsOptions o;
	o.nowMs = () @safe => 1_000_000L;
	o.nowIso = () @safe => "t";
	o.webhookMaxSubscriptionsPerPrincipal = 2; // small cap for the test
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);

	// Distinct arguments give each subscription a distinct key (a fresh slot).
	SubscribeParams sub(int i) @safe
	{
		return webhookSub("n", "https://proxy/hooks", Json(["i": Json(i)]));
	}

	rt.subscribeWebhook(sub(1), "user-1");
	rt.subscribeWebhook(sub(2), "user-1");
	// A third new subscription for the same principal exceeds the cap.
	auto e = collectException!McpException(rt.subscribeWebhook(sub(3), "user-1"));
	assert(e !is null && e.code == ErrorCode.resourceExhausted);

	// Another principal has its own budget and is unaffected.
	assertNotThrown!McpException(rt.subscribeWebhook(sub(1), "user-2"));

	// Refreshing an existing subscription reuses its slot and is never rejected.
	assertNotThrown!McpException(rt.subscribeWebhook(sub(1), "user-1"));
}

unittest  // a per-principal cap of 0 disables the limit
{
	import std.exception : assertNotThrown;
	import mcp.protocol.errors : McpException;

	EventsOptions o;
	o.nowMs = () @safe => 1_000_000L;
	o.nowIso = () @safe => "t";
	o.webhookMaxSubscriptionsPerPrincipal = 0; // unlimited
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	foreach (i; 0 .. 5)
		assertNotThrown!McpException(rt.subscribeWebhook(webhookSub("n",
				"https://proxy/hooks", Json(["i": Json(i)])), "user-1"));
}

unittest  // unsubscribeWebhook removes the subscription and fires on_unsubscribe
{
	auto rt = testRuntime();
	EventRegistration reg;
	reg.descriptor.name = "n";
	reg.emitOnly = true;
	int unsubs;
	reg.onUnsubscribe = (EventContext ctx, string id) @safe { unsubs++; };
	rt.register(reg);
	auto r = rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	assert(!rt.webhookStore().get(r.id).isNull);

	UnsubscribeParams u;
	u.name = "n";
	u.url = "https://proxy/hooks";
	rt.unsubscribeWebhook(u, "user-1");
	assert(rt.webhookStore().get(r.id).isNull && unsubs == 1);
}

unittest  // unsubscribeWebhook throws NotFound for an unknown subscription
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto rt = testRuntime();
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	UnsubscribeParams u;
	u.name = "n";
	u.url = "https://proxy/none";
	assertThrown!McpException(rt.unsubscribeWebhook(u, "user-1"));
}

unittest  // an allowlisted callback URL is pre-verified at subscribe time
{
	EventsOptions o;
	o.nowMs = () @safe => 0L;
	o.nowIso = () @safe => "t";
	o.callbackAllowlist = ["https://proxy.example.com/"];
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	auto r = rt.subscribeWebhook(webhookSub("n", "https://proxy.example.com/hooks"), "user-1");
	assert(rt.webhookStore().get(r.id).get.verified);
}

unittest  // an allowlist entry does not pre-verify a sibling domain or a userinfo URL
{
	EventsOptions o;
	o.nowMs = () @safe => 0L;
	o.nowIso = () @safe => "t";
	o.callbackAllowlist = ["https://hooks.example.com/"];
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);

	// A sibling domain whose name merely begins with the allowlisted authority must
	// not pre-verify (a raw byte-prefix would have matched it).
	auto sibling = rt.subscribeWebhook(webhookSub("n",
			"https://hooks.example.com.evil.com/hooks"), "user-1");
	assert(!rt.webhookStore().get(sibling.id).get.verified);

	// A userinfo that embeds the allowlisted host but targets another authority must
	// not pre-verify (and a userinfo-bearing URL is never pre-verified at all).
	auto userinfo = rt.subscribeWebhook(webhookSub("n",
			"https://hooks.example.com@evil.com/hooks"), "user-1");
	assert(!rt.webhookStore().get(userinfo.id).get.verified);

	// The genuine allowlisted authority is still pre-verified.
	auto ok = rt.subscribeWebhook(webhookSub("n", "https://hooks.example.com/hooks"), "user-1");
	assert(rt.webhookStore().get(ok.id).get.verified);
}

unittest  // assumePrincipal lets webhook subscribe succeed without an explicit principal
{
	EventsOptions o;
	o.nowMs = () @safe => 0L;
	o.nowIso = () @safe => "t";
	o.assumePrincipal = "demo-user";
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	auto r = rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "");
	assert(rt.webhookStore().get(r.id).get.principal == "demo-user");
}

unittest  // a plain-http callback is rejected by default but allowed in dev mode
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	auto rt = testRuntime();
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	assertThrown!McpException(rt.subscribeWebhook(webhookSub("n", "http://proxy/hooks"), "u"));

	EventsOptions o;
	o.nowMs = () @safe => 0L;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	auto dev = new EventsRuntime(null, o);
	dev.register(reg);
	// The dev http allowance is confined to loopback/internal hosts.
	auto r = dev.subscribeWebhook(webhookSub("n", "http://127.0.0.1:8080/hooks"), "u");
	assert(r.id.length > 0);
}

unittest  // http to a PUBLIC host is rejected at subscribe even with the dev flag
{
	import std.exception : assertThrown;
	import mcp.protocol.errors : McpException;

	EventsOptions o;
	o.nowMs = () @safe => 0L;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true; // dev flag set
	auto dev = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	dev.register(reg);
	// A public host over cleartext http would leak the payload/secret; it is rejected
	// even with the dev allowance, which is confined to loopback/internal hosts.
	assertThrown!McpException(dev.subscribeWebhook(webhookSub("n",
			"http://hooks.example.com/hooks"), "u"));
	// A loopback host over http remains allowed in dev mode.
	auto ok = dev.subscribeWebhook(webhookSub("n", "http://127.0.0.1:8080/hooks"), "u");
	assert(ok.id.length > 0);
}

version (MCPWebhookEd25519)
{
	// The standardwebhooks reference signing key (its own test vector).
	private enum ed25519TestKey = "whsk_6Xb/dCcHpPea21PS1N9VY/NZW723CEc77N4rJCubMbfVKIDij2HKpMKkioLlX0dRqSKJp4AJ6p9lMicMFs6Kvg==";

	unittest  // the ed25519 backend auto-wires a v1a signer and publishes the JWKS
	{
		EventsOptions o;
		o.nowMs = () @safe => 0L;
		o.nowIso = () @safe => "t";
		o.webhookSigningKey = ed25519TestKey;
		auto rt = new EventsRuntime(null, o);
		auto jwks = rt.webhookJwks();
		assert(jwks["keys"].length == 1);
		assert(jwks["keys"][0]["kty"].get!string == "OKP");
		assert(jwks["keys"][0]["crv"].get!string == "Ed25519");
		assert(jwks["keys"][0]["x"].get!string.length > 0);
	}

	unittest  // a delivery signed by the wired v1a signer verifies under the published JWKS key
	{
		import std.base64 : Base64URLNoPadding;
		import standardwebhooks.ed25519 : AsymmetricWebhook;

		EventsOptions o;
		o.nowMs = () @safe => 0L;
		o.nowIso = () @safe => "t";
		o.webhookSigningKey = ed25519TestKey;
		auto rt = new EventsRuntime(null, o);

		// Sign a delivery through the runtime's auto-wired signer (the same `v1a,`
		// path a real delivery uses), then build a verify-only AsymmetricWebhook from
		// the public key the server publishes in its JWKS `x` member. The symmetric
		// `v1,` HMAC rides alongside; here we verify only the appended `v1a,` token.
		const 
		body = `{"eventId":"evt_1","name":"n","timestamp":"t","data":{}}`;
		auto headers = signDeliveryHeaders(testSecret, "", 0, 0, "evt_1",
				1_614_265_330, body, "sub_abc", rt.opts_.v1aSigner);

		const xB64Url = rt.webhookJwks()["keys"][0]["x"].get!string;
		auto pub = () @trusted {
			return cast(immutable(ubyte)[]) Base64URLNoPadding.decode(xB64Url);
		}();
		auto verifier = AsymmetricWebhook.fromRawPublicKey(pub);

		// The v1a token in the (signer-only) signature header verifies against the
		// published public key, end to end.
		assert(verifier.verifyIgnoringTimestamp(body, headers) == body);
	}
}
else
{
	unittest  // setting webhookSigningKey without the ed25519 backend fails loudly
	{
		import std.exception : assertThrown;

		EventsOptions o;
		o.nowMs = () @safe => 0L;
		o.nowIso = () @safe => "t";
		o.webhookSigningKey = "whsk_anything";
		assertThrown!Exception(new EventsRuntime(null, o));
	}
}

version (unittest)
{
	import mcp.server.webhook_delivery : WebhookTransport, WebhookHttpResult;
	import vibe.data.json : parseJsonString;
	import mcp.protocol.events : DeliveryErrorCategory;

	// A fake transport that records every POST and answers verification handshakes
	// (echoing the challenge) and event deliveries (per a programmable status queue).
	final class FakeWebhookTransport : WebhookTransport
	{
		static struct Req
		{
			string url;
			string[string] headers;
			string body;
		}

		Req[] posts;
		bool echoChallenge = true;
		int[] eventStatuses; // statuses for successive event deliveries (default 200)
		int eventCount;

		WebhookHttpResult post(string url, string[string] headers, string body, bool allowPrivate) @safe
		{
			posts ~= Req(url, headers, body);
			Json j;
			try
				j = parseJsonString(body);
			catch (Exception)
			{
			}
			const isControl = j.type == Json.Type.object && "type" in j
				&& j["type"].type == Json.Type.string;
			if (isControl && j["type"].get!string == "verification")
				return echoChallenge ? WebhookHttpResult.success(200,
						`{"challenge":"` ~ j["challenge"].get!string ~ `"}`) : WebhookHttpResult.success(
						200, `{}`);
			if (isControl)
				return WebhookHttpResult.success(200);
			int status = (eventCount < eventStatuses.length) ? eventStatuses[eventCount] : 200;
			eventCount++;
			if (status / 100 == 2)
				return WebhookHttpResult.success(status);
			return WebhookHttpResult.failure(status / 100 == 4
					? DeliveryErrorCategory.http4xx : DeliveryErrorCategory.http5xx, status);
		}

		string wellKnownBody; // served for GET /.well-known/mcp-webhook-receiver.json when set
		string[] gets; // every GET url, in order

		WebhookHttpResult get(string url, bool allowPrivate) @safe
		{
			import std.algorithm : endsWith;

			gets ~= url;
			if (wellKnownBody.length && url.endsWith(wellKnownReceiverPath))
				return WebhookHttpResult.success(200, wellKnownBody);
			return WebhookHttpResult.failure(DeliveryErrorCategory.http4xx, 404);
		}

		// Event-delivery POSTs only (excludes verification/control envelopes).
		Req[] eventPosts() @safe
		{
			Req[] result;
			foreach (p; posts)
			{
				Json j;
				try
					j = parseJsonString(p.body);
				catch (Exception)
				{
				}
				if (!(j.type == Json.Type.object && "type" in j))
					result ~= p;
			}
			return result;
		}
	}

	private EventsRuntime engineRuntime(FakeWebhookTransport ft, bool allowPrivate = true) @safe
	{
		EventsOptions o;
		o.nowMs = () @safe => 1_000_000L;
		o.nowIso = () @safe => "t";
		o.allowPrivateCallbackHosts = allowPrivate;
		o.webhookTransport = ft;
		o.deliveryExecutor = (void delegate() @safe job) @safe { job(); };
		o.deliverySleep = (Duration d) @safe {};
		auto rt = new EventsRuntime(null, o);
		EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
		rt.register(reg);
		return rt;
	}
}

unittest  // a rotated previous secret is cleared once its grace window has elapsed
{
	enum secretB = "whsec_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=";

	long now = 1_000_000;
	auto ft = new FakeWebhookTransport();
	EventsOptions o;
	o.nowMs = () @safe => now;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	o.webhookTransport = ft;
	o.deliveryExecutor = (void delegate() @safe job) @safe { job(); };
	o.deliverySleep = (Duration d) @safe {};
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);

	auto p = webhookSub("n", "https://proxy/hooks");
	auto r = rt.subscribeWebhook(p, "user-1");
	// Rotate the secret: the prior secret is retained for the grace window.
	auto rotate = p;
	rotate.delivery = WebhookDelivery("https://proxy/hooks", secretB);
	rt.subscribeWebhook(rotate, "user-1");
	assert(rt.webhookStore().get(r.id).get.previousSecret.length > 0);

	// A delivery within the grace window keeps the previous secret.
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	assert(rt.webhookStore().get(r.id).get.previousSecret.length > 0);

	// Past the grace window, the next successful delivery clears it.
	now += 6 * 60 * 1000;
	rt.emit(EventOccurrence("evt_2", "n", "t"));
	auto sub = rt.webhookStore().get(r.id).get;
	assert(sub.previousSecret.length == 0);
	assert(sub.previousSecretGraceUntilMs == 0);
}

unittest  // end-to-end secret rotation: deliveries dual-sign within grace, single-sign after
{
	import standardwebhooks : Webhook;

	enum secretB = "whsec_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=";

	long now = 1_000_000;
	auto ft = new FakeWebhookTransport();
	EventsOptions o;
	o.nowMs = () @safe => now;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	o.webhookTransport = ft;
	o.deliveryExecutor = (void delegate() @safe job) @safe { job(); };
	o.deliverySleep = (Duration d) @safe {};
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);

	// Subscribe under the original secret, then re-subscribe with a new whsec_ to
	// rotate it. The prior secret is retained for the grace window.
	auto p = webhookSub("n", "https://proxy/hooks");
	rt.subscribeWebhook(p, "user-1");
	auto rotate = p;
	rotate.delivery = WebhookDelivery("https://proxy/hooks", secretB);
	rt.subscribeWebhook(rotate, "user-1");

	// A delivery within the grace window: the captured headers verify under BOTH
	// the new and the previous (rotated-out) secret (Standard Webhooks multi-sig).
	rt.emit(EventOccurrence("evt_1", "n", "t", Json(["x": Json(1)])));
	auto withinGrace = ft.eventPosts()[$ - 1];
	assert(Webhook(secretB).verifyIgnoringTimestamp(withinGrace.body,
			withinGrace.headers) == withinGrace.body);
	assert(Webhook(testSecret).verifyIgnoringTimestamp(withinGrace.body,
			withinGrace.headers) == withinGrace.body);

	// Past the grace window, the delivery is signed under only the new secret; the
	// previous secret no longer verifies.
	import std.exception : assertThrown;
	import standardwebhooks.exception : WebhookException;

	now += 6 * 60 * 1000;
	rt.emit(EventOccurrence("evt_2", "n", "t", Json(["x": Json(2)])));
	auto afterGrace = ft.eventPosts()[$ - 1];
	assert(Webhook(secretB).verifyIgnoringTimestamp(afterGrace.body,
			afterGrace.headers) == afterGrace.body);
	assertThrown!WebhookException(Webhook(testSecret)
			.verifyIgnoringTimestamp(afterGrace.body, afterGrace.headers));
}

unittest  // emit verifies the endpoint, then delivers a signed, routable POST
{
	import standardwebhooks : Webhook;

	auto ft = new FakeWebhookTransport();
	auto rt = engineRuntime(ft);
	rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	rt.emit(EventOccurrence("evt_1", "n", "t", Json(["x": Json(1)])));

	// one verification POST, then one event POST
	assert(ft.posts.length == 2);
	auto ev = ft.eventPosts()[0];
	assert("webhook-signature" in ev.headers);
	assert(ev.headers["X-MCP-Subscription-Id"].length > 0);
	// the event delivery verifies under the subscription's secret
	assert(Webhook(testSecret).verifyIgnoringTimestamp(ev.body, ev.headers) == ev.body);
}

unittest  // an endpoint that fails the challenge handshake receives no event delivery
{
	auto ft = new FakeWebhookTransport();
	ft.echoChallenge = false;
	auto rt = engineRuntime(ft);
	auto r = rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	// only the verification POST happened; no event delivery
	assert(ft.eventPosts().length == 0);
	// the failure was recorded as challenge_failed
	assert(rt.webhookStore().get(r.id)
			.get.lastErrorCat == cast(int) DeliveryErrorCategory.challengeFailed);
}

unittest  // a fresh webhook subscription replays the retained events after its cursor
{
	auto ft = new FakeWebhookTransport();
	auto rt = engineRuntime(ft);
	// Three events in the buffer (seq 1..3) before anyone subscribes.
	foreach (id; ["evt_1", "evt_2", "evt_3"])
		rt.emit(EventOccurrence(id, "n", "t"));
	assert(ft.eventPosts().length == 0); // no subscriber yet
	auto p = webhookSub("n", "https://proxy/hooks");
	p.cursor = "1"; // the client last persisted position 1
	auto r = rt.subscribeWebhook(p, "user-1");
	assert(!r.truncated);
	assert(ft.eventPosts().length == 2); // evt_2 and evt_3 replayed
	import std.algorithm : canFind;

	assert(ft.eventPosts()[0].body.canFind("evt_2") && ft.eventPosts()[1].body.canFind("evt_3"));
	// Both acked in order: the watermark settled at the last replayed position.
	assert(rt.webhookStore().get(r.id).get.cursor.get == "3");
}

unittest  // a null cursor bootstraps a webhook subscription at the current position
{
	auto ft = new FakeWebhookTransport();
	auto rt = engineRuntime(ft);
	rt.emit(EventOccurrence("evt_old", "n", "t"));
	auto r = rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	assert(ft.eventPosts().length == 0); // nothing replayed
	assert(!r.cursor.isNull && r.cursor.get == "1"); // a fresh cursor to persist
	assert(!r.truncated);
	rt.emit(EventOccurrence("evt_new", "n", "t"));
	assert(ft.eventPosts().length == 1);
}

unittest  // a cursor the buffer no longer covers replays what remains and reports truncated
{
	auto ft = new FakeWebhookTransport();
	auto rt = engineRuntime(ft);
	auto p = webhookSub("n", "https://proxy/hooks");
	p.cursor = "not-a-position"; // from a prior process: unrecognisable
	auto r = rt.subscribeWebhook(p, "user-1");
	assert(r.truncated);
	assert(!r.cursor.isNull); // reset to a position the server can serve from
}

unittest  // a check-backed type is served over webhook by replaying from the cursor, then polling
{
	auto ft = new FakeWebhookTransport();
	long now = 1_000_000;
	EventsOptions o;
	o.nowMs = () @safe => now;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	o.webhookTransport = ft;
	o.deliveryExecutor = (void delegate() @safe job) @safe { job(); };
	o.deliverySleep = (Duration d) @safe {};
	auto rt = new EventsRuntime(null, o);
	Nullable!string[] seen;
	EventRegistration reg;
	reg.descriptor.name = "email.received";
	reg.pollInterval = 10.seconds;
	reg.check = (EventContext ctx) @safe {
		seen ~= ctx.cursor;
		if (ctx.isBootstrap())
			return EventResult.empty("h0");
		if (ctx.cursor.get == "h0")
			return EventResult.of([EventOccurrence("m1", "email.received", "t")], "h1");
		return EventResult.empty(ctx.cursor.get); // quiet
	};
	rt.register(reg);

	auto p = webhookSub("email.received", "https://proxy/hooks");
	p.cursor = "h0";
	auto r = rt.subscribeWebhook(p, "user-1");
	assert(seen.length == 1 && seen[0].get == "h0"); // replayed from the client's cursor
	assert(ft.eventPosts().length == 1); // m1 delivered
	assert(rt.webhookStore().get(r.id).get.cursor.get == "h1"); // batch cursor settled on ack

	rt.pollWebhookSubscriptions();
	assert(seen.length == 2 && seen[1].get == "h1"); // the loop resumes from the fetch position
	rt.pollWebhookSubscriptions();
	assert(seen.length == 2); // within the 10 s cadence: not fetched again
	now += 10_000;
	rt.pollWebhookSubscriptions();
	assert(seen.length == 3);
	assert(ft.eventPosts().length == 1); // quiet polls deliver nothing
}

unittest  // a check function that bootstraps a webhook subscription settles the fresh cursor
{
	auto ft = new FakeWebhookTransport();
	auto rt = engineRuntime(ft);
	EventRegistration reg;
	reg.descriptor.name = "email.received";
	reg.check = (EventContext ctx) @safe {
		return ctx.isBootstrap() ? EventResult.empty("h0") : EventResult.empty(ctx.cursor.get);
	};
	rt.register(reg);
	auto r = rt.subscribeWebhook(webhookSub("email.received", "https://proxy/hooks"), "user-1");
	assert(r.cursor.get == "h0");
	assert(ft.eventPosts().length == 0);
}

unittest  // the watermark advances to a position only once every earlier one has settled
{
	auto ft = new FakeWebhookTransport();
	EventsOptions o;
	o.nowMs = () @safe => 1_000_000L;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	o.webhookTransport = ft;
	o.deliverySleep = (Duration d) @safe {};
	void delegate() @safe[] deferred;
	o.deliveryExecutor = (void delegate() @safe job) @safe { deferred ~= job; };
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	auto r = rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	rt.emit(EventOccurrence("evt_1", "n", "t")); // seq 1
	rt.emit(EventOccurrence("evt_2", "n", "t")); // seq 2
	// Two drain kicks are queued; run them so each job gets its own deferred task.
	deferred[0]();
	deferred[1]();
	auto jobs = deferred[2 .. $];
	assert(jobs.length == 2);
	jobs[1](); // evt_2 acks first
	assert(rt.webhookStore().get(r.id).get.cursor == r.cursor); // evt_1 still in flight: unchanged
	jobs[0](); // evt_1 acks
	assert(rt.webhookStore().get(r.id).get.cursor.get == "2"); // now both are safe
}

unittest  // a refresh of a live subscription does not replay from the client's older cursor
{
	auto ft = new FakeWebhookTransport();
	auto rt = engineRuntime(ft);
	auto p = webhookSub("n", "https://proxy/hooks");
	auto r1 = rt.subscribeWebhook(p, "user-1");
	foreach (id; ["evt_1", "evt_2"])
		rt.emit(EventOccurrence(id, "n", "t"));
	assert(ft.eventPosts().length == 2);
	assert(rt.webhookStore().get(r1.id).get.cursor.get == "2");
	p.cursor = r1.cursor; // the client re-supplies the cursor it was first given
	auto r2 = rt.subscribeWebhook(p, "user-1");
	assert(ft.eventPosts().length == 2); // nothing redelivered
	assert(r2.cursor.get == "2"); // the server's watermark, not the client's value
	assert(!r2.deliveryStatus.isNull);
}

unittest  // a lapsed subscription is recreated from the client's cursor, with lifecycle hooks
{
	auto ft = new FakeWebhookTransport();
	long now = 1_000_000;
	EventsOptions o;
	o.nowMs = () @safe => now;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	o.webhookTransport = ft;
	o.deliveryExecutor = (void delegate() @safe job) @safe { job(); };
	o.deliverySleep = (Duration d) @safe {};
	o.webhookTtlCap = 1.minutes;
	auto rt = new EventsRuntime(null, o);
	int subs, unsubs;
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	reg.onSubscribe = (EventContext ctx, string id) @safe { subs++; };
	reg.onUnsubscribe = (EventContext ctx, string id) @safe { unsubs++; };
	rt.register(reg);
	auto p = webhookSub("n", "https://proxy/hooks");
	rt.subscribeWebhook(p, "user-1");
	assert(subs == 1);
	foreach (id; ["evt_1", "evt_2", "evt_3"])
		rt.emit(EventOccurrence(id, "n", "t"));
	assert(ft.eventPosts().length == 3);

	now += 2 * 60 * 1000; // the grant lapsed
	p.cursor = "1"; // the client's last persisted position
	auto r = rt.subscribeWebhook(p, "user-1");
	assert(unsubs == 1 && subs == 2); // torn down and provisioned afresh
	assert(ft.eventPosts().length == 5); // evt_2 and evt_3 replayed
	assert(!r.deliveryStatus.isNull == false); // a fresh subscription carries no status
}

unittest  // sweepWebhookSubscriptions drops lapsed subscriptions and fires on_unsubscribe
{
	long now = 1_000_000;
	auto rt = testRuntime(() @safe => now);
	int unsubs;
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	reg.onUnsubscribe = (EventContext ctx, string id) @safe { unsubs++; };
	rt.register(reg);
	auto r = rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	rt.sweepWebhookSubscriptions();
	assert(!rt.webhookStore().get(r.id).isNull); // still within its grant
	now += 60 * 60 * 1000;
	rt.sweepWebhookSubscriptions();
	assert(rt.webhookStore().get(r.id).isNull);
	assert(unsubs == 1);
}

unittest  // events sharing a batch cursor settle the watermark together
{
	auto ft = new FakeWebhookTransport();
	EventsOptions o;
	o.nowMs = () @safe => 1_000_000L;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	o.webhookTransport = ft;
	o.deliverySleep = (Duration d) @safe {};
	void delegate() @safe[] deferred;
	o.deliveryExecutor = (void delegate() @safe job) @safe { deferred ~= job; };
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg;
	reg.descriptor.name = "email.received";
	reg.check = (EventContext ctx) @safe {
		if (ctx.isBootstrap())
			return EventResult.empty("h0");
		return EventResult.of([
			EventOccurrence("m1", "email.received", "t"), EventOccurrence("m2", "email.received", "t")
		], "h1");
	};
	rt.register(reg);
	auto p = webhookSub("email.received", "https://proxy/hooks");
	p.cursor = "h0";
	auto r = rt.subscribeWebhook(p, "user-1");
	assert(rt.webhookStore().get(r.id).get.cursor.get == "h0"); // replay in flight
	deferred[0](); // the drain: two per-job tasks
	auto jobs = deferred[1 .. $];
	assert(jobs.length == 2);
	jobs[0]();
	assert(rt.webhookStore().get(r.id).get.cursor.get == "h0"); // m2 still in flight
	jobs[1]();
	assert(rt.webhookStore().get(r.id).get.cursor.get == "h1");
}

unittest  // a deferred drain delivers every leased job, each to its own task
{
	auto ft = new FakeWebhookTransport();
	EventsOptions o;
	o.nowMs = () @safe => 1_000_000L;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	o.webhookTransport = ft;
	o.deliverySleep = (Duration d) @safe {};
	void delegate() @safe[] deferred;
	o.deliveryExecutor = (void delegate() @safe job) @safe { deferred ~= job; };
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	rt.emit(EventOccurrence("evt_2", "n", "t"));
	for (size_t i = 0; i < deferred.length; i++)
		deferred[i]();
	import std.algorithm : canFind;

	auto posts = ft.eventPosts();
	assert(posts.length == 2);
	assert(posts[0].body.canFind("evt_1") && posts[1].body.canFind("evt_2"));
}

unittest  // a receiver-published well-known document verifies a covered callback without a challenge
{
	auto ft = new FakeWebhookTransport();
	ft.echoChallenge = false; // a challenge, if sent, would fail
	ft.wellKnownBody = `{"receivers": ["/hooks/"]}`;
	auto rt = engineRuntime(ft);
	auto r = rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks/c1"), "user-1");
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	assert(ft.eventPosts().length == 1); // delivered
	assert(controlPostsOf(ft, "verification").length == 0); // no challenge POST
	assert(ft.gets.length == 1 && ft.gets[0] == "https://proxy:443" ~ wellKnownReceiverPath);
	assert(rt.webhookStore().get(r.id).get.verified);
}

unittest  // a callback outside the well-known document's prefixes still gets the challenge
{
	auto ft = new FakeWebhookTransport();
	ft.wellKnownBody = `{"receivers": ["/hooks/"]}`;
	auto rt = engineRuntime(ft);
	rt.subscribeWebhook(webhookSub("n", "https://proxy/other/c1"), "user-1");
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	assert(controlPostsOf(ft, "verification").length == 1);
	assert(ft.eventPosts().length == 1); // the echoed challenge verified it
}

unittest  // the well-known document is fetched once per origin and cached
{
	auto ft = new FakeWebhookTransport();
	ft.wellKnownBody = `{"receivers": ["/hooks/"]}`;
	auto rt = engineRuntime(ft);
	rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks/a"), "user-1");
	rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks/b"), "user-2");
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	assert(ft.eventPosts().length == 2);
	assert(ft.gets.length == 1);
}

unittest  // well-known verification can be disabled, falling back to the challenge
{
	auto ft = new FakeWebhookTransport();
	ft.wellKnownBody = `{"receivers": ["/hooks/"]}`;
	EventsOptions o;
	o.nowMs = () @safe => 1_000_000L;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	o.webhookTransport = ft;
	o.deliveryExecutor = (void delegate() @safe job) @safe { job(); };
	o.deliverySleep = (Duration d) @safe {};
	o.wellKnownReceiverVerification = false;
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks/c1"), "user-1");
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	assert(ft.gets.length == 0);
	assert(controlPostsOf(ft, "verification").length == 1);
}

unittest  // an unverified endpoint is not re-probed on every emit (verification backoff)
{
	long now = 1_000_000;
	auto ft = new FakeWebhookTransport();
	ft.echoChallenge = false; // the endpoint never completes the handshake
	EventsOptions o;
	o.nowMs = () @safe => now;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	o.webhookTransport = ft;
	o.deliveryExecutor = (void delegate() @safe job) @safe { job(); };
	o.deliverySleep = (Duration d) @safe {};
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");

	// First emit probes once and fails verification.
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	const afterFirst = ft.posts.length;
	assert(afterFirst == 1);

	// A second emit within the backoff window does NOT re-probe.
	rt.emit(EventOccurrence("evt_2", "n", "t"));
	assert(ft.posts.length == afterFirst);

	// Past the backoff window, a probe is allowed again.
	now += verifyBackoffBaseMs + 1;
	rt.emit(EventOccurrence("evt_3", "n", "t"));
	assert(ft.posts.length == afterFirst + 1);
}

unittest  // a 410 Gone response is not retried (single event attempt)
{
	auto ft = new FakeWebhookTransport();
	ft.eventStatuses = [410];
	auto rt = engineRuntime(ft);
	rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	assert(ft.eventPosts().length == 1); // no retry after 410
}

unittest  // a transient 503 is retried and then succeeds
{
	auto ft = new FakeWebhookTransport();
	ft.eventStatuses = [503, 200];
	auto rt = engineRuntime(ft);
	rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	assert(ft.eventPosts().length == 2); // failed once, retried, succeeded
}

unittest  // a delivery to a non-globally-routable callback is rejected before any POST
{
	auto ft = new FakeWebhookTransport();
	auto rt = engineRuntime(ft, /*allowPrivate*/ false);
	// subscribe-time only checks https; the private host is rejected at delivery.
	rt.subscribeWebhook(webhookSub("n", "https://10.0.0.1/hooks"), "user-1");
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	assert(ft.posts.length == 0); // SSRF guard blocked the verification/delivery POST
}

unittest  // a refresh after a delivery failure surfaces deliveryStatus.lastError
{
	auto ft = new FakeWebhookTransport();
	ft.eventStatuses = [503, 503, 503, 503, 503]; // exhaust the default 5 attempts
	auto rt = engineRuntime(ft);
	auto p = webhookSub("n", "https://proxy/hooks");
	rt.subscribeWebhook(p, "user-1");
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	// refresh returns delivery health
	auto refreshed = rt.subscribeWebhook(p, "user-1");
	assert(!refreshed.deliveryStatus.isNull);
	assert(refreshed.deliveryStatus.get.lastError.get == DeliveryErrorCategory.http5xx);
}

unittest  // a sustained failure rate over the minimum sample suspends the subscription
{
	auto ft = new FakeWebhookTransport();
	EventsOptions o;
	o.nowMs = () @safe => 1_000_000L;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	o.webhookTransport = ft;
	o.deliveryExecutor = (void delegate() @safe job) @safe { job(); };
	o.deliverySleep = (Duration d) @safe {};
	o.webhookMaxAttempts = 1; // one attempt per event => one outcome per emit
	o.webhookSuspension.minAttempts = 2;
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);

	auto r = rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	ft.eventStatuses = [500, 500];
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	assert(rt.webhookStore().get(r.id).get.active); // below the minimum sample
	rt.emit(EventOccurrence("evt_2", "n", "t"));
	auto suspended = rt.webhookStore().get(r.id).get;
	assert(!suspended.active); // 2 of 2 failed: 100% over a sample of 2
	assert(suspended.windowAttempts == 2 && suspended.windowFailures == 2);
}

unittest  // failures below the minimum sample never suspend
{
	auto ft = new FakeWebhookTransport();
	auto rt = engineRuntime(ft); // default policy: 100 attempts minimum
	auto r = rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	ft.eventStatuses = [500, 500, 500, 500, 500];
	foreach (i; 0 .. 5)
		rt.emit(EventOccurrence("evt_" ~ ['a', 'b', 'c', 'd', 'e'][i], "n", "t"));
	assert(rt.webhookStore().get(r.id).get.active);
}

unittest  // a failure rate under the threshold never suspends, however large the sample
{
	auto ft = new FakeWebhookTransport();
	EventsOptions o;
	o.nowMs = () @safe => 1_000_000L;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	o.webhookTransport = ft;
	o.deliveryExecutor = (void delegate() @safe job) @safe { job(); };
	o.deliverySleep = (Duration d) @safe {};
	o.webhookMaxAttempts = 1;
	o.webhookSuspension.minAttempts = 4;
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	auto r = rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	ft.eventStatuses = [500, 200, 500, 200]; // 50% failed
	foreach (i; 0 .. 4)
		rt.emit(EventOccurrence("evt_" ~ ['a', 'b', 'c', 'd'][i], "n", "t"));
	auto sub = rt.webhookStore().get(r.id).get;
	assert(sub.active && sub.windowAttempts == 4 && sub.windowFailures == 2);
}

unittest  // the sample window tumbles: an old streak does not count against a new window
{
	long now = 1_000_000;
	auto ft = new FakeWebhookTransport();
	EventsOptions o;
	o.nowMs = () @safe => now;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	o.webhookTransport = ft;
	o.deliveryExecutor = (void delegate() @safe job) @safe { job(); };
	o.deliverySleep = (Duration d) @safe {};
	o.webhookMaxAttempts = 1;
	o.webhookSuspension.minAttempts = 2;
	o.webhookSuspension.window = 1.minutes;
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	auto r = rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	ft.eventStatuses = [500, 500];
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	now += 2 * 60 * 1000; // the window elapsed: the first failure is forgotten
	rt.emit(EventOccurrence("evt_2", "n", "t"));
	auto sub = rt.webhookStore().get(r.id).get;
	assert(sub.active && sub.windowAttempts == 1 && sub.windowFailures == 1);
}

unittest  // events emitted while suspended are queued and delivered once a refresh reactivates
{
	auto ft = new FakeWebhookTransport();
	EventsOptions o;
	o.nowMs = () @safe => 1_000_000L;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	o.webhookTransport = ft;
	o.deliveryExecutor = (void delegate() @safe job) @safe { job(); };
	o.deliverySleep = (Duration d) @safe {};
	o.webhookMaxAttempts = 1;
	o.webhookSuspension.minAttempts = 2;
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	auto r = rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	ft.eventStatuses = [500, 500];
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	rt.emit(EventOccurrence("evt_2", "n", "t"));
	assert(!rt.webhookStore().get(r.id).get.active);
	const before = ft.eventPosts().length;

	// Suspended: the emit is queued, not attempted.
	rt.emit(EventOccurrence("evt_3", "n", "t"));
	assert(ft.eventPosts().length == before);

	// The refresh reactivates delivery and the queued event goes out (200 now).
	auto refreshed = rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	assert(!refreshed.deliveryStatus.isNull && refreshed.deliveryStatus.get.active);
	assert(ft.eventPosts().length == before + 1);
	import std.algorithm : canFind;

	assert(ft.eventPosts()[$ - 1].body.canFind("evt_3"));
}

unittest  // emitted webhook deliveries respect the type's match filter
{
	auto ft = new FakeWebhookTransport();
	EventsOptions o;
	o.nowMs = () @safe => 1_000_000L;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	o.webhookTransport = ft;
	o.deliveryExecutor = (void delegate() @safe job) @safe { job(); };
	o.deliverySleep = (Duration d) @safe {};
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg;
	reg.descriptor.name = "incident.created";
	reg.emitOnly = true;
	reg.match = (EventContext ctx, EventOccurrence ev) @safe {
		auto want = ctx.arguments["severity"];
		return want.type != Json.Type.string || ev.data["severity"].get!string == want.get!string;
	};
	rt.register(reg);
	rt.subscribeWebhook(webhookSub("incident.created", "https://proxy/hooks",
			Json(["severity": Json("P1")])), "user-1");
	// a P2 event does not match the P1 subscription -> no delivery (no verification either)
	rt.emit(EventOccurrence("e", "incident.created", "t", Json([
		"severity": Json("P2")
	])));
	assert(ft.posts.length == 0);
	// a P1 event matches -> verification + delivery
	rt.emit(EventOccurrence("e2", "incident.created", "t", Json([
		"severity": Json("P1")
	])));
	assert(ft.eventPosts().length == 1);
}

unittest  // publish enqueues a webhook delivery; delivery happens on a queue drain
{
	auto ft = new FakeWebhookTransport();
	EventsOptions o;
	o.nowMs = () @safe => 1_000_000L;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	o.webhookTransport = ft;
	o.deliverySleep = (Duration d) @safe {};
	// A deferring executor captures the per-publish kick without running it, so we
	// can observe that publish only ENQUEUES — delivery waits for a drain.
	void delegate() @safe[] deferred;
	o.deliveryExecutor = (void delegate() @safe job) @safe { deferred ~= job; };
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");

	rt.emit(EventOccurrence("evt_1", "n", "t"));
	assert(ft.posts.length == 0); // enqueued, not yet delivered

	// Run deferred tasks to completion: the drain itself spawns a per-job delivery
	// task (also deferred), so keep running until the queue of work drains.
	for (size_t i = 0; i < deferred.length; i++)
		deferred[i]();
	assert(ft.eventPosts().length == 1);
}

unittest  // multi-node: node B's worker delivers a job node A enqueued (shared store + queue)
{
	auto store = new InMemoryWebhookSubscriptionStore();
	auto queue = new InMemoryDeliveryQueue();

	// Node A publishes but "crashes" before its drain runs (kick dropped).
	auto ftA = new FakeWebhookTransport();
	EventsOptions oa;
	oa.nowMs = () @safe => 1_000_000L;
	oa.nowIso = () @safe => "t";
	oa.allowPrivateCallbackHosts = true;
	oa.webhookTransport = ftA;
	oa.deliverySleep = (Duration d) @safe {};
	oa.deliveryQueue = queue;
	oa.deliveryExecutor = (void delegate() @safe job) @safe {}; // drop the kick
	auto rtA = new EventsRuntime(store, oa);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rtA.register(reg);
	rtA.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	rtA.emit(EventOccurrence("evt_1", "n", "t"));
	assert(ftA.posts.length == 0); // node A never delivered

	// Node B shares the store + queue; its worker drain delivers the orphaned job.
	auto ftB = new FakeWebhookTransport();
	EventsOptions ob;
	ob.nowMs = () @safe => 2_000_000L;
	ob.nowIso = () @safe => "t";
	ob.allowPrivateCallbackHosts = true;
	ob.webhookTransport = ftB;
	ob.deliverySleep = (Duration d) @safe {};
	ob.deliveryQueue = queue;
	ob.deliveryExecutor = (void delegate() @safe job) @safe { job(); };
	auto rtB = new EventsRuntime(store, ob);
	rtB.drainDeliveries();
	assert(ftB.eventPosts().length == 1); // delivered by node B
}

version (unittest)
{
	// Control-envelope POSTs of a given `type` (e.g. "gap"), for delivery assertions.
	private FakeWebhookTransport.Req[] controlPostsOf(FakeWebhookTransport ft, string type) @safe
	{
		FakeWebhookTransport.Req[] result;
		foreach (p; ft.posts)
		{
			Json j;
			try
				j = parseJsonString(p.body);
			catch (Exception)
			{
			}
			if (j.type == Json.Type.object && "type" in j
					&& j["type"].type == Json.Type.string && j["type"].get!string == type)
				result ~= p;
		}
		return result;
	}
}

unittest  // attempt persistence: a job re-leased mid-retry does not restart attempts
{
	import mcp.server.event_store : Delivery, InMemoryDeliveryQueue;

	auto ft = new FakeWebhookTransport();
	// Every attempt fails, so the job would retry forever if attempts reset.
	ft.eventStatuses = [503, 503, 503, 503, 503, 503, 503, 503];
	auto queue = new InMemoryDeliveryQueue();
	EventsOptions o;
	o.nowMs = () @safe => 1_000_000L;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	o.webhookTransport = ft;
	o.deliveryQueue = queue;
	o.deliverySleep = (Duration d) @safe {};
	// Don't auto-run the kick; drive drains manually so we can simulate a crash.
	o.deliveryExecutor = (void delegate() @safe job) @safe { job(); };
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	auto r = rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");

	// Enqueue a job one attempt short of the cap on a prior (crashed) lease.
	auto occ = EventOccurrence("evt_1", "n", "t");
	occ.cursor = "5";
	queue.enqueue(Delivery(r.id ~ "/evt_1", r.id, occ, o.webhookMaxAttempts - 1));
	rt.drainDeliveries();
	// Resuming from the persisted count, only one more attempt is made before the cap.
	assert(ft.eventPosts().length == 1);
	// The job is settled (acked) and emits a gap, not retried forever.
	assert(controlPostsOf(ft, "gap").length == 1);
}

unittest  // the default retry schedule is 3-5 attempts spread over at most 15 minutes
{
	auto ft = new FakeWebhookTransport();
	auto rt = engineRuntime(ft);
	EventsOptions defaults;
	assert(defaults.webhookMaxAttempts >= 3 && defaults.webhookMaxAttempts <= 5);
	Duration total;
	foreach (attempt; 1 .. defaults.webhookMaxAttempts)
		total += rt.backoffFor(attempt);
	assert(total <= 15.minutes && total >= 5.minutes);
}

unittest  // an oversize delivery body is abandoned with a gap signal, never POSTed
{
	auto ft = new FakeWebhookTransport();
	auto rt = engineRuntime(ft);
	rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	import std.array : replicate;

	EventOccurrence big = EventOccurrence("evt_big", "n", "t");
	big.data = Json(["blob": Json("a".replicate(300 * 1024))]);
	rt.emit(big);
	assert(ft.eventPosts().length == 0);
	assert(controlPostsOf(ft, "gap").length == 1);
}

unittest  // gap-on-exhaustion: a signed gap envelope is posted when attempts run out
{
	auto ft = new FakeWebhookTransport();
	ft.eventStatuses = [503, 503, 503, 503, 503];
	auto rt = engineRuntime(ft);
	rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	auto gaps = controlPostsOf(ft, "gap");
	assert(gaps.length == 1);
	// the gap envelope carries the lost event's watermark cursor and is signed +
	// addressed, so the client persists it and treats the position as truncated.
	auto j = parseJsonString(gaps[0].body);
	assert(j["type"].get!string == "gap");
	assert(j["cursor"].get!string.length > 0);
	assert("webhook-signature" in gaps[0].headers);
	assert(gaps[0].headers["X-MCP-Subscription-Id"].length > 0);
}

unittest  // monotonic watermark: an out-of-order older ack does not regress the cursor
{
	auto rt = testRuntime();
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	auto r = rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");

	// Advance the watermark to 10, then a stale ack for 4 must not pull it back.
	rt.recordSuccess(r.id, nullable("10"));
	assert(rt.webhookStore().get(r.id).get.cursor.get == "10");
	rt.recordSuccess(r.id, nullable("4"));
	assert(rt.webhookStore().get(r.id).get.cursor.get == "10"); // unchanged
	// a strictly-greater ack still advances
	rt.recordSuccess(r.id, nullable("11"));
	assert(rt.webhookStore().get(r.id).get.cursor.get == "11");
}

unittest  // no double-delivery: a concurrent drain cannot re-lease an in-flight job
{
	auto ft = new FakeWebhookTransport();
	auto rt = engineRuntime(ft);
	rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	// The job delivered once and was acked; a second drain finds nothing to lease.
	assert(ft.eventPosts().length == 1);
	rt.drainDeliveries();
	assert(ft.eventPosts().length == 1); // still one — not re-delivered
}

unittest  // a transient failure leaves the job leased (not acked) for re-lease
{
	import mcp.server.event_store : InMemoryDeliveryQueue;

	auto ft = new FakeWebhookTransport();
	auto queue = new InMemoryDeliveryQueue();
	EventsOptions o;
	long now = 1_000_000L;
	o.nowMs = () @safe => now;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	o.webhookTransport = ft;
	o.deliveryQueue = queue;
	o.deliverySleep = (Duration d) @safe {};
	o.deliveryExecutor = (void delegate() @safe job) @safe { job(); };
	auto rt = new EventsRuntime(null, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");

	// The endpoint refuses the verification handshake, so no attempt is made and the
	// job is left in the queue (not acked) to retry on a later lease.
	ft.echoChallenge = false;
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	assert(ft.eventPosts().length == 0);
	// the job survives: once the endpoint verifies, a re-lease delivers it.
	ft.echoChallenge = true;
	now += rt.opts_.deliveryLease.total!"msecs" + 1; // let the lease expire
	rt.drainDeliveries();
	assert(ft.eventPosts().length == 1);
}

unittest  // a delivery whose store throws is dead-lettered, not looped invisibly
{
	import mcp.server.event_store : InMemoryDeliveryQueue, InMemoryWebhookSubscriptionStore;

	// A store that throws on get() once a subscription has been written, so the
	// delivery worker's deliverWithRetry throws after the job is enqueued.
	static final class ThrowingStore : WebhookSubscriptionStore
	{
		InMemoryWebhookSubscriptionStore inner;
		bool throwOnGet;
		this() @safe
		{
			inner = new InMemoryWebhookSubscriptionStore();
		}

		void put(WebhookSubscription sub) @safe
		{
			inner.put(sub);
		}

		Nullable!WebhookSubscription get(string id) @safe
		{
			if (throwOnGet)
				throw new Exception("store unavailable");
			return inner.get(id);
		}

		void remove(string id) @safe
		{
			inner.remove(id);
		}

		WebhookSubscription[] all() @safe
		{
			return inner.all();
		}
	}

	auto ft = new FakeWebhookTransport();
	auto store = new ThrowingStore();
	auto queue = new InMemoryDeliveryQueue();
	EventsOptions o;
	long now = 1_000_000L;
	o.nowMs = () @safe => now;
	o.nowIso = () @safe => "t";
	o.allowPrivateCallbackHosts = true;
	o.webhookTransport = ft;
	o.deliveryQueue = queue;
	o.webhookMaxAttempts = 1; // a single failed attempt dead-letters
	o.deliverySleep = (Duration d) @safe {};
	o.deliveryExecutor = (void delegate() @safe job) @safe { job(); };
	auto rt = new EventsRuntime(store, o);
	EventRegistration reg = {descriptor: EventType("n"), emitOnly: true};
	rt.register(reg);
	rt.subscribeWebhook(webhookSub("n", "https://proxy/hooks"), "user-1");

	// The store starts throwing on get, so the delivery task throws unexpectedly.
	store.throwOnGet = true;
	rt.emit(EventOccurrence("evt_1", "n", "t"));
	// The guard dead-lettered (acked) the job rather than leaving it leased to loop
	// forever: a later drain finds nothing to lease.
	store.throwOnGet = false;
	now += rt.opts_.deliveryLease.total!"msecs" + 1;
	assert(queue.lease(now, 1000).length == 0);
}
