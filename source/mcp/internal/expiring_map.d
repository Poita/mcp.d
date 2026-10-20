module mcp.internal.expiring_map;

import core.time : Duration, MonoTime;

/// A string-keyed cache of `V` with a per-entry insertion/activity timestamp,
/// bounded by an idle TTL and a maximum live-entry count. It keeps each entry in
/// a key map and in a least-recently-active list, and runs the TTL sweep + LRU
/// cap eviction internally.
///
/// A lookup checks only its own key's expiry; the full TTL sweep runs at most
/// once per quarter-TTL, and cap eviction takes the head of the activity list,
/// so per-request cost stays constant as the table grows.
/// Past the cap, entries never marked used (`markUsed`) are evicted before used
/// ones, so a burst of fresh entries cannot push out the ones in active use.
///
/// `ttl == Duration.zero` disables the sweep; `maxEntries == 0` disables the
/// cap. `clock` is injectable (`null` => `MonoTime.currTime`) so callers can
/// drive expiry deterministically in tests. The container does no locking; the
/// owner serializes access (e.g. `synchronized` on a `synchronized`-using class,
/// or vibe.d's single-fiber loop).
package(mcp) struct BoundedExpiringMap(V)
{
	/// One entry, linked into the never-used or the used activity list.
	private static final class Node
	{
		string key;
		V value;
		MonoTime stamp;
		bool used;
		Node prev, next;
	}

	/// Entries linked from least- to most-recently active. Stamps come from a
	/// non-decreasing clock and a restamped entry moves to the tail, so list
	/// order is stamp order.
	private static struct Order
	{
		Node head, tail;

		void append(Node n) @safe
		{
			n.prev = tail;
			n.next = null;
			if (tail !is null)
				tail.next = n;
			else
				head = n;
			tail = n;
		}

		/// Unlink `n`; a no-op when it is not linked here.
		void unlink(Node n) @safe
		{
			if (n.prev is null && head !is n)
				return;
			if (n.prev !is null)
				n.prev.next = n.next;
			else
				head = n.next;
			if (n.next !is null)
				n.next.prev = n.prev;
			else
				tail = n.prev;
			n.prev = n.next = null;
		}
	}

	private Node[string] nodes;
	private bool[string] busySeen; // keys last seen busy, restamped each sweep
	private Order unusedOrder, usedOrder;
	private MonoTime lastSweep;
	private Duration ttl;
	private size_t maxEntries;
	private MonoTime delegate() @safe clock;

	/// Called with an entry's key and value after the TTL sweep or cap eviction
	/// removes it, so the owner can release resources tied to the entry. Not
	/// called for `take` or `remove`.
	void delegate(string key, V value) @safe onEvict;

	/// When set, an entry for which this returns true is busy: the TTL never
	/// expires it. An entry seen busy (on a lookup of its key or when a sweep
	/// finds it past its TTL) is restamped on every later sweep until it is idle,
	/// so its full idle TTL starts once its work ends.
	bool delegate(ref V value) @safe busy;

	this(Duration ttl, size_t maxEntries, MonoTime delegate() @safe clock) @safe
	{
		this.ttl = ttl;
		this.maxEntries = maxEntries;
		this.clock = clock;
	}

	private MonoTime now() @safe
	{
		return clock is null ? MonoTime.currTime : clock();
	}

	/// Sweep expired entries, evict the oldest idle entry if inserting a new key
	/// would exceed the cap, then store `value` and stamp it as just-active.
	/// Returns false, storing nothing, when the cap is reached and every entry
	/// is busy.
	bool put(string key, V value) @safe
	{
		const t = now();
		sweepDue(t);
		if (auto p = key in nodes)
		{
			(*p).value = value;
			restamp(*p, t);
			return true;
		}
		if (maxEntries != 0)
			while (nodes.length >= maxEntries)
				if (!evictOldest())
					return false;
		auto n = new Node;
		n.key = key;
		n.value = value;
		n.stamp = t;
		nodes[key] = n;
		unusedOrder.append(n);
		return true;
	}

	/// Sweep expired entries, then consume and return the entry for `key`,
	/// setting `found`. The entry is removed (single use).
	V take(string key, out bool found) @safe
	{
		const t = now();
		sweepDue(t);
		if (auto n = live(key, t))
		{
			found = true;
			drop(n);
			return n.value;
		}
		found = false;
		return V.init;
	}

	/// Pointer to the live value for `key`, or `null` when absent. Sweeps expired
	/// entries before the lookup so a session past its idle TTL is not returned.
	/// When `refresh` is set, a hit stamps the entry as just-active so it survives
	/// future idle sweeps.
	V* get(string key, bool refresh) @safe
	{
		const t = now();
		sweepDue(t);
		if (auto n = live(key, t))
		{
			if (refresh)
				restamp(n, t);
			return &n.value;
		}
		return null;
	}

	/// Whether `key` has a live entry; an entry past its idle TTL is dropped and
	/// reported absent.
	bool contains(string key) @safe
	{
		const t = now();
		sweepDue(t);
		return live(key, t) !is null;
	}

	/// Record that `key` has been used, so cap eviction prefers other entries.
	/// The use counts as activity: the entry is stamped just-active, which also
	/// keeps the used list in stamp order as it joins that list's tail.
	void markUsed(string key) @safe
	{
		auto p = key in nodes;
		if (p is null || (*p).used)
			return;
		unusedOrder.unlink(*p);
		(*p).used = true;
		(*p).stamp = now();
		usedOrder.append(*p);
	}

	/// Remove the entry for `key`. Returns whether it existed.
	bool remove(string key) @safe
	{
		auto p = key in nodes;
		if (p is null)
			return false;
		drop(*p);
		return true;
	}

	/// Number of live entries.
	size_t length() @safe
	{
		return nodes.length;
	}

	private void restamp(Node n, MonoTime t) @safe
	{
		n.stamp = t;
		if (n.used)
		{
			usedOrder.unlink(n);
			usedOrder.append(n);
		}
		else
		{
			unusedOrder.unlink(n);
			unusedOrder.append(n);
		}
	}

	private void drop(Node n) @safe
	{
		nodes.remove(n.key);
		busySeen.remove(n.key);
		if (n.used)
			usedOrder.unlink(n);
		else
			unusedOrder.unlink(n);
	}

	/// Drop `n` as expired or evicted and report it to `onEvict`. A no-op when
	/// `n` is no longer stored, as when an earlier `onEvict` removed it.
	private void evict(Node n) @safe
	{
		auto p = n.key in nodes;
		if (p is null || *p !is n)
			return;
		drop(n);
		if (onEvict !is null)
			onEvict(n.key, n.value);
	}

	/// The entry for `key` if present and within its TTL; an expired entry is
	/// dropped.
	private Node live(string key, MonoTime t) @safe
	{
		auto p = key in nodes;
		if (p is null)
			return null;
		auto n = *p;
		if (expired(n, t))
		{
			evict(n);
			return null;
		}
		return n;
	}

	/// Whether `n` is past its idle TTL. A busy entry is restamped instead.
	private bool expired(Node n, MonoTime t) @safe
	{
		if (ttl <= Duration.zero)
			return false;
		if (busy !is null && busy(n.value))
		{
			restamp(n, t);
			busySeen[n.key] = true;
			return false;
		}
		if (busySeen.remove(n.key))
		{
			restamp(n, t);
			return false;
		}
		return t - n.stamp >= ttl;
	}

	private void sweepDue(MonoTime t) @safe
	{
		if (ttl <= Duration.zero || t - lastSweep < ttl / 4)
			return;
		lastSweep = t;
		sweep(t);
	}

	/// Restamp the entries last seen busy, then evict the entries past their
	/// TTL. Each list is in stamp order, so it is walked from its oldest entry
	/// and the walk stops at the first one within its TTL. A busy entry is
	/// restamped, which moves it to the tail; the walk restarts from the head
	/// after each entry, since `onEvict` may unlink others.
	private void sweep(MonoTime t) @safe
	{
		if (ttl <= Duration.zero)
			return;
		foreach (key; busySeen.keys)
		{
			auto p = key in nodes;
			if (p is null)
			{
				busySeen.remove(key);
				continue;
			}
			restamp(*p, t);
			if (busy is null || !busy((*p).value))
				busySeen.remove(key);
		}
		foreach (order; [&unusedOrder, &usedOrder])
			for (auto n = order.head; n !is null && t - n.stamp >= ttl; n = order.head)
			{
				if (busy !is null && busy(n.value))
				{
					restamp(n, t);
					busySeen[n.key] = true;
				}
				else
					evict(n);
			}
	}

	/// Evict the least-recently-active never-used entry, or the
	/// least-recently-active entry when every entry has been used, among the
	/// entries `among` accepts (every entry when null). A busy entry is never
	/// evicted. Returns false when there was no candidate.
	///
	/// Each list is walked from its oldest entry, skipping only busy or
	/// filtered-out entries, so with no filter and no busy entries this is O(1).
	bool evictOldest(scope bool delegate(ref V value) @safe among = null) @safe
	{
		foreach (head; [unusedOrder.head, usedOrder.head])
			for (auto n = head; n !is null; n = n.next)
				if ((among is null || among(n.value)) && (busy is null || !busy(n.value)))
				{
					evict(n);
					return true;
				}
		return false;
	}
}

unittest  // BoundedExpiringMap at its cap evicts in insertion order across many puts
{
	auto m = BoundedExpiringMap!int(Duration.zero, 3, null);
	foreach (i; 0 .. 10)
		m.put([cast(char)('a' + i)], i);
	assert(m.length == 3);
	assert(m.contains("h") && m.contains("i") && m.contains("j"));
}

unittest  // BoundedExpiringMap re-putting a key refreshes its eviction position
{
	auto m = BoundedExpiringMap!int(Duration.zero, 2, null);
	m.put("a", 1);
	m.put("b", 2);
	m.put("a", 3);
	m.put("c", 4);
	assert(!m.contains("b"));
	bool found;
	assert(m.take("a", found) == 3 && found);
}

unittest  // BoundedExpiringMap put/take round-trips and consumes the entry
{
	auto m = BoundedExpiringMap!int(Duration.zero, 0, null);
	m.put("a", 7);
	assert(m.length == 1);
	bool found;
	assert(m.take("a", found) == 7 && found);
	// Consumed: a second take misses.
	m.take("a", found);
	assert(!found);
}

unittest  // BoundedExpiringMap sweeps entries older than the TTL on the next put/take
{
	import core.time : MonoTime, minutes;

	auto clk = MonoTime.currTime;
	auto m = BoundedExpiringMap!int(10.minutes, 0, () @safe => clk);
	m.put("old", 1);
	clk += 11.minutes;
	m.put("fresh", 2);
	assert(m.length == 1);
	bool found;
	m.take("old", found);
	assert(!found);
	m.take("fresh", found);
	assert(found);
}

unittest  // BoundedExpiringMap's sweep still finds an expired entry after markUsed reorders it
{
	import core.time : MonoTime, minutes;

	auto clk = MonoTime.currTime;
	auto m = BoundedExpiringMap!int(10.minutes, 0, () @safe => clk);
	string[] evicted;
	m.onEvict = (string key, int value) @safe { evicted ~= key; };
	m.put("a", 1);
	clk += 5.minutes;
	m.put("b", 2);
	m.markUsed("b");
	clk += 4.minutes;
	m.markUsed("a");
	// Marking "a" used is activity, so it outlives "b".
	clk += 7.minutes;
	m.put("c", 3);
	assert(evicted == ["b"], "the sweep must evict exactly the entries past their TTL");
	assert(m.contains("a"));
}

unittest  // BoundedExpiringMap caps live entries, evicting the oldest by timestamp
{
	import core.time : MonoTime, minutes, seconds;

	auto clk = MonoTime.currTime;
	auto m = BoundedExpiringMap!int(10.minutes, 2, () @safe => clk);
	m.put("a", 1);
	clk += 1.seconds;
	m.put("b", 2);
	clk += 1.seconds;
	// Third put exceeds the cap of 2: the oldest ("a") is evicted.
	m.put("c", 3);
	assert(m.length == 2);
	bool found;
	m.take("a", found);
	assert(!found);
	m.take("b", found);
	assert(found);
	m.take("c", found);
	assert(found);
}

unittest  // BoundedExpiringMap overwriting an existing key does not trigger eviction
{
	auto m = BoundedExpiringMap!int(Duration.zero, 1, null);
	m.put("a", 1);
	m.put("a", 2);
	assert(m.length == 1);
	bool found;
	assert(m.take("a", found) == 2 && found);
}

unittest  // BoundedExpiringMap get(refresh) keeps an in-use entry off the eviction block
{
	import core.time : MonoTime, minutes, seconds;

	auto clk = MonoTime.currTime;
	auto m = BoundedExpiringMap!int(Duration.zero, 2, () @safe => clk);
	m.put("a", 1);
	clk += 1.seconds;
	m.put("b", 2);
	clk += 1.seconds;
	// Touch "a" so "b" becomes least-recently-active.
	assert(*m.get("a", true) == 1);
	m.put("c", 3);
	assert(m.contains("a") && m.contains("c") && !m.contains("b"));
}

unittest  // BoundedExpiringMap remove drops the entry and reports prior presence
{
	auto m = BoundedExpiringMap!int(Duration.zero, 0, null);
	m.put("a", 1);
	assert(m.remove("a"));
	assert(!m.remove("a"));
	assert(m.length == 0);
}

unittest  // BoundedExpiringMap lookups check only their own key between sweeps
{
	import core.time : MonoTime, minutes, seconds;

	auto clk = MonoTime.currTime;
	auto m = BoundedExpiringMap!int(10.minutes, 0, () @safe => clk);
	m.put("a", 1);
	clk += 9.minutes;
	m.put("b", 2);
	clk += 61.seconds; // "a" is now past its TTL
	assert(m.contains("b"));
	assert(m.length == 2, "a lookup of one key must not sweep the whole table");
	assert(!m.contains("a"), "an expired key is never reported present");
	assert(m.length == 1);
}

unittest  // BoundedExpiringMap survives an onEvict that removes another expiring entry
{
	import core.time : MonoTime, minutes;

	auto clk = MonoTime.currTime;
	auto m = BoundedExpiringMap!int(10.minutes, 0, () @safe => clk);
	string[] evicted;
	m.onEvict = (string key, int) @safe {
		evicted ~= key;
		if (evicted.length == 1)
			foreach (other; ["a", "b", "c"])
				if (other != key)
					m.remove(other);
	};
	m.put("a", 1);
	m.put("b", 2);
	m.put("c", 3);
	clk += 5.minutes;
	m.put("d", 4);
	clk += 6.minutes; // a, b and c are past their TTL; d is not
	assert(m.contains("d"));
	assert(evicted.length == 1, "an entry removed by onEvict is not evicted again");
	assert(m.length == 1);
	m.put("e", 5);
	assert(m.evictOldest());
	assert(!m.contains("d") && m.contains("e"), "the activity list stays intact");
}

unittest  // BoundedExpiringMap's sweep visits only the entries past their TTL
{
	import core.time : MonoTime, minutes;
	import std.conv : to;

	auto clk = MonoTime.currTime;
	auto m = BoundedExpiringMap!int(10.minutes, 0, () @safe => clk);
	string[] checked;
	m.busy = (ref int v) @safe { checked ~= v.to!string; return v == 1; };
	m.put("a", 0);
	m.put("b", 1);
	clk += 5.minutes;
	foreach (i; 2 .. 50)
		m.put("k" ~ i.to!string, i);
	clk += 6.minutes; // only a and b are past their TTL
	checked = null;
	m.put("z", 99);
	assert(checked == ["0", "1"], "only expired entries are checked for busy");
	assert(!m.contains("a") && m.contains("b"), "the expired idle entry goes, the busy one stays");
	assert(m.length == 50);
}

unittest  // BoundedExpiringMap gives an entry a fresh TTL once it stops being busy
{
	import core.time : MonoTime, minutes;

	auto clk = MonoTime.currTime;
	auto m = BoundedExpiringMap!int(10.minutes, 0, () @safe => clk);
	bool working = true;
	m.busy = (ref int v) @safe => v == 1 && working;
	m.put("s", 1);
	clk += 11.minutes;
	m.put("tick1", 0); // the sweep finds "s" past its TTL while busy
	clk += 9.minutes;
	working = false; // the long request ends just before "s" would expire again
	clk += 3.minutes;
	m.put("tick2", 0);
	clk += 3.minutes;
	assert(m.contains("s"), "a session must keep its idle TTL after its work ends");
}
