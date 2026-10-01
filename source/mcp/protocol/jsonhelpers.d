/// Internal typed helpers for reading optional fields out of a `vibe.data.json.Json`
/// object. They centralize the "is the key present AND of the expected type"
/// guard that every `fromJson` body would otherwise hand-roll, giving one place
/// to audit how malformed wire input is handled.
module mcp.protocol.jsonhelpers;

import std.traits : isIntegral, isFloatingPoint;
import std.typecons : Nullable;
import vibe.data.json : Json;

@safe:

/// Returns true when `t` is a JSON type that can legitimately hold a value of
/// type `T`. For integral `T`, both `Type.int_` and `Type.bigInt` are accepted:
/// vibe.d parses JSON integers outside `long`'s range as `Type.bigInt`, and the
/// range check against `T` happens when the value is read.
private bool typeMatchesFor(T)(Json.Type t) pure nothrow @safe @nogc
{
	static if (is(T == string))
		return t == Json.Type.string;
	else static if (is(T == bool))
		return t == Json.Type.bool_;
	else static if (isIntegral!T)
		return t == Json.Type.int_ || t == Json.Type.bigInt;
	else static if (isFloatingPoint!T)
		return t == Json.Type.float_;
	else
		static assert(false, "jsonhelpers: unsupported scalar type " ~ T.stringof);
}

/// Convert an integer-typed node `v` (`Type.int_` or `Type.bigInt`) to the
/// integral `T` when the value lies within `T`'s range, assigning it to `result`.
/// Returns false, leaving `result` untouched, when it does not fit.
private bool integralInRange(T)(Json v, ref T result) @safe
{
	import std.bigint : BigInt;

	if (v.type == Json.Type.int_)
	{
		immutable long n = v.get!long;
		static if (T.sizeof < long.sizeof || is(T == long))
		{
			if (n < T.min || n > T.max)
				return false;
		}
		else
		{
			if (n < 0)
				return false;
		}
		result = cast(T) n;
		return true;
	}
	immutable BigInt b = v.get!BigInt;
	if (b < BigInt(T.min) || b > BigInt(T.max))
		return false;
	static if (is(T == ulong))
		result = b.getDigit!ulong(0);
	else
		result = cast(T) b.toLong;
	return true;
}

/// Read `j[key]` as `T`, returning `fallback` when the key is absent, present
/// with a mismatched JSON type, or (for narrow integral T) when the wire value
/// is outside T's range. Never throws, so it is safe for tolerant wire parsing.
T getOr(T)(Json j, string key, T fallback) @safe
{
	if (j.type != Json.Type.object)
		return fallback;
	auto p = key in j;
	if (p is null || !typeMatchesFor!T(p.type))
		return fallback;
	static if (isIntegral!T)
	{
		T parsed;
		return integralInRange(*p, parsed) ? parsed : fallback;
	}
	else
	{
		return (*p).get!T;
	}
}

/// Assign `j[key]` into `val` only when the key is present, its JSON type
/// matches `T`, and (for narrow integral T) the wire value fits in T's range.
/// Leaves `val` untouched otherwise (preserving any default).
/// Returns whether the assignment happened. Never throws.
bool tryGet(T)(Json j, string key, ref T val) @safe if (!is(T : Nullable!U, U))
{
	if (j.type != Json.Type.object)
		return false;
	auto p = key in j;
	if (p is null || !typeMatchesFor!T(p.type))
		return false;
	static if (isIntegral!T)
	{
		if (!integralInRange(*p, val))
			return false;
	}
	else
	{
		val = (*p).get!T;
	}
	return true;
}

/// `v` as a JSON number (integer or float), for the spec `number` field `what`.
/// Throws -32602 for any other JSON type, including a numeric string.
double numberOrThrow(Json v, string what) @safe
{
	import mcp.protocol.errors : invalidParams;

	switch (v.type)
	{
	case Json.Type.int_:
		return cast(double) v.get!long;
	case Json.Type.bigInt:
		return v.to!double;
	case Json.Type.float_:
		return v.get!double;
	default:
		throw invalidParams("'" ~ what ~ "' must be a number");
	}
}

/// Throw -32602 unless `j` is a JSON object. `what` names the value in the
/// error message. Every `fromJson` for an object-shaped type calls this first,
/// so a peer sending e.g. a number where an object belongs gets invalidParams
/// rather than an internal JSON type error.
void requireObject(Json j, string what) @safe
{
	import mcp.protocol.errors : invalidParams;

	if (j.type != Json.Type.object)
		throw invalidParams("'" ~ what ~ "' must be a JSON object");
}

/// `v` as a string, for the field `what`. Throws -32602 for any other JSON type.
string stringOrThrow(Json v, string what) @safe
{
	import mcp.protocol.errors : invalidParams;

	if (v.type != Json.Type.string)
		throw invalidParams("'" ~ what ~ "' must be a string");
	return v.get!string;
}

/// `Nullable` overload: assigns the unwrapped value into `val` (leaving it
/// untouched — preserving any pre-set default — on a missing/mismatched field),
/// so a struct's `Nullable!T` field can be filled directly without a temporary.
bool tryGet(N : Nullable!T, T)(Json j, string key, ref N val) @safe
{
	T tmp;
	if (!tryGet(j, key, tmp))
		return false;
	val = tmp;
	return true;
}

@safe unittest  // getOr returns the value when the key is present and well-typed
{
	Json j = Json.emptyObject;
	j["name"] = "abc";
	assert(j.getOr("name", "") == "abc");
}

@safe unittest  // getOr falls back when the key is absent
{
	Json j = Json.emptyObject;
	assert(j.getOr("missing", "def") == "def");
}

@safe unittest  // getOr falls back on a type mismatch instead of throwing
{
	Json j = Json.emptyObject;
	j["n"] = 5;
	assert(j.getOr("n", "fallback") == "fallback");
}

@safe unittest  // getOr reads integers and booleans
{
	Json j = Json.emptyObject;
	j["count"] = 7;
	j["flag"] = true;
	assert(j.getOr("count", 0L) == 7);
	assert(j.getOr("flag", false) == true);
}

@safe unittest  // getOr reads a bigInt-typed node above long.max into ulong exactly
{
	import vibe.data.json : parseJsonString;

	Json j = parseJsonString(`{"size": 9223372036854775808}`);
	assert(j.getOr("size", 0UL) == 9_223_372_036_854_775_808UL);
}

@safe unittest  // tryGet reads a bigInt-typed node above long.max into ulong exactly
{
	import vibe.data.json : parseJsonString;

	Json j = parseJsonString(`{"size": 9223372036854775808}`);
	ulong val = 0;
	assert(tryGet(j, "size", val));
	assert(val == 9_223_372_036_854_775_808UL);
}

@safe unittest  // getOr falls back instead of throwing when a bigInt exceeds long
{
	import vibe.data.json : parseJsonString;

	Json j = parseJsonString(`{"n": 9223372036854775808, "m": -9223372036854775809}`);
	assert(j.getOr("n", 3L) == 3);
	assert(j.getOr("m", 3L) == 3);
	assert(j.getOr("n", 3) == 3);
}

@safe unittest  // getOr falls back when a bigInt exceeds ulong.max
{
	import vibe.data.json : parseJsonString;

	Json j = parseJsonString(`{"n": 18446744073709551616}`);
	assert(j.getOr("n", 5UL) == 5);
}

@safe unittest  // getOr falls back on a negative value for an unsigned type
{
	Json j = Json.emptyObject;
	j["n"] = -1;
	assert(j.getOr("n", 5UL) == 5);
	assert(j.getOr("n", 5u) == 5);
}

@safe unittest  // tryGet rejects a negative value for an unsigned type
{
	Json j = Json.emptyObject;
	j["n"] = -1;
	ulong val = 9;
	assert(!tryGet(j, "n", val));
	assert(val == 9);
}

@safe unittest  // tryGet leaves val untouched instead of throwing when a bigInt exceeds long
{
	import vibe.data.json : parseJsonString;

	Json j = parseJsonString(`{"n": 9223372036854775808}`);
	long val = 4;
	assert(!tryGet(j, "n", val));
	assert(val == 4);
}

@safe unittest  // tryGet assigns and reports true on a matching field
{
	Json j = Json.emptyObject;
	j["title"] = "hello";
	string s;
	assert(tryGet(j, "title", s));
	assert(s == "hello");
}

@safe unittest  // tryGet leaves the target untouched and returns false on mismatch
{
	Json j = Json.emptyObject;
	j["title"] = 42;
	string s = "orig";
	assert(!tryGet(j, "title", s));
	assert(s == "orig");
}

@safe unittest  // tryGet(Nullable) sets the wrapped value and returns true when key is present
{
	Json j = Json.emptyObject;
	j["name"] = "hello";
	Nullable!string n;
	assert(tryGet(j, "name", n));
	assert(!n.isNull && n.get == "hello");
}

@safe unittest  // tryGet(Nullable) leaves a pre-set non-null val untouched and returns false when key is absent
{
	Json j = Json.emptyObject;
	Nullable!string s = "sentinel";
	assert(!tryGet(j, "missing", s));
	assert(!s.isNull);
	assert(s.get == "sentinel");
}

@safe unittest  // getOr returns fallback instead of throwing when wire int exceeds narrow T.max
{
	// A long value that fits JSON int_ but exceeds int.max; get!int would throw
	// in vibe.d, violating the documented no-throw guarantee.
	Json j = Json.emptyObject;
	j["code"] = Json(long(2_147_483_648L)); // int.max + 1
	int result = j.getOr("code", -1);
	assert(result == -1);
}

@safe unittest  // tryGet returns false instead of throwing when wire int exceeds narrow T.max
{
	Json j = Json.emptyObject;
	j["code"] = Json(long(2_147_483_648L)); // int.max + 1
	int val = 99;
	bool assigned = tryGet(j, "code", val);
	assert(!assigned);
	assert(val == 99);
}

@safe unittest  // requireObject throws -32602 naming the field for a non-object value
{
	import mcp.protocol.errors : ErrorCode, McpException;
	import std.exception : collectException;
	import std.algorithm.searching : canFind;

	auto ex = cast(McpException) collectException(requireObject(Json(5), "capabilities"));
	assert(ex !is null && ex.code == ErrorCode.invalidParams);
	assert(ex.msg.canFind("capabilities"));
}

@safe unittest  // requireObject accepts a JSON object
{
	requireObject(Json.emptyObject, "x");
}
