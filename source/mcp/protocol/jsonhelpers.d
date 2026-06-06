/// Internal typed helpers for reading optional fields out of a `vibe.data.json.Json`
/// object. They centralize the "is the key present AND of the expected type"
/// guard that every `fromJson` body would otherwise hand-roll, giving one place
/// to audit how malformed wire input is handled.
module mcp.protocol.jsonhelpers;

import std.traits : isIntegral, isFloatingPoint;
import std.typecons : Nullable;
import vibe.data.json : Json;

@safe:

/// The `Json.Type` that backs a `tryGet`/`getOr` of type `T`. Kept explicit so
/// the supported set stays auditable; unsupported `T` fails to compile.
private template jsonTypeFor(T)
{
	static if (is(T == string))
		enum jsonTypeFor = Json.Type.string;
	else static if (is(T == bool))
		enum jsonTypeFor = Json.Type.bool_;
	else static if (isIntegral!T)
		enum jsonTypeFor = Json.Type.int_;
	else static if (isFloatingPoint!T)
		enum jsonTypeFor = Json.Type.float_;
	else
		static assert(false, "jsonhelpers: unsupported scalar type " ~ T.stringof);
}

/// Read `j[key]` as `T`, returning `fallback` when the key is absent or present
/// with a mismatched JSON type. Never throws on a type mismatch (unlike the bare
/// `j[key].get!T`), so it is safe for tolerant wire parsing.
T getOr(T)(Json j, string key, T fallback) @safe
{
	if (j.type != Json.Type.object)
		return fallback;
	auto p = key in j;
	if (p is null || p.type != jsonTypeFor!T)
		return fallback;
	return (*p).get!T;
}

/// Assign `j[key]` into `val` only when the key is present and its JSON type
/// matches `T`; leaves `val` untouched otherwise (preserving any default).
/// Returns whether the assignment happened.
bool tryGet(T)(Json j, string key, ref T val) @safe if (!is(T : Nullable!U, U))
{
	if (j.type != Json.Type.object)
		return false;
	auto p = key in j;
	if (p is null || p.type != jsonTypeFor!T)
		return false;
	val = (*p).get!T;
	return true;
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
