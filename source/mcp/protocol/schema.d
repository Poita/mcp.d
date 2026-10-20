module mcp.protocol.schema;

import vibe.data.json : Json;

import jsonschema : Validator;

@safe:

/// vibe.data serialization policy that maps any `enum` leaf to / from its
/// member *name* (string), rather than vibe's default numeric base value.
///
/// Derived schemas describe enums as `{type:"string", enum:[names…]}`, so both
/// directions of marshalling must agree: struct params/returns and bare-enum
/// values are (de)serialized by-name. The policy only defines
/// `toRepresentation`/`fromRepresentation` for enums, `SumType`s, `SysTime`, `UUID` and `ulong`
/// (see the arms below), so vibe's `isPolicySerializable` is false for every
/// other type and the default behaviour is preserved (it still recurses into
/// nested struct/array fields, applying this rule at any depth).
template EnumByNamePolicy(T) if (is(T == enum))
{
	import std.conv : to;

	static string toRepresentation(T v) @safe
	{
		return v.to!string;
	}

	static T fromRepresentation(string s) @safe
	{
		return s.to!T;
	}
}

/// The `std.sumtype.SumType` arm of `EnumByNamePolicy`: a `SumType` is written
/// as the value it currently holds (serialized under this same policy), matching
/// the `anyOf` of its member schemas that derived schemas advertise. Reading
/// prefers a member whose serialized form has the JSON value's own type (an
/// integer reads as `int`, not `double`), else takes the first member that
/// accepts the value. Among members that read a JSON object, the one whose
/// serialized form keeps the most of the object's keys wins, ties going to the
/// one adding the fewest keys of its own, so a struct that silently drops
/// fields loses to one that holds them all.
template EnumByNamePolicy(T) if (isSumType!T)
{
	static Json toRepresentation(T v)
	{
		import std.sumtype : match;
		import vibe.data.json : JsonSerializer;
		import vibe.data.serialization : serializeWithPolicy;

		return v.match!(held => serializeWithPolicy!(JsonSerializer, EnumByNamePolicy)(held));
	}

	static T fromRepresentation(Json j)
	{
		import std.traits : TemplateArgsOf;
		import vibe.data.json : JsonSerializer;
		import vibe.data.serialization : deserializeWithPolicy, serializeWithPolicy;

		T[] best;
		size_t bestKept, bestAdded;
		static foreach (V; TemplateArgsOf!T)
		{
			try
			{
				auto v = deserializeWithPolicy!(JsonSerializer, EnumByNamePolicy, V)(j);
				auto back = serializeWithPolicy!(JsonSerializer, EnumByNamePolicy)(v);
				if (back.type == j.type)
				{
					if (j.type != Json.Type.object)
						return T(v);
					const kept = sharedKeyCount(j, back);
					const added = back.length - kept;
					if (!best.length || kept > bestKept || (kept == bestKept && added < bestAdded))
					{
						best = [T(v)];
						bestKept = kept;
						bestAdded = added;
					}
				}
			}
			catch (Exception)
			{
			}
		}
		if (best.length)
			return best[0];
		static foreach (V; TemplateArgsOf!T)
		{
			try
				return T(deserializeWithPolicy!(JsonSerializer, EnumByNamePolicy, V)(j));
			catch (Exception)
			{
			}
		}
		throw new Exception("JSON value matches none of the types in " ~ T.stringof);
	}
}

/// The `SysTime` arm of `EnumByNamePolicy`: a `SysTime` is written in UTC, so
/// the value always carries the offset an RFC 3339 `date-time` requires. vibe
/// would otherwise write a local-time `SysTime` (such as `Clock.currTime()`)
/// with no offset at all.
template EnumByNamePolicy(T) if (is(T == imported!"std.datetime.systime".SysTime))
{
	static string toRepresentation(T v) @safe
	{
		return v.toUTC().toISOExtString();
	}

	static T fromRepresentation(string s) @safe
	{
		return T.fromISOExtString(s);
	}
}

/// The `UUID` arm of `EnumByNamePolicy`: a `UUID` is written as its canonical
/// hyphenated string, matching the `format: uuid` string derived schemas
/// advertise. vibe would otherwise write its sixteen raw bytes as an object.
template EnumByNamePolicy(T) if (is(T == imported!"std.uuid".UUID))
{
	static string toRepresentation(T v) @safe
	{
		return v.toString();
	}

	static T fromRepresentation(string s) @safe
	{
		return T(s);
	}
}

/// The `ulong` arm of `EnumByNamePolicy`: vibe stores integers as `long`, so a
/// `ulong` above `long.max` would be written negative. Such a value is written
/// and read as a JSON big integer instead; smaller ones stay plain integers.
template EnumByNamePolicy(T) if (is(immutable T == immutable ulong))
{
	static Json toRepresentation(T v) @safe
	{
		import std.bigint : BigInt;

		return v > long.max ? Json(BigInt(v)) : Json(cast(long) v);
	}

	static T fromRepresentation(Json j) @safe
	{
		import std.bigint : BigInt;
		import std.conv : ConvOverflowException;

		if (j.type == Json.Type.bigInt)
		{
			const b = j.get!BigInt;
			if (b < 0 || b > ulong.max)
				throw new ConvOverflowException("integer out of range for ulong: " ~ j.toString);
			return cast(T) b;
		}
		if (j.type == Json.Type.int_ && j.get!long < 0)
			throw new ConvOverflowException("integer out of range for ulong: " ~ j.toString);
		return cast(T) j.to!long;
	}
}

/// How many of object `a`'s keys object `b` also has.
private size_t sharedKeyCount(Json a, Json b) @safe
{
	size_t n;
	foreach (key; a.get!(Json[string]).byKey)
		if (key in b)
			n++;
	return n;
}

private enum isSumType(T) = imported!"std.sumtype".isSumType!T;

unittest  // a SumType is written as the value it holds, at any depth
{
	import std.sumtype : SumType;
	import vibe.data.json : JsonSerializer;
	import vibe.data.serialization : serializeWithPolicy;

	alias U = SumType!(int, string);
	static struct S
	{
		U u;
		U[] us;
	}

	auto j = serializeWithPolicy!(JsonSerializer, EnumByNamePolicy)(S(U("a"), [
		U(1), U("b")
	]));
	assert(j["u"] == Json("a"), j.toString);
	assert(j["us"] == Json([Json(1), Json("b")]), j.toString);
}

unittest  // a ulong above long.max is written and read back as its exact value
{
	import vibe.data.json : JsonSerializer;
	import vibe.data.serialization : deserializeWithPolicy, serializeWithPolicy;

	static struct S
	{
		ulong n;
		ulong[] ns;
	}

	auto j = serializeWithPolicy!(JsonSerializer, EnumByNamePolicy)(S(ulong.max, [
		1, 1UL << 63
	]));
	assert(j["n"].toString == "18446744073709551615", j.toString);
	assert(j["ns"].toString == "[1,9223372036854775808]", j.toString);
	auto back = deserializeWithPolicy!(JsonSerializer, EnumByNamePolicy, S)(j);
	assert(back.n == ulong.max && back.ns == [1, 1UL << 63]);
	assert(serializeWithPolicy!(JsonSerializer, EnumByNamePolicy)(ulong(7)).type == Json.Type.int_);
}

unittest  // a UUID is written and read back as its string form
{
	import std.uuid : UUID;
	import vibe.data.json : JsonSerializer;
	import vibe.data.serialization : deserializeWithPolicy, serializeWithPolicy;

	static struct S
	{
		UUID id;
	}

	enum text = "8ab3060e-2cba-4f23-b74c-b52db3bdfb46";
	auto j = serializeWithPolicy!(JsonSerializer, EnumByNamePolicy)(S(UUID(text)));
	assert(j["id"] == Json(text), j.toString);
	assert(deserializeWithPolicy!(JsonSerializer, EnumByNamePolicy, S)(j).id == UUID(text));
}

unittest  // a SumType reads back as the member matching the JSON value's own type
{
	import std.sumtype : SumType, has;
	import vibe.data.json : JsonSerializer;
	import vibe.data.serialization : deserializeWithPolicy;

	alias N = SumType!(double, int);
	auto n = deserializeWithPolicy!(JsonSerializer, EnumByNamePolicy, N)(Json(3));
	assert(n.has!int);
}

unittest  // a SumType of structs reads an object as the member that keeps every key
{
	import std.sumtype : SumType, has, match;
	import vibe.data.json : JsonSerializer, parseJsonString;
	import vibe.data.serialization : deserializeWithPolicy;

	static struct A
	{
		int x;
	}

	static struct B
	{
		int x;
		int y;
	}

	alias U = SumType!(A, B);
	auto u = deserializeWithPolicy!(JsonSerializer, EnumByNamePolicy, U)(
			parseJsonString(`{"x":1,"y":2}`));
	assert(u.has!B);
	assert(u.match!((B b) => b.y, (A a) => -1) == 2);
}

unittest  // a SumType of structs prefers the member with no keys beyond the input's
{
	import std.sumtype : SumType, has;
	import vibe.data.json : JsonSerializer, parseJsonString;
	import vibe.data.serialization : deserializeWithPolicy, optional;

	static struct B
	{
		int x;
		@optional int y;
	}

	static struct A
	{
		int x;
	}

	alias U = SumType!(B, A);
	auto u = deserializeWithPolicy!(JsonSerializer, EnumByNamePolicy, U)(parseJsonString(`{"x":1}`));
	assert(u.has!A);
}

/// Compile a vibe `Json` schema document into a reusable `Validator`, or `null`
/// when `schema` imposes no constraint (the boolean schema `true`, or any value
/// that is neither an object nor a boolean). The boolean schema `false` yields a
/// validator that rejects every value. Throws
/// -32602 (`McpException`) when the schema is a malformed object or declares an
/// unsupported `$schema` dialect, surfacing a bad schema where the tool is
/// registered rather than silently under-validating each request, and keeping a
/// peer-supplied schema's failure inside the MCP error model.
Validator makeValidator(Json schema)
{
	import jsonschema : SchemaException;
	import jsonschema.vibejson : compileSchema;
	import mcp.protocol.errors : invalidParams;

	if (schema.type == Json.Type.bool_)
	{
		if (schema.get!bool)
			return null;
		// `false` is the schema no value satisfies, spelled as an object.
		schema = Json(["not": Json.emptyObject]);
	}
	if (schema.type != Json.Type.object)
		return null;
	try
		return compileSchema(schema);
	catch (SchemaException e)
		throw invalidParams("invalid JSON Schema: " ~ e.msg);
}

/// Validate a vibe `Json` `value` against a pre-compiled `validator` (a `null`
/// validator imposes no constraint). Returns "" when the value conforms,
/// otherwise a human-readable, newline-separated description of the violations.
string validationError(Validator validator, Json value)
{
	import jsonschema.vibejson : validateJson;

	if (validator is null)
		return "";
	return validateJson(validator, value).toString();
}

/// One-shot convenience: compile `schema` and validate `value` in a single call,
/// with full JSON Schema 2020-12 semantics. On a hot path (e.g. per request)
/// prefer `makeValidator` once plus `validationError` per call, so the schema is
/// compiled only once.
string validateAgainstSchema(Json value, Json schema)
{
	return validationError(makeValidator(schema), value);
}

unittest  // validateAgainstSchema accepts a conforming object, rejects a wrong type
{
	struct Args
	{
		string name;
	}

	import mcp.api.binding : jsonSchemaOf;

	auto schema = jsonSchemaOf!Args;
	assert(validateAgainstSchema(Json(["name": Json("ok")]), schema) == "");
	assert(validateAgainstSchema(Json(["name": Json(42)]), schema).length > 0);
}

unittest  // validateAgainstSchema reports a missing required property
{
	struct Args
	{
		string name;
	}

	import mcp.api.binding : jsonSchemaOf;

	auto schema = jsonSchemaOf!Args;
	assert(validateAgainstSchema(Json.emptyObject, schema).length > 0);
}

unittest  // a non-object schema imposes no constraint
{
	assert(validateAgainstSchema(Json("anything"), Json.undefined) == "");
	assert(validateAgainstSchema(Json(42), Json.emptyObject) == "");
}

unittest  // full 2020-12: a $ref/$defs schema is now resolved and enforced
{
	import vibe.data.json : parseJsonString;

	// The validator resolves $ref against $defs, so a value whose nested type is
	// wrong is rejected.
	auto schema = parseJsonString(`{
		"type": "object",
		"properties": {"point": {"$ref": "#/$defs/pt"}},
		"required": ["point"],
		"$defs": {"pt": {"type": "object", "properties": {"x": {"type": "integer"}}, "required": ["x"]}}
	}`);
	assert(validateAgainstSchema(parseJsonString(`{"point": {"x": 1}}`), schema) == "");
	assert(validateAgainstSchema(parseJsonString(`{"point": {"x": "no"}}`), schema).length > 0);
	assert(validateAgainstSchema(parseJsonString(`{}`), schema).length > 0);
}

unittest  // an unsupported $schema dialect is rejected with -32602 (MCP "reject unknown dialects")
{
	import vibe.data.json : parseJsonString;
	import mcp.protocol.errors : ErrorCode, McpException;
	import std.exception : collectException;

	auto schema = parseJsonString(
			`{"$schema": "http://json-schema.org/draft-04/schema#", "type": "string"}`);
	auto e = collectException!McpException(makeValidator(schema));
	assert(e !is null && e.code == ErrorCode.invalidParams);
}

unittest  // validateAgainstSchema reports a malformed schema as -32602
{
	import vibe.data.json : parseJsonString;
	import mcp.protocol.errors : ErrorCode, McpException;
	import std.exception : collectException;

	auto schema = parseJsonString(
			`{"$schema": "http://json-schema.org/draft-04/schema#", "type": "string"}`);
	auto e = collectException!McpException(validateAgainstSchema(Json("x"), schema));
	assert(e !is null && e.code == ErrorCode.invalidParams);
}

unittest  // a draft-07 dialect schema is accepted and enforced (not rejected)
{
	import vibe.data.json : parseJsonString;

	// jsonschema supports 2020-12, 2019-09, and draft-07; a schema that declares
	// a supported non-default dialect compiles and validates rather than throwing.
	auto v = makeValidator(parseJsonString(
			`{"$schema": "http://json-schema.org/draft-07/schema#", "type": "integer"}`));
	assert(v !is null);
	assert(validationError(v, Json(7)) == "");
	assert(validationError(v, Json("no")).length > 0);
}

unittest  // a boolean false schema rejects every value
{
	auto v = makeValidator(Json(false));
	assert(v !is null);
	assert(validationError(v, Json(1)).length > 0);
	assert(validationError(v, Json.emptyObject).length > 0);
	assert(validateAgainstSchema(Json("x"), Json(false)).length > 0);
}

unittest  // a boolean true schema imposes no constraint
{
	assert(makeValidator(Json(true)) is null);
	assert(validateAgainstSchema(Json("x"), Json(true)) == "");
}

unittest  // makeValidator returns null for a non-object schema
{
	assert(makeValidator(Json.undefined) is null);
	assert(makeValidator(Json("x")) is null);
	assert(makeValidator(Json.emptyObject) !is null);
}

unittest  // a precompiled validator validates repeatedly with independent results
{
	struct Args
	{
		int n;
	}

	import mcp.api.binding : jsonSchemaOf;

	auto v = makeValidator(jsonSchemaOf!Args);
	assert(validationError(v, Json(["n": Json(1)])) == "");
	assert(validationError(v, Json(["n": Json("bad")])).length > 0);
	assert(validationError(v, Json(["n": Json(2)])) == "");
}

unittest  // a SysTime is written in UTC, so it always carries an offset
{
	import core.time : hours;
	import std.datetime.date : DateTime;
	import std.datetime.systime : SysTime;
	import std.datetime.timezone : LocalTime, SimpleTimeZone;
	import vibe.data.json : JsonSerializer;
	import vibe.data.serialization : serializeWithPolicy;

	static struct S
	{
		SysTime when;
	}

	const plus2 = new immutable SimpleTimeZone(2.hours);
	auto j = serializeWithPolicy!(JsonSerializer, EnumByNamePolicy)(
			S(SysTime(DateTime(2024, 1, 1, 10, 0, 0), plus2)));
	assert(j["when"] == Json("2024-01-01T08:00:00Z"), j.toString);

	auto local = serializeWithPolicy!(JsonSerializer, EnumByNamePolicy)(
			SysTime(DateTime(2024, 1, 1, 10, 0, 0), LocalTime()));
	assert(local.get!string[$ - 1] == 'Z', local.toString);
}

unittest  // a structured tool result carries a SysTime as a UTC date-time
{
	import mcp.protocol.types : CallToolResult;
	import std.datetime.date : DateTime;
	import std.datetime.systime : SysTime;
	import std.datetime.timezone : LocalTime;

	static struct R
	{
		SysTime at;
	}

	auto r = CallToolResult.structured(R(SysTime(DateTime(2024, 6, 1, 12, 30, 0), LocalTime())));
	const s = r.structuredContent["at"].get!string;
	assert(s[$ - 1] == 'Z', s);
	assert(SysTime.fromISOExtString(s) == SysTime(DateTime(2024, 6, 1, 12, 30, 0), LocalTime()));
}
