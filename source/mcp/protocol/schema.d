module mcp.protocol.schema;

import std.traits : isInstanceOf, isArray, isSomeString, isIntegral, isFloatingPoint;
import std.typecons : Nullable;

import vibe.data.json : Json;

import jsonschema : Validator;

@safe:

/// vibe.data serialization policy that maps any `enum` leaf to / from its
/// member *name* (string), rather than vibe's default numeric base value.
///
/// Derived schemas describe enums as `{type:"string", enum:[names…]}`, so both
/// directions of marshalling must agree: struct params/returns and bare-enum
/// values are (de)serialized by-name. The policy only defines
/// `toRepresentation`/`fromRepresentation` for enums and `SumType`s (see the
/// `SumType` arm below), so vibe's `isPolicySerializable` is false for every
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

		return v.match!(held => () @trusted {
			return serializeWithPolicy!(JsonSerializer, EnumByNamePolicy)(held);
		}());
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
				auto v = () @trusted {
					return deserializeWithPolicy!(JsonSerializer, EnumByNamePolicy, V)(j);
				}();
				auto back = () @trusted {
					return serializeWithPolicy!(JsonSerializer, EnumByNamePolicy)(v);
				}();
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
				return T(() @trusted {
					return deserializeWithPolicy!(JsonSerializer, EnumByNamePolicy, V)(j);
				}());
			catch (Exception)
			{
			}
		}
		throw new Exception("JSON value matches none of the types in " ~ T.stringof);
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

	auto j = () @trusted {
		return serializeWithPolicy!(JsonSerializer, EnumByNamePolicy)(S(U("a"), [
			U(1), U("b")
		]));
	}();
	assert(j["u"] == Json("a"), j.toString);
	assert(j["us"] == Json([Json(1), Json("b")]), j.toString);
}

unittest  // a SumType reads back as the member matching the JSON value's own type
{
	import std.sumtype : SumType, has;
	import vibe.data.json : JsonSerializer;
	import vibe.data.serialization : deserializeWithPolicy;

	alias N = SumType!(double, int);
	auto n = () @trusted {
		return deserializeWithPolicy!(JsonSerializer, EnumByNamePolicy, N)(Json(3));
	}();
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
	auto u = () @trusted {
		return deserializeWithPolicy!(JsonSerializer, EnumByNamePolicy, U)(
				parseJsonString(`{"x":1,"y":2}`));
	}();
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
	auto u = () @trusted {
		return deserializeWithPolicy!(JsonSerializer, EnumByNamePolicy, U)(
				parseJsonString(`{"x":1}`));
	}();
	assert(u.has!A);
}

/// True when `F` is a scalar permitted as an elicitation form field: a
/// bool/integer/floating/string/enum, a `Nullable` of one, or a flat array of a
/// primitive enum (a multi-select). No nested objects or arrays of objects.
template isElicitScalar(F)
{
	static if (isInstanceOf!(Nullable, F))
		enum isElicitScalar = isElicitScalar!(typeof(F.init.get()));
	else static if (isArray!F && !isSomeString!F) // a multi-select array of enum members (a flat array of a primitive
		// enum), e.g. `Color[]`, is a permitted form field (array items enum).
		enum isElicitScalar = is(typeof(F.init[0]) == enum);
	else
		enum isElicitScalar = is(F == bool) || isIntegral!F
			|| isFloatingPoint!F || isSomeString!F || is(F == enum);
}

/// True when `T` is a flat struct whose every field is an `isElicitScalar`, i.e. a
/// valid type to derive an elicitation form `requestedSchema` from (via
/// `elicitationSchemaOf!T`). Used by `RequestContext.elicit!T` and `elicitationRequest!T`
/// to reject nested/array structs at compile time.
template isFlatElicitationStruct(T)
{
	import std.meta : allSatisfy;

	static if (is(T == struct))
		enum isFlatElicitationStruct = allSatisfy!(isElicitScalar, typeof(T.tupleof));
	else
		enum isFlatElicitationStruct = false;
}

/// Build a form-`elicitation` `InputRequest` whose `requestedSchema` is derived
/// from the flat struct `T` via `elicitationSchemaOf!T` (same compile-time flat-struct
/// restriction as `RequestContext.elicit!T`). This convenience lives beside
/// `jsonSchemaOf` because deriving a schema from a D type is reflection work; the
/// `InputRequest.elicitation(string, string, Json)` overload in `mcp.protocol.mrtr`
/// takes a ready-made schema and so stays free of any schema/reflection dependency.
auto elicitationRequest(T)(string id, string message) @safe
{
	import mcp.protocol.mrtr : InputRequest;

	static assert(isFlatElicitationStruct!T, "elicitationRequest!T requires a flat struct of scalar fields (string/number/integer/boolean/enum); " ~ T
			.stringof ~ " has a nested or non-scalar field");
	return InputRequest.elicitation(id, message, elicitationSchemaOf!T);
}

/// The elicitation form `requestedSchema` for the flat struct `T`. Elicitation
/// properties must be primitive schemas, so a `Nullable` field renders as its
/// bare primitive (no `anyOf` null branch) and is optional by being absent
/// from `required`.
Json elicitationSchemaOf(T)()
{
	import jsonschema : generate = jsonSchemaOf, GeneratorSettings;
	import jsonschema.vibejson : nodeToVibeJson;

	static assert(isFlatElicitationStruct!T, "elicitationSchemaOf!T requires a flat struct of scalar fields (string/number/integer/boolean/enum); " ~ T
			.stringof ~ " has a nested or non-scalar field");
	enum settings = () {
		GeneratorSettings s;
		s.inlineSubschemas = true;
		s.nullableOmitsNull = true;
		return s;
	}();
	return nodeToVibeJson(generate!(T, settings)());
}

@safe unittest  // elicitationRequest!T derives requestedSchema from a flat struct
{
	import vibe.data.json : Json;

	static struct Details
	{
		int travelers;
		bool insurance;
	}

	auto ir = elicitationRequest!Details("e2", "Details?");
	assert(ir.type == "elicitation");
	assert(ir.params["message"].get!string == "Details?");
	assert(ir.params["requestedSchema"] == elicitationSchemaOf!Details);
}

@safe unittest  // elicitationRequest!T renders a Nullable field as a bare primitive, optional via required
{
	import std.typecons : Nullable;

	static struct Contact
	{
		string name;
		Nullable!int age;
	}

	const schema = elicitationRequest!Contact("e3", "Contact?").params["requestedSchema"];
	const age = schema["properties"]["age"];
	assert(age["type"].get!string == "integer");
	assert("anyOf" !in age);
	assert(schema["required"].length == 1 && schema["required"][0].get!string == "name");
	assert(elicitationSchemaOf!Contact == schema);
}

@safe unittest  // elicitationRequest!T rejects a non-flat struct at compile time
{
	static struct Inner
	{
		int x;
	}

	static struct Nested
	{
		Inner inner;
	}

	static assert(!__traits(compiles, elicitationRequest!Nested("e", "m")));
}

/// Compile a vibe `Json` schema document into a reusable `Validator`, or `null`
/// when `schema` is not a JSON object (and so imposes no constraint). Throws a
/// `jsonschema.SchemaException` when the schema is a malformed object or declares
/// an unsupported `$schema` dialect, surfacing a bad schema where the tool is
/// registered rather than silently under-validating each request.
Validator makeValidator(Json schema)
{
	import jsonschema.vibejson : compileSchema;

	if (schema.type != Json.Type.object)
		return null;
	return compileSchema(schema);
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

unittest  // an unsupported $schema dialect is rejected (MCP "reject unknown dialects")
{
	import vibe.data.json : parseJsonString;
	import jsonschema : SchemaException;
	import std.exception : assertThrown;

	auto schema = parseJsonString(
			`{"$schema": "http://json-schema.org/draft-04/schema#", "type": "string"}`);
	assertThrown!SchemaException(makeValidator(schema));
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

unittest  // isFlatElicitationStruct accepts a flat scalar struct, rejects nesting
{
	struct Flat
	{
		string s;
		int n;
		Nullable!bool b;
	}

	struct Nested
	{
		Flat inner;
	}

	static assert(isFlatElicitationStruct!Flat);
	static assert(!isFlatElicitationStruct!Nested);
}
