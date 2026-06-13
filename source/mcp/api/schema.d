module mcp.api.schema;

import std.traits : isInstanceOf, isArray, isSomeString, isIntegral, isFloatingPoint;
import std.typecons : Nullable;

import vibe.data.json : Json;

import jsonschema : Validator;

@safe:

/// Generate a JSON Schema (2020-12) fragment describing the D type `T`, rendered
/// as a vibe `Json`.
///
/// Delegates to the `jsonschema` package's compile-time generator — the canonical
/// home for D-type → JSON Schema mapping and the constraint UDAs (`@minimum`,
/// `@pattern`, …) re-exported from `mcp.api.attributes`. `inlineSubschemas` is set
/// so the schema is fully self-contained (no `$defs`/`$ref`): MCP embeds tool
/// `inputSchema`/`outputSchema` and elicitation `requestedSchema` directly, and
/// not every client resolves `$ref` within an embedded schema. The compile-time
/// settings overload rejects a directly or mutually recursive `T` with a
/// `static assert` (as the previous inlining generator did by construction).
Json jsonSchemaOf(T)()
{
	import jsonschema : generate = jsonSchemaOf, GeneratorSettings;
	import jsonschema.vibejson : nodeToVibeJson;

	enum GeneratorSettings settings = {inlineSubschemas: true};
	return nodeToVibeJson(generate!(T, settings)());
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
/// `jsonSchemaOf!T`). Used by `RequestContext.elicit!T` and
/// `InputRequest.elicitation!T` to reject nested/array structs at compile time.
template isFlatElicitationStruct(T)
{
	import std.meta : allSatisfy;

	static if (is(T == struct))
		enum isFlatElicitationStruct = allSatisfy!(isElicitScalar, typeof(T.tupleof));
	else
		enum isFlatElicitationStruct = false;
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

unittest  // jsonSchemaOf maps a scalar to its primitive type
{
	auto s = jsonSchemaOf!int;
	assert(s["type"].get!string == "integer");
}

unittest  // jsonSchemaOf maps a struct to an object with properties and required
{
	struct Args
	{
		string name;
		Nullable!int count;
	}

	auto s = jsonSchemaOf!Args;
	assert(s["type"].get!string == "object");
	assert("name" in s["properties"]);
	assert("count" in s["properties"]);
	// `name` is required; the Nullable `count` is optional.
	import std.algorithm : canFind;
	import std.array : array;

	auto req = s["required"][].array;
	assert(req.canFind(Json("name")));
	assert(!req.canFind(Json("count")));
}

unittest  // jsonSchemaOf inlines a shared nested struct rather than emitting $ref
{
	struct Inner
	{
		int a;
	}

	struct Outer
	{
		Inner first;
		Inner second;
	}

	auto s = jsonSchemaOf!Outer;
	// inlineSubschemas: the shared `Inner` is expanded at both use sites and the
	// document carries no $defs/$ref that an MCP client would have to resolve.
	assert("$defs" !in s);
	assert(s["properties"]["first"]["type"].get!string == "object");
	assert(s["properties"]["second"]["properties"]["a"]["type"].get!string == "integer");
}

unittest  // validateAgainstSchema accepts a conforming object, rejects a wrong type
{
	struct Args
	{
		string name;
	}

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

	// The previous SDK validator ignored $ref (unknown keyword => satisfied);
	// the jsonschema-backed one resolves it, so a wrong-typed value is rejected.
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
