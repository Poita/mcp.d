module mcp.api.schema;

import std.traits;
import std.typecons : Nullable;
import std.conv : to;
import std.sumtype : isSumType;

import vibe.data.json : Json;

@safe:

/// True when `T` is one of the `std.datetime` value types. Imported lazily so
/// the trait does not force a `std.datetime` dependency on callers that never
/// use it.
private template isStdDateTime(T)
{
	import std.datetime.systime : SysTime;
	import std.datetime.date : DateTime, Date, TimeOfDay;

	enum isStdDateTime = is(T == SysTime) || is(T == DateTime) || is(T == Date) || is(T == TimeOfDay);
}

/// The JSON Schema `format` keyword value for a `std.datetime` type. `SysTime`
/// and `DateTime` carry both date and time components, so they map to
/// `"date-time"`. `Date` encodes only a calendar date (`"date"`) and `TimeOfDay`
/// encodes only a wall-clock time (`"time"`).
private template stdDateTimeFormat(T)
{
	import std.datetime.systime : SysTime;
	import std.datetime.date : DateTime, Date, TimeOfDay;

	static if (is(T == Date))
		enum stdDateTimeFormat = "date";
	else static if (is(T == TimeOfDay))
		enum stdDateTimeFormat = "time";
	else
		enum stdDateTimeFormat = "date-time";
}

/// Generate a JSON Schema (2020-12) fragment describing the D type `T`.
///
/// The mapping is complete and fully recursive — every type expressible as a
/// tool parameter or structured result maps to a faithful schema. Mapping:
///
/// - `bool` -> `{type: "boolean"}`
/// - integral -> `{type: "integer"}`
/// - floating point -> `{type: "number"}`
/// - `string` -> `{type: "string"}`
/// - `enum` -> `{type: "string", enum: [members…]}`
/// - arrays/slices -> `{type: "array", items: <recursive>}`
/// - associative arrays (string keys) ->
///   `{type: "object", additionalProperties: <recursive>}`
/// - `struct` -> `{type: "object", properties: <recursive>,
///   required: <fields that are neither `Nullable!T` nor have a default>}`
/// - `Nullable!T` -> the schema of `T` (optionality is handled by the
///   enclosing object via `required`)
/// - `SumType!(A, B, …)` / tagged unions -> `{anyOf: [schema(A), schema(B), …]}`
/// - `std.datetime` types: `SysTime`/`DateTime` -> `{type: "string", format: "date-time"}`;
///   `Date` -> `{type: "string", format: "date"}`;
///   `TimeOfDay` -> `{type: "string", format: "time"}`
///
/// Any other type — pointers, delegates, classes, `void`, or an associative
/// array with a non-string key — is genuinely unmappable and raises a clear
/// `static assert(false, …)` at compile time. There is never a `{type:"string"}`
/// fallback for a structured type.
Json jsonSchemaOf(T)() @safe
{
	Json s = Json.emptyObject;

	static if (isInstanceOf!(Nullable, T))
	{
		return jsonSchemaOf!(TemplateArgsOf!T[0]);
	}
	else static if (is(T == bool))
	{
		s["type"] = "boolean";
	}
	else static if (is(T == enum))
	{
		s["type"] = "string";
		Json e = Json.emptyArray;
		static foreach (m; EnumMembers!T)
			e ~= Json(to!string(m));
		s["enum"] = e;
	}
	else static if (isStdDateTime!T)
	{
		s["type"] = "string";
		s["format"] = stdDateTimeFormat!T;
	}
	else static if (isIntegral!T)
	{
		s["type"] = "integer";
	}
	else static if (isFloatingPoint!T)
	{
		s["type"] = "number";
	}
	else static if (isSomeString!T)
	{
		s["type"] = "string";
	}
	else static if (isSumType!T)
	{
		Json variants = Json.emptyArray;
		static foreach (V; TemplateArgsOf!T)
			variants ~= jsonSchemaOf!V;
		s["anyOf"] = variants;
	}
	else static if (isAssociativeArray!T)
	{
		static assert(isSomeString!(KeyType!T),
				"jsonSchemaOf: unsupported associative-array key type "
				~ KeyType!T.stringof ~ " in " ~ T.stringof ~ " (JSON object keys must be strings)");
		s["type"] = "object";
		s["additionalProperties"] = jsonSchemaOf!(ValueType!T);
	}
	else static if (isArray!T)
	{
		s["type"] = "array";
		s["items"] = jsonSchemaOf!(typeof(T.init[0]));
	}
	else static if (is(T == struct))
	{
		s["type"] = "object";
		Json props = Json.emptyObject;
		Json required = Json.emptyArray;
		static foreach (i, field; FieldNameTuple!T)
		{
			{
				alias FT = typeof(__traits(getMember, T, field));
				Json prop = jsonSchemaOf!FT;
				applyFieldFacets!(T, field)(prop);
				props[field] = prop;
				static if (!isInstanceOf!(Nullable, FT) && !hasFieldDefault!(T, i))
					required ~= Json(field);
			}
		}
		s["properties"] = props;
		if (required.length > 0)
			s["required"] = required;
	}
	else
	{
		static assert(false, "jsonSchemaOf: unsupported type " ~ T.stringof
				~ " (only scalars, enums, std.datetime, strings, arrays,"
				~ " string-keyed associative arrays, structs, Nullable, and"
				~ " SumType are supported)");
	}
	return s;
}

/// Emit the field-level facet UDAs (`@minimum`, `@maximum`, `@title`,
/// `@schemaDefault`) declared on `T.field` onto its property schema `prop`.
/// Fields without these UDAs are left untouched.
private void applyFieldFacets(T, string field)(ref Json prop) @safe
{
	import mcp.api.attributes : minimum, maximum, title, SchemaDefault, format,
		minLength, maxLength, pattern, minItems, maxItems;
	import std.traits : getUDAs, hasUDA;

	alias member = __traits(getMember, T, field);

	static if (hasUDA!(member, minimum))
		prop["minimum"] = Json(getUDAs!(member, minimum)[0].value);
	static if (hasUDA!(member, maximum))
		prop["maximum"] = Json(getUDAs!(member, maximum)[0].value);
	static if (hasUDA!(member, title))
		prop["title"] = Json(getUDAs!(member, title)[0].value);

	// String facets (format / minLength / maxLength / pattern) and array
	// facets (minItems / maxItems) for richer elicitation form schemas.
	static if (hasUDA!(member, format))
		prop["format"] = Json(getUDAs!(member, format)[0].value);
	static if (hasUDA!(member, minLength))
		prop["minLength"] = Json(cast(long) getUDAs!(member, minLength)[0].value);
	static if (hasUDA!(member, maxLength))
		prop["maxLength"] = Json(cast(long) getUDAs!(member, maxLength)[0].value);
	static if (hasUDA!(member, pattern))
		prop["pattern"] = Json(getUDAs!(member, pattern)[0].value);
	static if (hasUDA!(member, minItems))
		prop["minItems"] = Json(cast(long) getUDAs!(member, minItems)[0].value);
	static if (hasUDA!(member, maxItems))
		prop["maxItems"] = Json(cast(long) getUDAs!(member, maxItems)[0].value);

	static foreach (uda; getUDAs!(member, SchemaDefault))
		prop["default"] = schemaDefaultJson(uda.value);
}

/// Serialize a `@schemaDefault` value into its JSON wire form. An `enum` value
/// becomes its member name (matching the enum's `{type:"string", enum:[…]}`
/// schema); all other supported scalars serialize directly.
private Json schemaDefaultJson(V)(V value) @safe
{
	static if (is(V == enum))
	{
		import std.conv : to;

		return Json(to!string(value));
	}
	else static if (is(V == bool))
		return Json(value);
	else static if (isIntegral!V)
		return Json(cast(long) value);
	else static if (isFloatingPoint!V)
		return Json(cast(double) value);
	else static if (isSomeString!V)
		return Json(value);
	else
	{
		static assert(false,
				"schemaDefaultJson: unsupported @schemaDefault value type " ~ V.stringof);
	}
}

/// A field type permitted in an elicitation form schema: a scalar (string /
/// number / integer / boolean / enum), optionally wrapped in `Nullable`. The
/// elicitation `requestedSchema` (SEP-1034/1330) is a flat object of such
/// primitives — no nested objects or arrays.
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

/// True when `T` is a flat struct whose every field is an `isElicitScalar`,
/// i.e. a valid type to derive an elicitation form `requestedSchema` from (via
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

/// True when field `i` of struct `T` carries a declared default, so it may be
/// omitted from a JSON payload and is therefore not listed in `required`. A
/// field counts as defaulted when it carries a `@schemaDefault` UDA (an explicit
/// presence test, observable even when the value equals the type's `.init`) or
/// when its declared initialiser differs from the type's `.init`. D exposes no
/// trait distinguishing `int x = 0;` from `int x;` once the value equals `.init`,
/// so the value comparison is the closest available signal for the latter case;
/// `@schemaDefault` is the way to mark such a field optional unambiguously.
private template hasFieldDefault(T, size_t i)
{
	import mcp.api.attributes : SchemaDefault;
	import std.traits : hasUDA;

	alias FT = typeof(T.tupleof[i]);
	static if (hasUDA!(T.tupleof[i], SchemaDefault))
		enum hasFieldDefault = true;
	else
	{
		enum readableAtCompileTime = __traits(compiles, {
				enum d = T.init.tupleof[i];
			});
		static if (readableAtCompileTime)
			enum hasFieldDefault = T.init.tupleof[i] != FT.init;
		else
			enum hasFieldDefault = false;
	}
}

/// Validate a JSON `value` against a JSON Schema `schema` (a schema document of
/// the kind produced by `jsonSchemaOf`).
///
/// Returns an empty string when `value` conforms; otherwise a human-readable
/// description of the first violation found. The supported keyword subset
/// matches what this SDK emits and is the same subset used for tool input and
/// output schemas: `type` (object/array/string/integer/number/boolean), nested
/// `properties` with `required`, `additionalProperties` (both the object
/// value-schema form and the boolean `false` form, which forbids any
/// undeclared object key), array `items`, `enum`, `anyOf`/`oneOf` (the value
/// must match at least one sub-schema, as emitted for SumType parameters and
/// returns), and the facet bounds `minimum`/`maximum` (numbers),
/// `minLength`/`maxLength` (code-point string length), and
/// `minItems`/`maxItems` (array length). Other unknown keywords are ignored
/// (treated as satisfied), so a richer hand-written schema never reports a
/// spurious failure.
string validateAgainstSchema(Json value, Json schema) @safe
{
	return validateAt(value, schema, "");
}

private string validateAt(Json value, Json schema, string path) @safe
{
	// A non-object schema (e.g. `true`, or absent) imposes no constraint.
	if (schema.type != Json.Type.object)
		return "";

	const where = path.length ? path : "(root)";

	// Self-contained keyword groups; each returns "" when its facet is
	// satisfied (or not present). The recursive cases below stay inline so
	// they can re-enter validateAt with the right child path.
	foreach (msg; [
		checkScalarType(value, schema, where), checkRequired(value, schema, where),
		checkAdditionalProps(value, schema, where),
		checkNumericBounds(value, schema, where),
		checkStringBounds(value, schema, where),
		checkArrayBounds(value, schema, where),
	])
		if (msg.length)
			return msg;

	if (value.type == Json.Type.object && "properties" in schema
			&& schema["properties"].type == Json.Type.object)
	{
		auto props = schema["properties"];
		foreach (string key, sub; props.byKeyValue)
			if (key in value)
			{
				auto msg = validateAt(value[key], sub, path.length ? path ~ "." ~ key : key);
				if (msg.length)
					return msg;
			}
	}

	if (value.type == Json.Type.array && "items" in schema
			&& schema["items"].type == Json.Type.object)
	{
		auto items = schema["items"];
		foreach (i; 0 .. value.length)
		{
			auto msg = validateAt(value[i], items, path ~ "[" ~ i.to!string ~ "]");
			if (msg.length)
				return msg;
		}
	}

	// anyOf: the value conforms iff it validates against at least one
	// sub-schema. SumType-typed parameters and returns are emitted as
	// `{anyOf:[…]}`; only when every branch fails is the value rejected.
	if ("anyOf" in schema && schema["anyOf"].type == Json.Type.array)
	{
		auto subs = schema["anyOf"];
		bool any;
		foreach (i; 0 .. subs.length)
			if (validateAt(value, subs[i], path).length == 0)
			{
				any = true;
				break;
			}
		if (!any)
			return where ~ ": value does not match any permitted schema";
	}

	// oneOf: the value conforms iff it validates against exactly one
	// sub-schema. Every branch is checked: zero matches is rejected as
	// unmatched, and two or more matches is rejected because the branches
	// are mutually exclusive.
	if ("oneOf" in schema && schema["oneOf"].type == Json.Type.array)
	{
		auto subs = schema["oneOf"];
		size_t matches;
		foreach (i; 0 .. subs.length)
			if (validateAt(value, subs[i], path).length == 0)
				matches++;
		if (matches == 0)
			return where ~ ": value does not match any permitted schema";
		if (matches > 1)
			return where ~ ": value matches more than one mutually-exclusive schema";
	}

	return "";
}

// enum + type: the value must be one of the permitted members and match the
// declared primitive type.
private string checkScalarType(Json value, Json schema, string where) @safe
{
	if ("enum" in schema && schema["enum"].type == Json.Type.array)
	{
		bool found;
		auto e = schema["enum"];
		foreach (i; 0 .. e.length)
			if (e[i] == value)
			{
				found = true;
				break;
			}
		if (!found)
			return where ~ ": value is not one of the permitted enum members";
	}

	if ("type" in schema && schema["type"].type == Json.Type.string)
	{
		const t = schema["type"].get!string;
		if (!matchesType(value, t))
			return where ~ ": expected type '" ~ t ~ "'";
	}

	return "";
}

// required: every listed property must be present on the object value.
private string checkRequired(Json value, Json schema, string where) @safe
{
	if (value.type == Json.Type.object && "required" in schema
			&& schema["required"].type == Json.Type.array)
	{
		auto req = schema["required"];
		foreach (i; 0 .. req.length)
			if (req[i].type == Json.Type.string)
			{
				const field = req[i].get!string;
				if (field !in value)
					return where ~ ": missing required property '" ~ field ~ "'";
			}
	}

	return "";
}

// additionalProperties in both forms. The object form validates each member
// whose key is not covered by an explicit `properties` entry against the value
// schema; the boolean `false` form rejects any such undeclared member. The two
// forms are mutually exclusive on a given schema. SDK-emitted AA schemas have
// no `properties`, so every member is checked; combined schemas stay correct by
// only checking the residual keys.
private string checkAdditionalProps(Json value, Json schema, string where) @safe
{
	if (value.type != Json.Type.object || "additionalProperties" !in schema)
		return "";

	const hasProps = "properties" in schema && schema["properties"].type == Json.Type.object;
	auto ap = schema["additionalProperties"];

	if (ap.type == Json.Type.object)
	{
		foreach (string key, member; value.byKeyValue)
		{
			if (hasProps && key in schema["properties"])
				continue;
			auto msg = validateAt(member, ap, where == "(root)" ? key : where ~ "." ~ key);
			if (msg.length)
				return msg;
		}
	}
	else if (ap.type == Json.Type.bool_ && !ap.get!bool)
	{
		foreach (string key, member; value.byKeyValue)
		{
			if (hasProps && key in schema["properties"])
				continue;
			return where ~ ": additional property '" ~ key ~ "' is not permitted";
		}
	}

	return "";
}

// minimum / maximum on number and integer values.
private string checkNumericBounds(Json value, Json schema, string where) @safe
{
	if (value.type != Json.Type.int_ && value.type != Json.Type.float_
			&& value.type != Json.Type.bigInt)
		return "";

	if ("minimum" in schema && schema["minimum"].type != Json.Type.undefined)
	{
		if (compareJsonNumbers(value, schema["minimum"]) < 0)
			return where ~ ": value is below the minimum";
	}
	if ("maximum" in schema && schema["maximum"].type != Json.Type.undefined)
	{
		if (compareJsonNumbers(value, schema["maximum"]) > 0)
			return where ~ ": value is above the maximum";
	}

	return "";
}

// minLength / maxLength, counted in code points.
private string checkStringBounds(Json value, Json schema, string where) @safe
{
	if (value.type != Json.Type.string)
		return "";

	import std.utf : count;

	const len = value.get!string.count;
	if ("minLength" in schema && schema["minLength"].type == Json.Type.int_)
	{
		if (len < schema["minLength"].get!long)
			return where ~ ": string is shorter than minLength";
	}
	if ("maxLength" in schema && schema["maxLength"].type == Json.Type.int_)
	{
		if (len > schema["maxLength"].get!long)
			return where ~ ": string is longer than maxLength";
	}

	return "";
}

// minItems / maxItems on array length.
private string checkArrayBounds(Json value, Json schema, string where) @safe
{
	if (value.type != Json.Type.array)
		return "";

	if ("minItems" in schema && schema["minItems"].type == Json.Type.int_)
	{
		if (value.length < schema["minItems"].get!long)
			return where ~ ": array has fewer than minItems items";
	}
	if ("maxItems" in schema && schema["maxItems"].type == Json.Type.int_)
	{
		if (value.length > schema["maxItems"].get!long)
			return where ~ ": array has more than maxItems items";
	}

	return "";
}

// Compare two JSON numbers, returning a negative value when `a < b`, zero when
// equal, and a positive value when `a > b`. Integral operands (int_/bigInt) are
// compared exactly via BigInt so that values beyond 2^53 do not collapse onto a
// shared double; the lossy double path is used only when a float is involved.
private int compareJsonNumbers(Json a, Json b) @safe
{
	static bool isIntegral(Json j)
	{
		return j.type == Json.Type.int_ || j.type == Json.Type.bigInt;
	}

	if (isIntegral(a) && isIntegral(b))
	{
		import std.bigint : BigInt;

		const BigInt x = a.type == Json.Type.int_ ? BigInt(a.get!long) : a.get!BigInt;
		const BigInt y = b.type == Json.Type.int_ ? BigInt(b.get!long) : b.get!BigInt;
		if (x < y)
			return -1;
		if (x > y)
			return 1;
		return 0;
	}

	const da = jsonNumber(a);
	const db = jsonNumber(b);
	if (da < db)
		return -1;
	if (da > db)
		return 1;
	return 0;
}

private double jsonNumber(Json j) @safe
{
	if (j.type == Json.Type.int_)
		return cast(double) j.get!long;
	if (j.type == Json.Type.float_)
		return j.get!double;
	if (j.type == Json.Type.bigInt)
	{
		import std.bigint : BigInt, toDecimalString;

		return toDecimalString(j.get!BigInt).to!double;
	}
	return 0;
}

private bool matchesType(Json value, string type) @safe
{
	switch (type)
	{
	case "object":
		return value.type == Json.Type.object;
	case "array":
		return value.type == Json.Type.array;
	case "string":
		return value.type == Json.Type.string;
	case "boolean":
		return value.type == Json.Type.bool_;
	case "integer":
		// Accept an integral JSON value, or a float that is integral-valued.
		if (value.type == Json.Type.int_ || value.type == Json.Type.bigInt)
			return true;
		if (value.type == Json.Type.float_)
		{
			import std.math : floor;

			return value.get!double == floor(value.get!double);
		}
		return false;
	case "number":
		return value.type == Json.Type.int_ || value.type == Json.Type.float_
			|| value.type == Json.Type.bigInt;
	case "null":
		return value.type == Json.Type.null_;
	default:
		// Unknown / unsupported type keyword: do not report a failure.
		return true;
	}
}

unittest  // scalar schemas
{
	assert(jsonSchemaOf!int["type"].get!string == "integer");
	assert(jsonSchemaOf!double["type"].get!string == "number");
	assert(jsonSchemaOf!bool["type"].get!string == "boolean");
	assert(jsonSchemaOf!string["type"].get!string == "string");
}

unittest  // enum becomes a string with members
{
	enum Color
	{
		red,
		green,
		blue
	}

	auto s = jsonSchemaOf!Color;
	assert(s["type"].get!string == "string");
	assert(s["enum"].length == 3);
	assert(s["enum"][0].get!string == "red");
}

unittest  // arrays carry an items schema
{
	auto s = jsonSchemaOf!(int[]);
	assert(s["type"].get!string == "array");
	assert(s["items"]["type"].get!string == "integer");
}

unittest  // structs become objects with properties and required
{
	struct Point
	{
		int x;
		int y;
		Nullable!string label;
	}

	auto s = jsonSchemaOf!Point;
	assert(s["type"].get!string == "object");
	assert(s["properties"]["x"]["type"].get!string == "integer");
	assert(s["properties"]["label"]["type"].get!string == "string");
	// x and y are required; the Nullable label is not.
	assert(s["required"].length == 2);
}

unittest  // Nullable unwraps to the inner schema
{
	assert(jsonSchemaOf!(Nullable!int)["type"].get!string == "integer");
}

unittest  // validateAgainstSchema accepts a conforming object
{
	struct Result
	{
		int total;
		string label;
	}

	auto schema = jsonSchemaOf!Result;
	Json v = Json.emptyObject;
	v["total"] = 7;
	v["label"] = "ok";
	assert(validateAgainstSchema(v, schema) == "");
}

unittest  // validateAgainstSchema rejects a wrong scalar type
{
	struct Result
	{
		int total;
	}

	auto schema = jsonSchemaOf!Result;
	Json v = Json.emptyObject;
	v["total"] = "not-a-number";
	auto msg = validateAgainstSchema(v, schema);
	assert(msg.length > 0);
}

unittest  // validateAgainstSchema rejects a missing required property
{
	struct Result
	{
		int total;
		string label;
	}

	auto schema = jsonSchemaOf!Result;
	Json v = Json.emptyObject;
	v["total"] = 1;
	auto msg = validateAgainstSchema(v, schema);
	assert(msg.length > 0);
}

unittest  // validateAgainstSchema treats Nullable members as optional
{
	struct Result
	{
		int total;
		Nullable!string label;
	}

	auto schema = jsonSchemaOf!Result;
	Json v = Json.emptyObject;
	v["total"] = 3;
	assert(validateAgainstSchema(v, schema) == "");
}

unittest  // validateAgainstSchema descends into array items
{
	auto schema = jsonSchemaOf!(int[]);
	Json good = Json.emptyArray;
	good ~= 1;
	good ~= 2;
	assert(validateAgainstSchema(good, schema) == "");

	Json bad = Json.emptyArray;
	bad ~= 1;
	bad ~= "x";
	assert(validateAgainstSchema(bad, schema).length > 0);
}

unittest  // validateAgainstSchema enforces enum membership
{
	enum Color
	{
		red,
		green,
		blue
	}

	auto schema = jsonSchemaOf!Color;
	assert(validateAgainstSchema(Json("green"), schema) == "");
	assert(validateAgainstSchema(Json("teal"), schema).length > 0);
}

unittest  // an empty / non-object schema imposes no constraint
{
	assert(validateAgainstSchema(Json("anything"), Json.undefined) == "");
	assert(validateAgainstSchema(Json(42), Json.emptyObject) == "");
}

unittest  // validateAgainstSchema enforces a SumType (anyOf) schema
{
	import std.sumtype : SumType;

	auto schema = jsonSchemaOf!(SumType!(int, string));
	assert("anyOf" in schema);
	assert(validateAgainstSchema(Json(7), schema) == "");
	assert(validateAgainstSchema(Json("hi"), schema) == "");
	assert(validateAgainstSchema(Json(true), schema).length > 0);
	assert(validateAgainstSchema(Json.emptyObject, schema).length > 0);
}

unittest  // oneOf rejects a value that matches more than one branch
{
	Json intSchema = Json.emptyObject;
	intSchema["type"] = "integer";
	Json minSchema = Json.emptyObject;
	minSchema["type"] = "integer";
	minSchema["minimum"] = Json(0);

	Json branches = Json.emptyArray;
	branches ~= intSchema;
	branches ~= minSchema;
	Json schema = Json.emptyObject;
	schema["oneOf"] = branches;

	assert(validateAgainstSchema(Json(5), schema).length > 0);
}

unittest  // oneOf accepts a value that matches exactly one branch
{
	Json intSchema = Json.emptyObject;
	intSchema["type"] = "integer";
	Json strSchema = Json.emptyObject;
	strSchema["type"] = "string";

	Json branches = Json.emptyArray;
	branches ~= intSchema;
	branches ~= strSchema;
	Json schema = Json.emptyObject;
	schema["oneOf"] = branches;

	assert(validateAgainstSchema(Json(5), schema) == "");
	assert(validateAgainstSchema(Json("hi"), schema) == "");
}

unittest  // oneOf rejects a value that matches no branch
{
	Json intSchema = Json.emptyObject;
	intSchema["type"] = "integer";
	Json strSchema = Json.emptyObject;
	strSchema["type"] = "string";

	Json branches = Json.emptyArray;
	branches ~= intSchema;
	branches ~= strSchema;
	Json schema = Json.emptyObject;
	schema["oneOf"] = branches;

	assert(validateAgainstSchema(Json(true), schema).length > 0);
}

unittest  // validateAgainstSchema enforces minimum / maximum
{
	Json schema = Json.emptyObject;
	schema["type"] = "integer";
	schema["minimum"] = Json(1);
	schema["maximum"] = Json(100);
	assert(validateAgainstSchema(Json(50), schema) == "");
	assert(validateAgainstSchema(Json(0), schema).length > 0);
	assert(validateAgainstSchema(Json(101), schema).length > 0);
}

unittest  // validateAgainstSchema accepts a long-overflow integer (bigInt)
{
	import vibe.data.json : parseJsonString;

	auto big = parseJsonString("99999999999999999999999999999");
	assert(big.type == Json.Type.bigInt);
	Json schema = Json.emptyObject;
	schema["type"] = "integer";
	assert(validateAgainstSchema(big, schema) == "");
}

unittest  // validateAgainstSchema accepts a long-overflow number (bigInt)
{
	import vibe.data.json : parseJsonString;

	auto big = parseJsonString("99999999999999999999999999999");
	assert(big.type == Json.Type.bigInt);
	Json schema = Json.emptyObject;
	schema["type"] = "number";
	assert(validateAgainstSchema(big, schema) == "");
}

unittest  // validateAgainstSchema enforces maximum on a bigInt value
{
	import vibe.data.json : parseJsonString;

	auto big = parseJsonString("99999999999999999999999999999");
	assert(big.type == Json.Type.bigInt);
	Json schema = Json.emptyObject;
	schema["type"] = "integer";
	schema["maximum"] = Json(100);
	assert(validateAgainstSchema(big, schema).length > 0);
}

unittest  // validateAgainstSchema enforces minimum on a negative bigInt value
{
	import vibe.data.json : parseJsonString;

	auto big = parseJsonString("-99999999999999999999999999999");
	assert(big.type == Json.Type.bigInt);
	Json schema = Json.emptyObject;
	schema["type"] = "integer";
	schema["minimum"] = Json(0);
	assert(validateAgainstSchema(big, schema).length > 0);
}

unittest  // validateAgainstSchema accepts an in-range bigInt value
{
	import vibe.data.json : parseJsonString;

	auto big = parseJsonString("99999999999999999999999999999");
	assert(big.type == Json.Type.bigInt);
	Json schema = Json.emptyObject;
	schema["type"] = "integer";
	schema["minimum"] = Json(1);
	assert(validateAgainstSchema(big, schema) == "");
}

unittest  // validateAgainstSchema rejects a bigInt one above a 2^53 maximum
{
	import vibe.data.json : parseJsonString;

	// 2^53 + 1 collapses onto the same double as 2^53, so a double comparison
	// would wrongly accept it; the BigInt path must reject it.
	auto big = parseJsonString("9007199254740993");
	assert(big.type == Json.Type.int_ || big.type == Json.Type.bigInt);
	Json schema = Json.emptyObject;
	schema["type"] = "integer";
	schema["maximum"] = parseJsonString("9007199254740992");
	assert(validateAgainstSchema(big, schema).length > 0);
}

unittest  // validateAgainstSchema rejects a true bigInt one above a 2^53 maximum
{
	import std.bigint : BigInt;

	// A value forced into the bigInt representation, just past the double mantissa.
	auto big = Json(BigInt("9007199254740993"));
	assert(big.type == Json.Type.bigInt);
	Json schema = Json.emptyObject;
	schema["type"] = "integer";
	schema["maximum"] = Json(9007199254740992L);
	assert(validateAgainstSchema(big, schema).length > 0);
}

unittest  // validateAgainstSchema accepts a bigInt equal to a 2^53 maximum
{
	import vibe.data.json : parseJsonString;

	auto big = parseJsonString("9007199254740992");
	assert(big.type == Json.Type.bigInt || big.type == Json.Type.int_);
	Json schema = Json.emptyObject;
	schema["type"] = "integer";
	schema["maximum"] = parseJsonString("9007199254740992");
	assert(validateAgainstSchema(big, schema) == "");
}

unittest  // validateAgainstSchema enforces minLength / maxLength
{
	Json schema = Json.emptyObject;
	schema["type"] = "string";
	schema["minLength"] = Json(3);
	schema["maxLength"] = Json(5);
	assert(validateAgainstSchema(Json("abcd"), schema) == "");
	assert(validateAgainstSchema(Json("ab"), schema).length > 0);
	assert(validateAgainstSchema(Json("abcdef"), schema).length > 0);
}

unittest  // validateAgainstSchema enforces minItems / maxItems
{
	Json schema = Json.emptyObject;
	schema["type"] = "array";
	schema["minItems"] = Json(1);
	schema["maxItems"] = Json(2);
	Json one = Json.emptyArray;
	one ~= 1;
	Json three = Json.emptyArray;
	three ~= 1;
	three ~= 2;
	three ~= 3;
	assert(validateAgainstSchema(one, schema) == "");
	assert(validateAgainstSchema(Json.emptyArray, schema).length > 0);
	assert(validateAgainstSchema(three, schema).length > 0);
}

unittest  // a @minimum field UDA is emitted and enforced together
{
	import mcp.api.attributes : minimum;

	struct P
	{
		@minimum(1) int count;
	}

	auto schema = jsonSchemaOf!P;
	Json good = Json.emptyObject;
	good["count"] = Json(5);
	assert(validateAgainstSchema(good, schema) == "");
	Json bad = Json.emptyObject;
	bad["count"] = Json(-5);
	assert(validateAgainstSchema(bad, schema).length > 0);
}

unittest  // associative array maps to object with additionalProperties
{
	auto s = jsonSchemaOf!(int[string]);
	assert(s["type"].get!string == "object");
	assert(s["additionalProperties"]["type"].get!string == "integer");
}

unittest  // associative array of structs (recursive value schema)
{
	struct Item
	{
		string name;
		int qty;
	}

	auto s = jsonSchemaOf!(Item[string]);
	assert(s["type"].get!string == "object");
	auto ap = s["additionalProperties"];
	assert(ap["type"].get!string == "object");
	assert(ap["properties"]["name"]["type"].get!string == "string");
	assert(ap["properties"]["qty"]["type"].get!string == "integer");
}

unittest  // arbitrarily deep nesting: array of structs holding AAs of structs
{
	struct Leaf
	{
		double value;
	}

	struct Branch
	{
		Leaf[string] leaves;
	}

	auto s = jsonSchemaOf!(Branch[]);
	assert(s["type"].get!string == "array");
	auto branch = s["items"];
	assert(branch["type"].get!string == "object");
	auto leaves = branch["properties"]["leaves"];
	assert(leaves["type"].get!string == "object");
	auto leaf = leaves["additionalProperties"];
	assert(leaf["type"].get!string == "object");
	assert(leaf["properties"]["value"]["type"].get!string == "number");
}

unittest  // nested optionals: Nullable struct field carrying an AA
{
	struct Config
	{
		string id;
		Nullable!(string[string]) tags;
	}

	auto s = jsonSchemaOf!Config;
	assert(s["type"].get!string == "object");
	// tags is Nullable -> optional; only id is required.
	assert(s["required"].length == 1);
	assert(s["required"][0].get!string == "id");
	auto tags = s["properties"]["tags"];
	assert(tags["type"].get!string == "object");
	assert(tags["additionalProperties"]["type"].get!string == "string");
}

unittest  // SumType maps to anyOf over the recursive variant schemas
{
	import std.sumtype : SumType;

	struct Box
	{
		int n;
	}

	alias V = SumType!(int, string, Box);
	auto s = jsonSchemaOf!V;
	assert("anyOf" in s);
	assert(s["anyOf"].length == 3);
	assert(s["anyOf"][0]["type"].get!string == "integer");
	assert(s["anyOf"][1]["type"].get!string == "string");
	assert(s["anyOf"][2]["type"].get!string == "object");
	assert(s["anyOf"][2]["properties"]["n"]["type"].get!string == "integer");
}

unittest  // std.datetime maps to a date-time formatted string
{
	import std.datetime.systime : SysTime;
	import std.datetime.date : DateTime, Date, TimeOfDay;

	auto a = jsonSchemaOf!SysTime;
	assert(a["type"].get!string == "string");
	assert(a["format"].get!string == "date-time");

	assert(jsonSchemaOf!DateTime["format"].get!string == "date-time");
}

unittest  // Date maps to format "date" and TimeOfDay maps to format "time"
{
	import std.datetime.date : Date, TimeOfDay;

	assert(jsonSchemaOf!Date["format"].get!string == "date");
	assert(jsonSchemaOf!TimeOfDay["format"].get!string == "time");
}

unittest  // struct fields with a declared default are optional, not required
{
	struct Options
	{
		int required;
		int limit = 10;
		string mode = "fast";
	}

	auto s = jsonSchemaOf!Options;
	assert(s["required"].length == 1);
	assert(s["required"][0].get!string == "required");
}

unittest  // a @schemaDefault field is optional even when no D initialiser is present
{
	import mcp.api.attributes : schemaDefault;

	struct Form
	{
		int required;
		@schemaDefault(false) bool verbose;
		@schemaDefault(10) int limit;
	}

	auto s = jsonSchemaOf!Form;
	assert(s["required"].length == 1);
	assert(s["required"][0].get!string == "required");
}

unittest  // a @schemaDefault field is optional even when its value equals .init
{
	import mcp.api.attributes : schemaDefault;

	struct Form
	{
		@schemaDefault(0) int limit = 0;
		@schemaDefault(false) bool flag = false;
		@schemaDefault("") string note = "";
	}

	auto s = jsonSchemaOf!Form;
	assert("required" !in s);
}

unittest  // a @schemaDefault enum field carrying its .init member is optional
{
	import mcp.api.attributes : schemaDefault;

	enum Cabin
	{
		economy,
		business
	}

	struct Form
	{
		string destination;
		@schemaDefault(Cabin.economy) Cabin cabin = Cabin.economy;
	}

	auto s = jsonSchemaOf!Form;
	assert(s["required"].length == 1);
	assert(s["required"][0].get!string == "destination");
}

unittest  // without @schemaDefault, a field defaulted to .init stays required
{
	struct Form
	{
		int limit = 0;
		bool flag = false;
		string note = "";
	}

	auto s = jsonSchemaOf!Form;
	assert(s["required"].length == 3);
}

unittest  // unsupported types fail to compile (no silent string fallback)
{
	assert(!__traits(compiles, jsonSchemaOf!(int*)));
	assert(!__traits(compiles, jsonSchemaOf!(void delegate())));
	// non-string AA key is rejected
	assert(!__traits(compiles, jsonSchemaOf!(string[int])));
}

unittest  // generated AA schema and validation agree
{
	auto schema = jsonSchemaOf!(int[string]);
	Json good = Json.emptyObject;
	good["a"] = 1;
	good["b"] = 2;
	assert(validateAgainstSchema(good, schema) == "");
}

unittest  // @minimum / @maximum emit numeric bounds on the property schema
{
	import mcp.api.attributes : minimum, maximum;

	struct Form
	{
		@minimum(1) @maximum(100) int count;
	}

	auto s = jsonSchemaOf!Form;
	auto count = s["properties"]["count"];
	assert(count["type"].get!string == "integer");
	assert(count["minimum"].get!double == 1.0);
	assert(count["maximum"].get!double == 100.0);
}

unittest  // @title emits the display title on the property schema
{
	import mcp.api.attributes : title;

	struct Form
	{
		@title("Item count") int count;
	}

	auto s = jsonSchemaOf!Form;
	assert(s["properties"]["count"]["title"].get!string == "Item count");
}

unittest  // @schemaDefault emits an integer default
{
	import mcp.api.attributes : schemaDefault;

	struct Form
	{
		@schemaDefault(10) int limit;
	}

	auto s = jsonSchemaOf!Form;
	assert(s["properties"]["limit"]["default"].get!long == 10);
}

unittest  // @schemaDefault emits a bool false default
{
	import mcp.api.attributes : schemaDefault;

	struct Form
	{
		@schemaDefault(false) bool verbose;
	}

	auto s = jsonSchemaOf!Form;
	assert("default" in s["properties"]["verbose"]);
	assert(s["properties"]["verbose"]["default"].get!bool == false);
}

unittest  // @schemaDefault on an enum field emits the enum's wire value
{
	import mcp.api.attributes : schemaDefault;

	enum Mode
	{
		fast,
		slow
	}

	struct Form
	{
		@schemaDefault(Mode.slow) Mode mode;
	}

	auto s = jsonSchemaOf!Form;
	assert(s["properties"]["mode"]["default"].get!string == "slow");
}

unittest  // a field with no facet UDAs is unchanged
{
	struct Form
	{
		int count;
	}

	auto s = jsonSchemaOf!Form;
	auto count = s["properties"]["count"];
	assert(count["type"].get!string == "integer");
	assert("minimum" !in count);
	assert("maximum" !in count);
	assert("title" !in count);
	assert("default" !in count);
}

unittest  // validateAgainstSchema validates AA values via additionalProperties
{
	auto schema = jsonSchemaOf!(int[string]);
	Json bad = Json.emptyObject;
	bad["a"] = "not-an-int";
	auto msg = validateAgainstSchema(bad, schema);
	assert(msg.length > 0);
}

unittest  // additionalProperties: a conforming AA value passes
{
	auto schema = jsonSchemaOf!(int[string]);
	Json good = Json.emptyObject;
	good["a"] = 1;
	good["b"] = 2;
	assert(validateAgainstSchema(good, schema) == "");
}

unittest  // additionalProperties recurses into struct value schemas
{
	struct Item
	{
		int qty;
	}

	auto schema = jsonSchemaOf!(Item[string]);
	Json bad = Json.emptyObject;
	Json inner = Json.emptyObject;
	inner["qty"] = "oops";
	bad["x"] = inner;
	assert(validateAgainstSchema(bad, schema).length > 0);
}

unittest  // additionalProperties:false rejects unknown object keys
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	Json aProp = Json.emptyObject;
	aProp["type"] = "integer";
	props["a"] = aProp;
	schema["properties"] = props;
	schema["additionalProperties"] = Json(false);

	Json withExtra = Json.emptyObject;
	withExtra["a"] = 1;
	withExtra["b"] = 2; // not declared in properties
	assert(validateAgainstSchema(withExtra, schema).length > 0,
			"an unknown key must be rejected when additionalProperties is false");

	Json onlyDeclared = Json.emptyObject;
	onlyDeclared["a"] = 1;
	assert(validateAgainstSchema(onlyDeclared, schema) == "",
			"a value with only declared keys must pass");
}

unittest  // string facets emit format/minLength/maxLength/pattern
{
	import mcp.api.attributes : format, minLength, maxLength, pattern;

	struct Form
	{
		@format("email") @minLength(3) @maxLength(64) @pattern("^.+@.+$") string addr;
	}

	auto s = jsonSchemaOf!Form;
	auto a = s["properties"]["addr"];
	assert(a["format"].get!string == "email");
	assert(a["minLength"].get!long == 3);
	assert(a["maxLength"].get!long == 64);
	assert(a["pattern"].get!string == "^.+@.+$");
}

unittest  // array facets emit minItems/maxItems
{
	import mcp.api.attributes : minItems, maxItems;

	struct Form
	{
		@minItems(1) @maxItems(5) int[] picks;
	}

	auto s = jsonSchemaOf!Form;
	auto p = s["properties"]["picks"];
	assert(p["type"].get!string == "array");
	assert(p["minItems"].get!long == 1);
	assert(p["maxItems"].get!long == 5);
}

unittest  // a multi-select enum array is a valid elicitation field
{
	enum Color
	{
		red,
		green,
		blue
	}

	struct Form
	{
		Color[] selected;
	}

	static assert(isElicitScalar!(Color[]));
	static assert(isFlatElicitationStruct!Form);
	auto s = jsonSchemaOf!Form;
	auto sel = s["properties"]["selected"];
	assert(sel["type"].get!string == "array");
	assert(sel["items"]["type"].get!string == "string");
	assert(sel["items"]["enum"].length == 3);
}
