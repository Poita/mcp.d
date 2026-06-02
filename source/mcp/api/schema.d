module mcp.api.schema;

import std.traits;
import std.typecons : Nullable;
import std.conv : to;
import std.sumtype : isSumType;

import vibe.data.json : Json;

@safe:

/// True when `T` is one of the `std.datetime` value types that serialize to an
/// ISO date-time string. Imported lazily so the trait does not force a
/// `std.datetime` dependency on callers that never use it.
private template isStdDateTime(T)
{
	import std.datetime.systime : SysTime;
	import std.datetime.date : DateTime, Date, TimeOfDay;

	enum isStdDateTime = is(T == SysTime) || is(T == DateTime) || is(T == Date) || is(T == TimeOfDay);
}

/// Generate a JSON Schema (2020-12) fragment describing the D type `T`.
///
/// The mapping is complete and fully recursive — every type expressible as a
/// tool parameter or structured result maps to a faithful schema, with no
/// silent fallback. Mapping:
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
/// - `std.datetime` types (`SysTime`, `DateTime`, `Date`, `TimeOfDay`) ->
///   `{type: "string", format: "date-time"}`
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
		s["format"] = "date-time";
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
/// Fields without these UDAs are left untouched, preserving existing behaviour.
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

	// #55: string facets (format / minLength / maxLength / pattern) and array
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
	else static if (isArray!F && !isSomeString!F) // #55: a multi-select array of enum members (a flat array of a primitive
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

/// True when field `i` of struct `T` declares an explicit non-`.init` default
/// initialiser, so it may be omitted from a JSON payload and is therefore not
/// listed in `required`.
private template hasFieldDefault(T, size_t i)
{
	alias FT = typeof(T.tupleof[i]);
	static if (__traits(compiles, { enum d = T.init.tupleof[i]; }))
				enum hasFieldDefault = T.init.tupleof[i] != FT.init;
	else
				enum hasFieldDefault = false;
				}

		/// Validate a JSON `value` against a JSON Schema `schema` (a schema document of
		/// the kind produced by `jsonSchemaOf`).
		///
		/// Returns an empty string when `value` conforms; otherwise a human-readable
		/// description of the first violation found. The supported keyword subset
		/// matches what this SDK emits and is the same subset used for tool input and
		/// output schemas: `type` (object/array/string/integer/number/boolean), nested
		/// `properties` with `required`, object `additionalProperties`, array `items`,
		/// and `enum`. Unknown keywords are
		/// ignored (treated as satisfied), so a richer hand-written schema never reports
		/// a spurious failure.
		string validateAgainstSchema(Json value, Json schema) @safe
		{
			return validateAt(value, schema, "");
		}

		private string validateAt(Json value, Json schema, string path) @safe
		{
			import std.algorithm : canFind;

			// A non-object schema (e.g. `true`, or absent) imposes no constraint.
			if (schema.type != Json.Type.object)
				return "";

			const where = path.length ? path : "(root)";

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

			// additionalProperties: validate each object member whose key is not
			// already covered by an explicit `properties` entry against the
			// additionalProperties value schema (#46). SDK-emitted AA schemas have
			// no `properties`, so every member is validated; for combined schemas
			// this stays correct by only validating the residual keys.
			if (value.type == Json.Type.object && "additionalProperties" in schema
				&& schema["additionalProperties"].type == Json.Type.object)
				{
				auto ap = schema["additionalProperties"];
				const hasProps = "properties" in schema
					&& schema["properties"].type == Json.Type.object;
				foreach (string key, member; value.byKeyValue)
					{
					if (hasProps && key in schema["properties"])
						continue;
					auto msg = validateAt(member, ap, path.length ? path ~ "." ~ key : key);
					if (msg.length)
						return msg;
				}
			}

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

			if (value.type == Json.Type.array && "items" in schema
				&& schema["items"].type == Json.Type.object)
				{
				auto items = schema["items"];
				foreach (i; 0 .. value.length)
					{
					import std.conv : to;

					auto msg = validateAt(value[i], items, path ~ "[" ~ i.to!string ~ "]");
					if (msg.length)
						return msg;
				}
			}

			return "";
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
				if (value.type == Json.Type.int_)
					return true;
				if (value.type == Json.Type.float_)
					{
					import std.math : floor;

					return value.get!double == floor(value.get!double);
				}
				return false;
			case "number":
				return value.type == Json.Type.int_ || value.type == Json.Type.float_;
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
			assert(jsonSchemaOf!Date["format"].get!string == "date-time");
			assert(jsonSchemaOf!TimeOfDay["format"].get!string == "date-time");
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

		unittest  // #46 validateAgainstSchema validates AA values via additionalProperties
		{
			auto schema = jsonSchemaOf!(int[string]);
			Json bad = Json.emptyObject;
			bad["a"] = "not-an-int";
			auto msg = validateAgainstSchema(bad, schema);
			assert(msg.length > 0);
		}

		unittest  // #46 additionalProperties: a conforming AA value passes
		{
			auto schema = jsonSchemaOf!(int[string]);
			Json good = Json.emptyObject;
			good["a"] = 1;
			good["b"] = 2;
			assert(validateAgainstSchema(good, schema) == "");
		}

		unittest  // #46 additionalProperties recurses into struct value schemas
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

		unittest  // #55 string facets emit format/minLength/maxLength/pattern
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

		unittest  // #55 array facets emit minItems/maxItems
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

		unittest  // #55 a multi-select enum array is a valid elicitation field
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
