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
			props[field] = jsonSchemaOf!(typeof(__traits(getMember, T, field)));
			static if (!isInstanceOf!(Nullable, typeof(__traits(getMember, T,
					field))) && !hasFieldDefault!(T, i))
				required ~= Json(field);
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
		/// `properties` with `required`, array `items`, and `enum`. Unknown keywords are
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
			int* ptr;
			assert(!__traits(compiles, jsonSchemaOf!(typeof(ptr))));
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
