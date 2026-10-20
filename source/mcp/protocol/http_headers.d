/// The Streamable HTTP request headers 2026-07-28 introduces, and the
/// `x-mcp-header` mechanism that mirrors tool parameters into `Mcp-Param-*`
/// headers: value encoding, header-name validation and annotation discovery.
module mcp.protocol.http_headers;

import vibe.data.json : Json;

@safe:

/// Standard Streamable HTTP request headers introduced by 2026-07-28.
enum HttpHeader : string
{
	protocolVersion = "MCP-Protocol-Version",
	method = "Mcp-Method",
	name = "Mcp-Name",
	paramPrefix = "Mcp-Param-",
}

/// Encode a tool-parameter value for transmission in an `Mcp-Param-*` header.
/// Plain-ASCII values pass through; anything else (non-ASCII, control chars,
/// surrounding whitespace, or a value that looks like the sentinel) is wrapped
/// as `=?base64?<base64-of-utf8>?=`.
string encodeHeaderValue(string value) @safe
{
	import std.base64 : Base64;

	if (value.length == 0)
		return value;
	bool needsEncoding = false;
	if (value[0] == ' ' || value[$ - 1] == ' ')
		needsEncoding = true;
	foreach (char c; value)
		if (c < 0x20 || c > 0x7E)
			needsEncoding = true;
	if (value.length >= 9 && value[0 .. 9] == "=?base64?")
		needsEncoding = true;

	if (!needsEncoding)
		return value;
	return "=?base64?" ~ () @trusted {
		return cast(string) Base64.encode(cast(const(ubyte)[]) value);
	}() ~ "?=";
}

/// Decode an `Mcp-Param-*` header value produced by `encodeHeaderValue`. A
/// sentinel-framed value whose body is not valid base64, or decodes to bytes
/// that are not valid UTF-8, is malformed and returned undecoded, so comparing
/// it against a body value yields a clean mismatch.
string decodeHeaderValue(string headerValue) @safe
{
	import std.base64 : Base64, Base64Exception;
	import std.utf : UTFException, validate;

	if (headerValue.length >= 11 && headerValue[0 .. 9] == "=?base64?"
			&& headerValue[$ - 2 .. $] == "?=")
	{
		const inner = headerValue[9 .. $ - 2];
		try
		{
			auto decoded = () @trusted { return cast(string) Base64.decode(inner); }();
			validate(decoded);
			return decoded;
		}
		catch (Base64Exception)
			return headerValue;
		catch (UTFException)
			return headerValue;
	}
	return headerValue;
}

/// Whether a header value would corrupt the request line if written verbatim:
/// an embedded CR or LF lets the value terminate the current header and inject
/// further headers (or smuggle a request) into the outbound HTTP stream. The raw
/// socket request paths call this as a last line of defence before concatenating
/// a value onto the wire, so even a value that bypassed `encodeHeaderValue`
/// cannot break framing.
bool isHeaderValueUnsafe(string value) @safe nothrow @nogc
{
	foreach (char c; value)
		if (c == '\r' || c == '\n')
			return true;
	return false;
}

/// Whether a JSON Schema `type` value is one the modern permits an `x-mcp-header`
/// annotation to be applied to. Per `server/tools` #x-mcp-header, only the
/// primitive types `integer`, `string`, and `boolean` are allowed; `number` is
/// explicitly NOT permitted (its value may not round-trip through a header).
bool isPrimitiveHeaderType(string jsonSchemaType) @safe pure nothrow
{
	return jsonSchemaType == "integer" || jsonSchemaType == "string" || jsonSchemaType == "boolean";
}

/// Validate a single `x-mcp-header` value (the name portion of the resulting
/// `Mcp-Param-{name}` header) against the modern constraints, returning a
/// human-readable reason on violation or `null` when valid.
///
/// Per `server/tools` #x-mcp-header an `x-mcp-header` value:
/// * MUST NOT be empty;
/// * MUST match HTTP field-name token syntax (`1*tchar`, RFC 9110 §5.1);
/// * MUST NOT contain control characters, including CR (`\r`) or LF (`\n`).
///
/// Case-insensitive uniqueness across the whole schema is enforced separately by
/// `validateInputSchemaHeaders` (it is not a property of a value in isolation).
string validateHeaderName(string value) @safe pure nothrow
{
	if (value.length == 0)
		return "x-mcp-header value MUST NOT be empty";
	foreach (char c; value)
	{
		// RFC 9110 §5.1 tchar: "!#$%&'*+-.^_`|~" / DIGIT / ALPHA.
		// This excludes control characters (incl. CR/LF), spaces, and ':'.
		const bool isTchar = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			|| (c >= '0' && c <= '9') || c == '!' || c == '#' || c == '$' || c == '%'
			|| c == '&' || c == '\'' || c == '*' || c == '+' || c == '-' || c == '.'
			|| c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
		if (!isTchar)
			return "x-mcp-header value '" ~ value
				~ "' is not a valid HTTP field-name token (1*tchar)";
	}
	return null;
}

/// A single `x-mcp-header` annotation discovered in a tool `inputSchema`,
/// together with the path of property keys to reach the annotated value.
struct ParamHeader
{
	string[] path; /// property keys from the root `inputSchema` to the annotated value
	string header; /// the resolved header name, e.g. `Mcp-Param-Region`
	string name; /// the raw `x-mcp-header` value (header suffix), e.g. `Region`
}

/// Collect every valid `x-mcp-header` annotation in a tool `inputSchema`,
/// recursing only through chains of `object` `properties` keys. The modern
/// requires an annotated property to be _statically reachable_ from the schema
/// root via `properties` alone — never through `items` (or any array keyword),
/// composition (`oneOf`/`anyOf`/`allOf`/`not`), conditional (`if`/`then`/`else`),
/// or `$ref` — so annotations sitting under those keywords are not surfaced.
/// Nested object properties at any depth are permitted. Annotations on
/// non-primitive (`number`/object/array) properties, or with an invalid value,
/// are skipped here; use `validateInputSchemaHeaders` to reject such schemas up
/// front.
ParamHeader[] paramHeaders(Json inputSchema) @safe
{
	ParamHeader[] result;
	void walk(Json node, string[] path) @safe
	{
		if (node.type != Json.Type.object)
			return;
		if ("properties" in node && node["properties"].type == Json.Type.object)
		{
			foreach (name, prop; node["properties"].byKeyValue)
			{
				if (prop.type != Json.Type.object)
					continue;
				auto childPath = path ~ name;
				if ("x-mcp-header" in prop && prop["x-mcp-header"].type == Json.Type.string)
				{
					const hv = prop["x-mcp-header"].get!string;
					const ptype = ("type" in prop && prop["type"].type == Json.Type.string) ? prop["type"]
						.get!string : "";
					if (validateHeaderName(hv) is null && isPrimitiveHeaderType(ptype))
						result ~= ParamHeader(childPath, HttpHeader.paramPrefix ~ hv, hv);
				}
				walk(prop, childPath);
			}
		}
	}

	walk(inputSchema, []);
	return result;
}

/// Validate every `x-mcp-header` annotation in a tool `inputSchema` against the
/// modern constraints (`server/tools` #x-mcp-header): non-empty, HTTP token
/// syntax, no CR/LF, primitive-only (`number` forbidden), and case-insensitive
/// uniqueness across the whole schema. The annotation MUST also sit on a property
/// that is _statically reachable_ from the root via a chain of `properties` keys
/// only: an annotation under any other keyword — `items` and the other array
/// keywords, composition (`oneOf`/`anyOf`/`allOf`/`not`), conditional
/// (`if`/`then`/`else`), `$ref`/`$defs`, `additionalProperties`,
/// `patternProperties`, `dependentSchemas`, `unevaluatedProperties`,
/// `propertyNames`, or an unknown keyword — makes the tool definition invalid.
/// Data-valued keywords (`const`/`enum`/`default`/`examples`) are not searched.
/// Returns a human-readable reason on the first violation, or `null` when every
/// annotation is valid.
string validateInputSchemaHeaders(Json inputSchema) @safe
{
	string err;
	bool[string] seen; // ASCII-lowercased header values already encountered

	// Keywords whose values are JSON data rather than subschemas: an
	// `x-mcp-header` key inside them is not an annotation.
	static immutable string[] valueKeys = [
		"const", "enum", "default", "examples"
	];
	// Keywords whose values map names to subschemas, so their keys are names
	// rather than keywords.
	static immutable string[] schemaMapKeys = [
		"properties", "patternProperties", "dependentSchemas", "$defs",
		"definitions"
	];

	// True when the schema `node` (an object or an array of schemas), or any
	// subschema nested within it, carries an `x-mcp-header`. Data under value
	// keywords is skipped. Used to reject annotations that hang off a
	// non-`properties` keyword and are therefore not statically reachable.
	bool containsAnnotation(Json node) @safe
	{
		import std.algorithm.searching : canFind;

		if (node.type == Json.Type.array)
		{
			foreach (elem; node.byValue)
				if (containsAnnotation(elem))
					return true;
			return false;
		}
		if (node.type != Json.Type.object)
			return false;
		if ("x-mcp-header" in node)
			return true;
		foreach (key, v; node.byKeyValue)
		{
			if (valueKeys.canFind(key))
				continue;
			if (!schemaMapKeys.canFind(key) || v.type != Json.Type.object)
			{
				if (containsAnnotation(v))
					return true;
				continue;
			}
			foreach (_, sub; v.byKeyValue)
				if (containsAnnotation(sub))
					return true;
		}
		return false;
	}

	// Whether the value `v` of schema keyword `key` contains an annotation.
	bool keywordContainsAnnotation(string key, Json v) @safe
	{
		import std.algorithm.searching : canFind;

		if (!schemaMapKeys.canFind(key) || v.type != Json.Type.object)
			return containsAnnotation(v);
		foreach (_, sub; v.byKeyValue)
			if (containsAnnotation(sub))
				return true;
		return false;
	}

	// `isProperty` is true when `node` is a `properties` member, whose own
	// `x-mcp-header` the caller has already validated.
	void walk(Json node, bool isProperty) @safe
	{
		import std.algorithm.searching : canFind;

		if (err !is null || node.type != Json.Type.object)
			return;
		if ("properties" in node && node["properties"].type == Json.Type.object)
		{
			foreach (name, prop; node["properties"].byKeyValue)
			{
				if (err !is null)
					break;
				if (prop.type != Json.Type.object)
					continue;
				if ("x-mcp-header" in prop)
				{
					if (prop["x-mcp-header"].type != Json.Type.string)
					{
						err = "x-mcp-header value on '" ~ name ~ "' MUST be a string";
						break;
					}
					const hv = prop["x-mcp-header"].get!string;
					auto nameErr = validateHeaderName(hv);
					if (nameErr !is null)
					{
						err = nameErr;
						break;
					}
					const ptype = ("type" in prop && prop["type"].type == Json.Type.string) ? prop["type"]
						.get!string : "";
					if (!isPrimitiveHeaderType(ptype))
					{
						err = "x-mcp-header '" ~ hv ~ "' on '" ~ name
							~ "' may only be applied to primitive types"
							~ " (integer/string/boolean); type '" ~ ptype ~ "' is not permitted";
						break;
					}
					import std.uni : toLower;

					const lc = hv.toLower;
					if (lc in seen)
					{
						err = "x-mcp-header value '" ~ hv
							~ "' is not case-insensitively unique within the inputSchema";
						break;
					}
					seen[lc] = true;
				}
				walk(prop, true);
			}
		}
		// Only a chain of `properties` keys reaches an annotated property
		// statically; an annotation under any other keyword (array, composition,
		// conditional, reference, map-shaped keywords such as
		// `additionalProperties`/`patternProperties`, or an unknown extension)
		// invalidates the whole tool definition.
		foreach (key, v; node.byKeyValue)
		{
			if (key == "properties" || valueKeys.canFind(key) || (isProperty && key == "x-mcp-header"))
				continue;
			if (key == "x-mcp-header" || keywordContainsAnnotation(key, v))
			{
				err = "x-mcp-header MUST only be applied to statically reachable properties"
					~ " (a chain of `properties` keys); an annotation under `" ~ key
					~ "` is invalid";
				break;
			}
		}
	}

	walk(inputSchema, false);
	return err;
}

unittest  // header value codec: plain ASCII passes through; others base64
{
	assert(encodeHeaderValue("us-west1") == "us-west1");
	assert(decodeHeaderValue("us-west1") == "us-west1");

	// non-ASCII -> base64 sentinel, round-trips
	auto enc = encodeHeaderValue("Hello, 世界");
	assert(enc.length > 9 && enc[0 .. 9] == "=?base64?");
	assert(decodeHeaderValue(enc) == "Hello, 世界");

	// leading/trailing space and sentinel-looking values are encoded
	assert(encodeHeaderValue(" padded ")[0 .. 9] == "=?base64?");
	assert(decodeHeaderValue(encodeHeaderValue(" padded ")) == " padded ");
	assert(decodeHeaderValue(encodeHeaderValue("=?base64?x?=")) == "=?base64?x?=");
}

unittest  // decodeHeaderValue tolerates sentinel-framed but invalid base64
{
	// Valid sentinel framing with an undecodable body must not throw; the raw
	// value is returned so downstream comparison yields a clean mismatch.
	const malformed = "=?base64?@@@@?=";
	assert(decodeHeaderValue(malformed) == malformed);
}

unittest  // decodeHeaderValue treats base64 that decodes to invalid UTF-8 as malformed
{
	import std.base64 : Base64;
	import std.utf : validate;

	const string bad = "=?base64?" ~ Base64.encode(cast(const(ubyte)[])[
		0xff, 0xfe, 0x41
	]).idup ~ "?=";
	const decoded = decodeHeaderValue(bad);
	assert(decoded == bad);
	validate(decoded);
}

unittest  // encodeHeaderValue neutralises CR/LF, so an encoded value is wire-safe
{
	// A URI carrying CR/LF must not survive as raw control bytes in the output;
	// it is base64-wrapped and the result carries no CR/LF.
	const evil = "file:///x\r\nMcp-Injected: 1";
	const enc = encodeHeaderValue(evil);
	assert(enc[0 .. 9] == "=?base64?");
	assert(!isHeaderValueUnsafe(enc));
	assert(decodeHeaderValue(enc) == evil);
}

unittest  // isHeaderValueUnsafe flags only embedded CR/LF
{
	assert(isHeaderValueUnsafe("a\rb"));
	assert(isHeaderValueUnsafe("a\nb"));
	assert(isHeaderValueUnsafe("trailing\r\n"));
	assert(!isHeaderValueUnsafe("file:///a b"));
	assert(!isHeaderValueUnsafe("us-west1"));
	assert(!isHeaderValueUnsafe(""));
}

unittest  // paramHeaderMap is not part of the API; paramHeaders is the one extractor
{
	static assert(!__traits(compiles, paramHeaderMap(Json.emptyObject)));
}

unittest  // validateHeaderName: empty value rejected (modern x-mcp-header MUST NOT be empty)
{
	assert(validateHeaderName("") !is null);
}

unittest  // validateHeaderName: valid token passes
{
	assert(validateHeaderName("Region") is null);
	assert(validateHeaderName("X-Trace-Id_v2.1") is null);
}

unittest  // validateHeaderName: CR/LF and control chars rejected (no header injection)
{
	assert(validateHeaderName("Re\rgion") !is null);
	assert(validateHeaderName("Re\ngion") !is null);
	assert(validateHeaderName("Re\x01gion") !is null);
}

unittest  // validateHeaderName: space and colon are not tchar
{
	assert(validateHeaderName("My Region") !is null);
	assert(validateHeaderName("Region:") !is null);
}

unittest  // isPrimitiveHeaderType: integer/string/boolean allowed, number/object/array not
{
	assert(isPrimitiveHeaderType("integer"));
	assert(isPrimitiveHeaderType("string"));
	assert(isPrimitiveHeaderType("boolean"));
	assert(!isPrimitiveHeaderType("number"));
	assert(!isPrimitiveHeaderType("object"));
	assert(!isPrimitiveHeaderType("array"));
}

unittest  // validateInputSchemaHeaders: a valid primitive annotation passes
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["region"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Region")
	]);
	props["limit"] = Json([
		"type": Json("integer"),
		"x-mcp-header": Json("Limit")
	]);
	schema["properties"] = props;
	assert(validateInputSchemaHeaders(schema) is null);
}

unittest  // validateInputSchemaHeaders rejects an annotation under any non-`properties` keyword
{
	import vibe.data.json : parseJsonString;

	enum ann = `{"type":"string","x-mcp-header":"H"}`;
	foreach (frag; [
		`"additionalProperties":` ~ ann, `"patternProperties":{"^a":` ~ ann ~ `}`,
		`"dependentSchemas":{"a":{"properties":{"b":` ~ ann ~ `}}}`,
		`"unevaluatedProperties":` ~ ann, `"propertyNames":` ~ ann,
		`"x-vendor":{"properties":{"b":` ~ ann ~ `}}`, `"x-mcp-header":"Root"`
	])
	{
		auto schema = parseJsonString(`{"type":"object",` ~ frag ~ `}`);
		assert(validateInputSchemaHeaders(schema) !is null, frag);
	}
	// The same holds below a nested object property.
	auto nested = parseJsonString(`{"type":"object","properties":{"o":{"type":"object",`
			~ `"additionalProperties":` ~ ann ~ `}}}`);
	assert(validateInputSchemaHeaders(nested) !is null);
}

unittest  // validateInputSchemaHeaders ignores annotation-shaped data under value keywords
{
	import vibe.data.json : parseJsonString;

	auto schema = parseJsonString(`{"type":"object","properties":{"o":{"type":"object",`
			~ `"default":{"x-mcp-header":"x"},"examples":[{"x-mcp-header":"y"}]},`
			~ `"r":{"type":"string","x-mcp-header":"Region"}}}`);
	assert(validateInputSchemaHeaders(schema) is null);
}

unittest  // validateInputSchemaHeaders ignores annotation-shaped data under value keywords of nested subschemas
{
	import vibe.data.json : parseJsonString;

	auto schema = parseJsonString(`{"type":"object","properties":{"tags":{"type":"array",`
			~ `"items":{"type":"object","default":{"x-mcp-header":"x"},`
			~ `"enum":[{"x-mcp-header":"y"}]}}}}`);
	assert(validateInputSchemaHeaders(schema) is null);
}

unittest  // validateInputSchemaHeaders rejects an annotated subschema named like a value keyword
{
	import vibe.data.json : parseJsonString;

	auto schema = parseJsonString(
			`{"type":"object","$defs":{"default":` ~ `{"type":"string","x-mcp-header":"Region"}}}`);
	assert(validateInputSchemaHeaders(schema) !is null);
}

unittest  // validateInputSchemaHeaders: number-typed annotation is rejected (number NOT permitted)
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["amount"] = Json([
		"type": Json("number"),
		"x-mcp-header": Json("Amount")
	]);
	schema["properties"] = props;
	assert(validateInputSchemaHeaders(schema) !is null);
}

unittest  // validateInputSchemaHeaders: empty x-mcp-header value rejected
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["region"] = Json(["type": Json("string"), "x-mcp-header": Json("")]);
	schema["properties"] = props;
	assert(validateInputSchemaHeaders(schema) !is null);
}

unittest  // validateInputSchemaHeaders: CR/LF in value rejected
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["region"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Re\r\ngion")
	]);
	schema["properties"] = props;
	assert(validateInputSchemaHeaders(schema) !is null);
}

unittest  // validateInputSchemaHeaders: case-insensitively duplicate values rejected
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["a"] = Json(["type": Json("string"), "x-mcp-header": Json("Region")]);
	props["b"] = Json(["type": Json("string"), "x-mcp-header": Json("region")]);
	schema["properties"] = props;
	assert(validateInputSchemaHeaders(schema) !is null);
}

unittest  // validateInputSchemaHeaders: detects duplicate across nesting depths
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json nestedProps = Json.emptyObject;
	nestedProps["region"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Region")
	]);
	Json nested = Json.emptyObject;
	nested["type"] = "object";
	nested["properties"] = nestedProps;
	Json props = Json.emptyObject;
	props["top"] = Json(["type": Json("string"), "x-mcp-header": Json("REGION")]);
	props["obj"] = nested;
	schema["properties"] = props;
	assert(validateInputSchemaHeaders(schema) !is null);
}

unittest  // paramHeaders: recurses into nested object properties (any nesting depth)
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json nestedProps = Json.emptyObject;
	nestedProps["region"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Region")
	]);
	Json nested = Json.emptyObject;
	nested["type"] = "object";
	nested["properties"] = nestedProps;
	Json props = Json.emptyObject;
	props["filters"] = nested;
	schema["properties"] = props;

	auto phs = paramHeaders(schema);
	assert(phs.length == 1);
	assert(phs[0].path == ["filters", "region"]);
	assert(phs[0].header == "Mcp-Param-Region");
}

unittest  // x-mcp-header under array items is not statically reachable: rejected and not surfaced
{
	// 2026-07-28 requires annotated properties to be reachable via a chain of
	// `properties` keys only; a chain through `items` (an array keyword) is invalid.
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json itemProps = Json.emptyObject;
	itemProps["tag"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Tag")
	]);
	Json items = Json.emptyObject;
	items["type"] = "object";
	items["properties"] = itemProps;
	Json arr = Json.emptyObject;
	arr["type"] = "array";
	arr["items"] = items;
	Json props = Json.emptyObject;
	props["entries"] = arr;
	schema["properties"] = props;

	assert(validateInputSchemaHeaders(schema) !is null);
	assert(paramHeaders(schema).length == 0);
}

unittest  // x-mcp-header under composition (oneOf/anyOf/allOf/not) is rejected
{
	foreach (key; ["oneOf", "anyOf", "allOf", "not"])
	{
		Json branch = Json.emptyObject;
		branch["type"] = "object";
		branch["properties"] = Json([
			"region": Json([
				"type": Json("string"),
				"x-mcp-header": Json("Region")
			])
		]);
		Json schema = Json.emptyObject;
		schema["type"] = "object";
		if (key == "not")
			schema[key] = branch;
		else
			schema[key] = Json([branch]);
		assert(validateInputSchemaHeaders(schema) !is null,
				"annotation under " ~ key ~ " must reject");
		assert(paramHeaders(schema).length == 0);
	}
}

unittest  // x-mcp-header under conditional (if/then/else) is rejected
{
	foreach (key; ["if", "then", "else"])
	{
		Json branch = Json.emptyObject;
		branch["type"] = "object";
		branch["properties"] = Json([
			"region": Json([
				"type": Json("string"),
				"x-mcp-header": Json("Region")
			])
		]);
		Json schema = Json.emptyObject;
		schema["type"] = "object";
		schema[key] = branch;
		assert(validateInputSchemaHeaders(schema) !is null,
				"annotation under " ~ key ~ " must reject");
	}
}

unittest  // x-mcp-header reachable only through $ref/$defs is rejected
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	schema["properties"] = Json(["filter": Json(["$ref": Json("#/$defs/F")])]);
	schema["$defs"] = Json([
		"F": Json([
			"type": Json("object"),
			"properties": Json([
				"region": Json([
					"type": Json("string"),
					"x-mcp-header": Json("Region")
				])
			])
		])
	]);
	assert(validateInputSchemaHeaders(schema) !is null);
	assert(paramHeaders(schema).length == 0);
}

unittest  // paramHeaders: number-typed annotations are skipped (not collected)
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json props = Json.emptyObject;
	props["amount"] = Json([
		"type": Json("number"),
		"x-mcp-header": Json("Amount")
	]);
	schema["properties"] = props;
	assert(paramHeaders(schema).length == 0);
}

unittest  // x-mcp-header under array-form (tuple) items is rejected, not surfaced
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json elemProps = Json.emptyObject;
	elemProps["tag"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Tag")
	]);
	Json elem = Json.emptyObject;
	elem["type"] = "object";
	elem["properties"] = elemProps;
	Json arr = Json.emptyObject;
	arr["type"] = "array";
	arr["items"] = Json([elem]); // array-form (tuple) items
	Json props = Json.emptyObject;
	props["entries"] = arr;
	schema["properties"] = props;

	assert(validateInputSchemaHeaders(schema) !is null);
	assert(paramHeaders(schema).length == 0);
}

unittest  // x-mcp-header under prefixItems element schemas is rejected, not surfaced
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json elemProps = Json.emptyObject;
	elemProps["region"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Region")
	]);
	Json elem = Json.emptyObject;
	elem["type"] = "object";
	elem["properties"] = elemProps;
	Json arr = Json.emptyObject;
	arr["type"] = "array";
	arr["prefixItems"] = Json([elem]);
	Json props = Json.emptyObject;
	props["coords"] = arr;
	schema["properties"] = props;

	assert(validateInputSchemaHeaders(schema) !is null);
	assert(paramHeaders(schema).length == 0);
}

unittest  // validateInputSchemaHeaders: rejects CR/LF header on array-form items element
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json elemProps = Json.emptyObject;
	elemProps["tag"] = Json([
		"type": Json("string"),
		"x-mcp-header": Json("Ta\r\ng")
	]);
	Json elem = Json.emptyObject;
	elem["type"] = "object";
	elem["properties"] = elemProps;
	Json arr = Json.emptyObject;
	arr["type"] = "array";
	arr["items"] = Json([elem]);
	Json props = Json.emptyObject;
	props["entries"] = arr;
	schema["properties"] = props;
	assert(validateInputSchemaHeaders(schema) !is null);
}

unittest  // validateInputSchemaHeaders: rejects number-typed header on prefixItems element
{
	Json schema = Json.emptyObject;
	schema["type"] = "object";
	Json elemProps = Json.emptyObject;
	elemProps["amount"] = Json([
		"type": Json("number"),
		"x-mcp-header": Json("Amount")
	]);
	Json elem = Json.emptyObject;
	elem["type"] = "object";
	elem["properties"] = elemProps;
	Json arr = Json.emptyObject;
	arr["type"] = "array";
	arr["prefixItems"] = Json([elem]);
	Json props = Json.emptyObject;
	props["coords"] = arr;
	schema["properties"] = props;
	assert(validateInputSchemaHeaders(schema) !is null);
}
