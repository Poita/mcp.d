module mcp.api.reflection;

import std.traits;
import std.typecons : Tuple, Nullable, nullable;
import std.meta : AliasSeq;

import vibe.data.json : Json, serializeToJson, deserializeJson, JsonSerializer;
import vibe.data.serialization : serializeWithPolicy, deserializeWithPolicy;

import mcp.protocol.types;
import mcp.protocol.capabilities : Icon;
import mcp.protocol.modern : CacheHint, CacheScope;
import mcp.server.server : McpServer, ToolResponse;
import mcp.server.context;
import mcp.server.task_context : TaskContext;
import mcp.server.task_runtime : TaskOptions;
import mcp.api.attributes;
import mcp.api.apps : UiToolMeta, setUiToolMeta;
import mcp.api.schema;

@safe:

/// vibe.data serialization policy that maps any `enum` leaf to / from its
/// member *name* (string), rather than vibe's default numeric base value.
///
/// The reflection layer emits enum schemas as `{type:"string", enum:[names…]}`
/// (see `jsonSchemaOf`), so both directions of marshalling must agree: struct
/// params/returns and bare-enum values are (de)serialized by-name. The policy
/// only defines `toRepresentation`/`fromRepresentation` for enums, so vibe's
/// `isPolicySerializable` is false for every other type and the default
/// behaviour is preserved (it still recurses into nested struct/array fields,
/// applying this rule to any enum found at any depth).
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

/// Register every `@tool` / `@prompt` / `@resource` / `@resourceTemplate`
/// annotated method of `obj` on `server`, deriving JSON schemas and argument
/// marshalling from the method signatures (FastMCP-style ergonomics).
void registerHandlers(T)(McpServer server, T obj) @safe
{
	registerAnnotatedMembers!(T, obj)(server);
}

/// Register every `@tool` / `@prompt` / `@resource` / `@resourceTemplate`
/// annotated **free function** in module `mod` on `server`, mirroring
/// `registerHandlers` but targeting module-scope symbols rather than the
/// methods of an instance (FastMCP-style module decoration).
///
/// Free functions cannot receive a `RequestContext` via `this`, so a context
/// must be taken as an explicit parameter (exactly as opt-in methods do).
/// Non-function members and functions without a recognized UDA are skipped.
void registerModule(alias mod)(McpServer server) @safe
{
	registerAnnotatedMembers!(mod, mod)(server);
}

/// Walk every overload of every member of `root` and dispatch each recognized
/// handler UDA to the matching register method. `root` supplies the member set;
/// `parent` is the symbol member calls resolve against — `(T, obj)` for an
/// instance, `(mod, mod)` for a module's free functions. Members without a
/// recognized UDA are skipped.
private void registerAnnotatedMembers(alias root, alias parent)(McpServer server) @safe
{
	static foreach (memberName; __traits(allMembers, root))
	{
		static if (__traits(compiles, __traits(getOverloads, root, memberName)))
		{
			static foreach (overload; __traits(getOverloads, root, memberName))
			{
				static foreach (attr; __traits(getAttributes, overload))
				{
					static if (is(typeof(attr) == tool))
						registerToolMethod!(memberName, overload, parent)(server, attr);
					else static if (is(typeof(attr) == task))
						registerTaskMethod!(memberName, overload, parent)(server, attr);
					else static if (is(typeof(attr) == prompt))
						registerPromptMethod!(memberName, overload, parent)(server, attr);
					else static if (is(typeof(attr) == resource))
						registerResourceMethod!(memberName, overload, parent)(server, attr);
					else static if (is(typeof(attr) == resourceTemplate))
						registerTemplateMethod!(memberName, overload, parent)(server, attr);
				}
			}
		}
	}
}

/// Convenience variadic form of `registerModule`: register the annotated free
/// functions of several modules in one call.
void registerModules(mods...)(McpServer server) @safe
{
	static foreach (mod; mods)
		registerModule!mod(server);
}

/// Reject any method-level `@describeParam` or `@mcpHeader` UDA whose
/// `parameter` does not name a schema parameter of `func`. A parameter that is
/// not declared at all, or one that is an injected context parameter (a trailing
/// `RequestContext` / `TaskContext`, which is excluded from the input schema and
/// has no property to annotate), is always a programmer error: the annotation
/// would silently match nothing. Reject it at compile time with a clear
/// diagnostic instead.
private void validateParamUdas(alias func)()
{
	alias names = ParameterIdentifierTuple!func;
	alias types = Parameters!func;

	// Whether `pname` names a parameter of `func` that appears in the input
	// schema (declared, and not an injected RequestContext / TaskContext).
	static bool namesSchemaParam(string pname)()
	{
		bool found;
		static foreach (i, P; types)
			static if (!is(P : RequestContext) && !is(P == TaskContext))
				if (names[i] == pname)
					found = true;
		return found;
	}

	static foreach (attr; __traits(getAttributes, func))
	{
		static if (is(typeof(attr) == describeParam))
			static assert(namesSchemaParam!(attr.parameter)(), "@describeParam(\""
					~ attr.parameter ~ "\", ...) names no schema parameter of this method "
					~ "(an injected RequestContext/TaskContext has no schema property).");
		else static if (is(typeof(attr) == mcpHeader))
			static assert(namesSchemaParam!(attr.parameter)(), "@mcpHeader(\""
					~ attr.parameter ~ "\", ...) names no schema parameter of this method "
					~ "(an injected RequestContext/TaskContext has no schema property).");
	}
}

/// Resolve the documentation string for the parameter named `pname` of `func`
/// from the method-level `@describeParam` UDA layer, or `""` when none applies.
private string describeFor(alias func, string pname)() @safe
{
	string desc;
	static foreach (attr; __traits(getAttributes, func))
		static if (is(typeof(attr) == describeParam))
			if (attr.parameter == pname && attr.description.length)
				desc = attr.description;
	return desc;
}

/// Whether `P` is an admissible `@mcpHeader` parameter type: one whose
/// `jsonSchemaOf` yields a draft primitive header type (integer/string/boolean).
/// `Nullable!T` is unwrapped to its inner type. Mirrors the runtime check
/// `draft.isPrimitiveHeaderType` so detection is symmetric at compile time.
private template isPrimitiveHeaderParam(P)
{
	import std.traits : isIntegral;

	static if (isInstanceOf!(Nullable, P))
		enum isPrimitiveHeaderParam = isPrimitiveHeaderParam!(TemplateArgsOf!P[0]);
	else
		enum isPrimitiveHeaderParam = is(P == bool) || is(P == enum)
			|| isIntegral!P || isSomeString!P;
}

/// Build the `{type:object, properties, required}` schema for a method's
/// parameters, skipping any `RequestContext` parameter.
private Json parametersSchema(alias func)() @safe
{
	import mcp.protocol.modern : validateHeaderName;
	import std.traits : ParameterDefaultValueTuple;

	validateParamUdas!func();

	alias names = ParameterIdentifierTuple!func;
	alias types = Parameters!func;
	// ParameterDefaultValueTuple yields `void` for a parameter with no declared
	// D-level default and the default value's type otherwise.
	alias defs = ParameterDefaultValueTuple!func;

	Json props = Json.emptyObject;
	Json required = Json.emptyArray;
	static foreach (i, P; types)
	{
		static if (!is(P : RequestContext) && !is(P == TaskContext))
		{
			{
				// Generate the parameter's schema and fold in the field-level
				// facet UDAs (@minimum, @maximum, @title, @format, @minLength,
				// @maxLength, @pattern, @minItems, @maxItems, @schemaDefault)
				// attached directly to the parameter. Both the generator and
				// applyUdaFacets are jsonschema's, operating in its JsonNode IR;
				// render to vibe Json once the facets are applied, then layer the
				// MCP-specific extensions (x-mcp-header, description) on below.
				import jsonschema : genParamNode = jsonSchemaOf, applyUdaFacets, GeneratorSettings;
				import jsonschema.vibejson : nodeToVibeJson;

				enum GeneratorSettings paramSettings = {inlineSubschemas: true};
				auto psNode = genParamNode!(P, paramSettings)();
				applyUdaFacets!(__traits(getAttributes, types[i .. i + 1]))(psNode);
				Json ps = nodeToVibeJson(psNode);
				// Draft x-mcp-header: a method-level @mcpHeader(parameter, name)
				// naming this parameter mirrors it into an `Mcp-Param-<name>`
				// request header; emit the extension property so the transport can
				// validate it (see draft.paramHeaders). The header name and the
				// named parameter's type are checked against the draft
				// `x-mcp-header` constraints at compile time: the value MUST be a
				// valid HTTP token (non-empty, 1*tchar, no CR/LF) and the parameter
				// MUST be a primitive type (string/integral/bool); `number`
				// (floating point) is NOT permitted.
				static foreach (attr; __traits(getAttributes, func))
					static if (is(typeof(attr) == mcpHeader))
						if (attr.parameter == names[i])
							{
							static assert(validateHeaderName(attr.name) is null,
									"@mcpHeader(\"" ~ attr.parameter ~ "\", \"" ~ attr.name
									~ "\") is not a valid x-mcp-header value: " ~ validateHeaderName(
										attr.name));
							// The draft permits only primitive x-mcp-header value
							// types (integer/string/boolean). Whitelist exactly those
							// (plus the `Nullable` thereof) so a struct/array/AA/
							// `number` parameter is rejected at the registration site
							// rather than per-request via the transport's
							// `headerMismatch` (see draft.isPrimitiveHeaderType).
							static assert(isPrimitiveHeaderParam!P, "@mcpHeader cannot be applied to parameter '" ~ names[i] ~ "' of type " ~ P
									.stringof ~ "; x-mcp-header permits only integer/string/boolean (or Nullable thereof)");
							ps["x-mcp-header"] = attr.name;
						}
				// Fold the @describeParam UDA into the property's JSON Schema
				// `description` (a standard annotation keyword, valid in every
				// protocol version).
				{
					enum d = describeFor!(func, names[i]);
					static if (d.length)
						ps["description"] = d;
				}
				props[names[i]] = ps;
			}
			// A parameter is required only when it is neither Nullable nor carries a
			// declared D-level default value. ParameterDefaultValueTuple gives
			// `void` for params without a default.
			static if (!isInstanceOf!(Nullable, P) && is(defs[i] == void))
				required ~= Json(names[i]);
		}
	}
	Json s = Json.emptyObject;
	s["type"] = "object";
	s["properties"] = props;
	if (required.length > 0)
		s["required"] = required;
	return s;
}

/// Whether argument `name` is meaningfully present in `args`: keyed, and neither
/// JSON `null` nor `undefined`. The canonical absent/null/undefined predicate
/// shared by the defaulting and Nullable marshalling paths.
private bool argPresent(Json args, string name) @safe
{
	return (name in args) !is null && args[name].type != Json.Type.null_
		&& args[name].type != Json.Type.undefined;
}

/// Convert one JSON argument value into the parameter type `P`, falling back to
/// the parameter's declared D-level default `def` when the argument is absent.
/// `def` is the value from `ParameterDefaultValueTuple` for this slot.
private P marshalArgDefault(P, alias def)(Json args, string name) @safe
{
	static if (is(P : RequestContext))
	{
		assert(false, "context parameters are injected, not marshalled");
	}
	else
	{
		if (!argPresent(args, name))
			return def;
		return marshalArg!P(args, name);
	}
}

/// Convert one JSON argument value into the parameter type `P`.
private P marshalArg(P)(Json args, string name) @safe
{
	static if (is(P : RequestContext))
	{
		assert(false, "context parameters are injected, not marshalled");
	}
	else static if (isInstanceOf!(Nullable, P))
	{
		alias Inner = TemplateArgsOf!P[0];
		if (argPresent(args, name))
			return P(marshalScalar!Inner(args[name]));
		return P.init;
	}
	else
	{
		if (argPresent(args, name))
			return marshalScalar!P(args[name]);
		return P.init;
	}
}

/// Convert a captured resource-template URI variable (always a string) into the
/// declared parameter type `P`. Enums are parsed by member name, other scalars
/// via `std.conv.to`; conversion failure throws (caller maps it to InvalidParams).
private P marshalTemplateVar(P)(string raw) @safe
{
	import std.conv : to;

	static if (is(P == string))
		return raw;
	else static if (is(P == enum) || isIntegral!P || isFloatingPoint!P || is(P == bool))
		return to!P(raw);
	else
	{
		// Aggregate / Nullable etc.: interpret the captured string as a JSON
		// document and deserialize through the enum-aware policy.
		import vibe.data.json : parseJsonString;

		return marshalScalar!P(parseJsonString(raw));
	}
}

private P marshalScalar(P)(Json v) @safe
{
	// Deserialize through EnumByNamePolicy so any enum — whether `P` itself or
	// an enum field nested inside a struct/array — is read from its schema-
	// declared string member name rather than vibe's default integer base
	// value. Non-enum types are unaffected by the policy.
	return () @trusted {
		return deserializeWithPolicy!(JsonSerializer, EnumByNamePolicy, P)(v);
	}();
}

/// Deserialize a dynamic handler's raw wire `arguments` into a typed value `T`.
///
/// The UDA-driven registration overloads marshal each argument from the method
/// signature for you, but the dynamic `registerTool`/`registerPrompt`
/// overloads hand the handler the raw `Json arguments`. This is the inbound
/// counterpart of the client's `callTool!T`: it deserializes `arguments` through
/// the same enum-by-name policy the UDA layer uses (so any `enum` leaf is read
/// from its schema-declared member name, at any nesting depth) and maps a vibe
/// conversion failure to `invalidParams` (-32602), matching how the reflection
/// layer reports a malformed argument. A handler can then write
/// `auto a = argsAs!MyArgs(arguments);` instead of hand-rolling
/// `arguments["x"].get!int` with manual presence/type checks.
T argsAs(T)(Json arguments) @safe
{
	import mcp.protocol.errors : McpException, invalidParams;

	try
		return marshalScalar!T(arguments);
	catch (McpException e)
		throw e;
	catch (Exception e)
		throw invalidParams("arguments: " ~ e.msg);
}

/// The JSON Schema describing a tool's structured output, derived from its
/// return type — or `Json.undefined` when the tool produces unstructured text
/// (a `string`) or supplies its own `CallToolResult`. Aggregate (`struct`)
/// returns map to their object schema directly; scalar/array/enum returns are
/// wrapped under a `result` property so `structuredContent` is always an object.
private Json outputSchemaOf(R)() @safe
{
	static if (is(R == CallToolResult) || is(R == ToolResponse) || isSomeString!R || is(R == void))
		return Json.undefined;
	else static if (is(R == struct))
		return jsonSchemaOf!R;
	else
	{
		Json s = Json.emptyObject;
		s["type"] = "object";
		Json props = Json.emptyObject;
		props["result"] = jsonSchemaOf!R;
		s["properties"] = props;
		s["required"] = Json([Json("result")]);
		return s;
	}
}

/// Wrap a tool method's return value into a `CallToolResult`. The structured
/// result mirrors `outputSchemaOf!R`: structs serialize to an object; scalars,
/// arrays, and enums are wrapped under a `result` key; strings become text
/// content with no structured output.
private CallToolResult toToolResult(R)(R ret) @safe if (!is(R == void))
{
	static if (is(R == CallToolResult))
		return ret;
	else static if (isSomeString!R)
	{
		CallToolResult r;
		r.content = [Content.makeText(ret)];
		return r;
	}
	else
	{
		CallToolResult r;
		// Serialize through EnumByNamePolicy so enum leaves (the value itself, or
		// enums nested in structs/arrays) emit their schema-declared string member
		// name, matching the tool's outputSchema instead of an integer base value.
		static if (is(R == struct))
			auto structured = () @trusted {
				return serializeWithPolicy!(JsonSerializer, EnumByNamePolicy)(ret);
			}();
		else
		{
			Json structured = Json.emptyObject;
			structured["result"] = () @trusted {
				return serializeWithPolicy!(JsonSerializer, EnumByNamePolicy)(ret);
			}();
		}
		r.structuredContent = structured;
		r.content = [Content.makeText(structured.toString())];
		return r;
	}
}

/// Collect every `@icon` UDA on a method into the descriptor `Icon[]` shape.
private Icon[] collectIcons(alias overload)() @safe
{
	Icon[] icons;
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == icon))
		{
			{
				Icon ic;
				ic.src = a.src;
				if (a.mimeType.length)
					ic.mimeType = nullable(a.mimeType);
				ic.sizes = a.sizes;
				if (a.theme.length)
					ic.theme = nullable(a.theme);
				icons ~= ic;
			}
		}
	}
	return icons;
}

/// Collect a `@meta` UDA's object into a descriptor `_meta` Json (undefined when
/// absent or when the supplied value is not an object).
private Json collectMeta(alias overload)() @safe
{
	Json m = Json.undefined;
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == meta))
		{
			if (a.value.type == Json.Type.object)
				m = a.value;
		}
	}
	return m;
}

/// Fold a method's `@icon` UDAs into `descriptor.icons` and its `@meta` UDA into
/// `descriptor.meta`. Generic over any descriptor exposing those members (Tool,
/// Prompt, Resource, ResourceTemplate).
private void applyIconsAndMeta(alias overload, D)(ref D descriptor) @safe
{
	descriptor.icons = collectIcons!overload();
	auto m = collectMeta!overload();
	if (m.type == Json.Type.object)
		descriptor.meta = m;
}

/// Fold a resource/template method's value UDAs into `descriptor`: the
/// `@audience` / `@priority` / `@lastModified` annotations plus the shared
/// `@icon` / `@meta` metadata. Generic over Resource and ResourceTemplate, which
/// share the `annotations` / `icons` / `meta` members. Absent UDAs leave the
/// corresponding field unset (omitted from the wire form).
private void applyResourceMetadata(alias overload, D)(ref D descriptor) @safe
{
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == audience))
			descriptor.annotations.audience = a.roles;
		else static if (is(typeof(a) == priority))
			descriptor.annotations.priority = a.value;
		else static if (is(typeof(a) == lastModified))
			descriptor.annotations.lastModified = a.value;
	}
	applyIconsAndMeta!overload(descriptor);
}

/// Collect a `@cache` UDA into a `Nullable!CacheHint` for resource/template
/// registration; null when absent.
private Nullable!CacheHint collectCache(alias overload)() @safe
{
	Nullable!CacheHint hint;
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == cache))
		{
			{
				static assert(a.scope_ == "public" || a.scope_ == "private",
						"@cache scope_ must be \"public\" or \"private\", got: " ~ a.scope_);
				CacheHint h;
				h.ttl = a.ttl;
				h.cacheScope = (a.scope_ == "private") ? CacheScope.private_ : CacheScope.public_;
				hint = h;
			}
		}
	}
	return hint;
}

private void registerToolMethod(string memberName, alias overload, alias parent)(
		McpServer server, tool attr) @safe
{
	import std.traits : ReturnType;

	Tool descriptor;
	descriptor.name = attr.name;
	if (attr.description.length)
		descriptor.description = nullable(attr.description);
	if (attr.title.length)
		descriptor.title = nullable(attr.title);
	descriptor.inputSchema = parametersSchema!overload();
	auto outSchema = outputSchemaOf!(ReturnType!overload)();
	if (outSchema.type == Json.Type.object)
		descriptor.outputSchema = outSchema;

	// Fold every method UDA in a single pass: the marker hint UDAs (@readOnly /
	// @destructive / @idempotent / @openWorld) and the @hintTitle value UDA into
	// typed ToolAnnotations. A single loop keeps every UDA handled in one place so
	// a new UDA cannot land in only one pass. A marker's presence sets the
	// corresponding hint to true; absence leaves it unset (omitted from the wire
	// form).
	ToolAnnotations anns;
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (__traits(isSame, a, readOnly))
			anns.readOnlyHint = true;
		else static if (__traits(isSame, a, destructive))
			anns.destructiveHint = true;
		else static if (__traits(isSame, a, idempotent))
			anns.idempotentHint = true;
		else static if (__traits(isSame, a, openWorld))
			anns.openWorldHint = true;
		else static if (is(typeof(a) == hintTitle))
		{
			if (a.value.length)
				anns.title = a.value;
		}
	}
	if (!anns.empty)
		descriptor.annotations = anns.toJson();

	applyIconsAndMeta!overload(descriptor);

	// Fold a @ui UDA into the tool's _meta.ui (MCP Apps), merging with any
	// _meta already set by @meta above.
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == ui))
			setUiToolMeta(descriptor, UiToolMeta(a.resourceUri, a.visibility));
	}

	server.registerTool(descriptor, (Json args, RequestContext ctx) @safe {
		import mcp.protocol.errors : McpException;

		alias names = ParameterIdentifierTuple!overload;
		alias defs = ParameterDefaultValueTuple!overload;
		// A malformed argument that the coarse input-schema check admits (e.g. when
		// schema validation is disabled, or a conversion the type-check cannot rule
		// out) must surface as a clean, attributed tool-execution error rather than
		// a raw std.conv/vibe exception string. This SDK classifies tool input
		// failures as `isError:true` results (not -32602), so the marshalling
		// failure is returned as an error CallToolResult, wrapped to the handler's
		// return type. Protocol errors thrown by the marshaller are re-thrown so an
		// inner McpException is not swallowed (mirrors the prompt path's pass-through).
		static CallToolResult marshalError(string argName, string msg) @safe
		{
			return CallToolResult.error("argument '" ~ argName ~ "': " ~ msg);
		}

		Tuple!(Parameters!overload) argv;
		static foreach (i, P; Parameters!overload)
		{
			static if (is(P : RequestContext))
				argv[i] = ctx;
			else
			{
				// A required parameter (neither Nullable nor carrying a D-level
				// default) must be present even when input-schema validation is
				// disabled; a missing one is a tool input error, not a silently
				// default-constructed value.
				static if (is(defs[i] == void) && !isInstanceOf!(Nullable, P))
				{
					if (!argPresent(args, names[i]))
					{
						static if (is(ReturnType!overload == ToolResponse))
							return ToolResponse.complete(marshalError(names[i],
								"required argument is missing"));
						else
							return marshalError(names[i], "required argument is missing");
					}
				}
				try
				{
					static if (is(defs[i] == void))
						argv[i] = marshalArg!P(args, names[i]);
					else
						argv[i] = marshalArgDefault!(P, defs[i])(args, names[i]);
				}
				catch (McpException e)
					throw e;
				catch (Exception e)
				{
					static if (is(ReturnType!overload == ToolResponse))
						return ToolResponse.complete(marshalError(names[i], e.msg));
					else
						return marshalError(names[i], e.msg);
				}
			}
		}
		// An MRTR-capable tool returns a ToolResponse directly, so it may answer
		// `inputRequired` (stateless elicitation) as well as `complete`; any other
		// return type is wrapped into a CallToolResult.
		static if (is(ReturnType!overload == ToolResponse))
			return __traits(getMember, parent, memberName)(argv.expand);
		else static if (is(ReturnType!overload == void))
		{
			__traits(getMember, parent, memberName)(argv.expand);
			CallToolResult empty;
			return empty;
		}
		else
			return toToolResult(__traits(getMember, parent, memberName)(argv.expand));
	});
}

private void registerTaskMethod(string memberName, alias overload, alias parent)(
		McpServer server, task attr) @safe
{
	import std.traits : ReturnType;

	// A task executor runs asynchronously, after the originating request has
	// already returned a task handle — there is no live RequestContext to inject.
	// Task methods observe progress/cancellation/input through a TaskContext.
	static foreach (P; Parameters!overload)
		static assert(!is(P : RequestContext),
				"@task method '" ~ memberName ~ "' must not take a RequestContext "
				~ "(the request has already returned); take a TaskContext instead.");
	static assert(!is(ReturnType!overload == ToolResponse),
			"@task method '" ~ memberName ~ "' must return a value (or void), not ToolResponse");

	Tool descriptor;
	descriptor.name = attr.name;
	if (attr.description.length)
		descriptor.description = nullable(attr.description);
	if (attr.title.length)
		descriptor.title = nullable(attr.title);
	descriptor.inputSchema = parametersSchema!overload();
	auto outSchema = outputSchemaOf!(ReturnType!overload)();
	if (outSchema.type == Json.Type.object)
		descriptor.outputSchema = outSchema;

	// Behavioral-hint UDAs fold exactly as for @tool.
	ToolAnnotations anns;
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (__traits(isSame, a, readOnly))
			anns.readOnlyHint = true;
		else static if (__traits(isSame, a, destructive))
			anns.destructiveHint = true;
		else static if (__traits(isSame, a, idempotent))
			anns.idempotentHint = true;
		else static if (__traits(isSame, a, openWorld))
			anns.openWorldHint = true;
		else static if (is(typeof(a) == hintTitle))
		{
			if (a.value.length)
				anns.title = a.value;
		}
	}
	if (!anns.empty)
		descriptor.annotations = anns.toJson();
	applyIconsAndMeta!overload(descriptor);

	// Per-task timing from @taskTtl / @taskPollInterval; an absent UDA inherits the
	// corresponding server default.
	import core.time : Duration;

	Nullable!Duration ttl;
	Nullable!Duration pollInterval;
	static foreach (a; __traits(getAttributes, overload))
	{
		static if (is(typeof(a) == taskTtl))
			ttl = a.value;
		else static if (is(typeof(a) == taskPollInterval))
			pollInterval = a.value;
	}

	// The executor runs on each dispatch: it reconstitutes the typed arguments
	// from the task's durable input, injects the TaskContext, invokes the method,
	// and wraps the return value into a CallToolResult-shaped result JSON. A
	// marshalling failure or a thrown exception propagates to runTaskExecutor,
	// which fails the task; a `tc.requireInput(...)` suspends it.
	server.registerTaskTool(descriptor, (TaskContext tc) @safe {
		alias names = ParameterIdentifierTuple!overload;
		alias defs = ParameterDefaultValueTuple!overload;
		Json args = tc.inputJson();
		Tuple!(Parameters!overload) argv;
		static foreach (i, P; Parameters!overload)
		{
			static if (is(P == TaskContext))
				argv[i] = tc;
			else static if (is(defs[i] == void))
				argv[i] = marshalArg!P(args, names[i]);
			else
				argv[i] = marshalArgDefault!(P, defs[i])(args, names[i]);
		}
		static if (is(ReturnType!overload == void))
		{
			__traits(getMember, parent, memberName)(argv.expand);
			CallToolResult empty;
			return empty.toJson();
		}
		else
			return toToolResult(__traits(getMember, parent, memberName)(argv.expand)).toJson();
	}, ttl, pollInterval);
}

/// Wrap a prompt method's return value into a `GetPromptResult`.
private GetPromptResult toPromptResult(R)(R ret) @safe
{
	static if (is(R == GetPromptResult))
		return ret;
	else static if (is(R == PromptMessage[]))
	{
		GetPromptResult r;
		r.messages = ret;
		return r;
	}
	else static if (isSomeString!R)
	{
		GetPromptResult r;
		r.messages = [PromptMessage("user", Content.makeText(ret))];
		return r;
	}
	else
		static assert(false,
				"@prompt method must return GetPromptResult, PromptMessage[], or string");
}

private void registerPromptMethod(string memberName, alias overload, alias parent)(
		McpServer server, prompt attr) @safe
{
	validateParamUdas!overload();

	Prompt descriptor;
	descriptor.name = attr.name;
	if (attr.title.length)
		descriptor.title = nullable(attr.title);
	if (attr.description.length)
		descriptor.description = nullable(attr.description);
	alias names = ParameterIdentifierTuple!overload;
	alias defs = ParameterDefaultValueTuple!overload;
	static foreach (i, P; Parameters!overload)
	{
		static if (!is(P : RequestContext))
		{
			// Populate PromptArgument.description from the @describeParam UDA.
			enum d = describeFor!(overload, names[i]);
			// A prompt argument is required only when it is neither Nullable nor
			// carries a declared D-level default, matching the tool path.
			descriptor.arguments ~= PromptArgument(names[i], d.length
					? nullable(d) : Nullable!string.init,
					!isInstanceOf!(Nullable, P) && is(defs[i] == void));
		}
	}

	applyIconsAndMeta!overload(descriptor);

	server.registerPrompt(descriptor, (Json args, RequestContext ctx) @safe {
		import mcp.protocol.errors : McpException, invalidParams;
		import mcp.server.server : PromptResponse;

		Tuple!(Parameters!overload) argv;
		static foreach (i, P; Parameters!overload)
		{
			// A declared RequestContext parameter binds to the real per-request
			// context so context-dependent features (logging, cancellation,
			// elicitation) work from prompts, exactly as the tool path does.
			static if (is(P : RequestContext))
				argv[i] = ctx;
			else static if (is(defs[i] == void))
			{
				// A malformed argument (e.g. an out-of-range enum member or a
				// non-numeric integer) must surface as InvalidParams (-32602)
				// rather than escaping as an internal error (-32603), mirroring
				// the resource-template path. Protocol errors thrown by the
				// marshaller are passed through unchanged so an inner
				// invalidParams is not double-wrapped.
				try
					argv[i] = marshalArg!P(args, names[i]);
				catch (McpException e)
					throw e;
				catch (Exception e)
					throw invalidParams("argument '" ~ names[i] ~ "': " ~ e.msg);
			}
			else
			{
				try
					argv[i] = marshalArgDefault!(P, defs[i])(args, names[i]);
				catch (McpException e)
					throw e;
				catch (Exception e)
					throw invalidParams("argument '" ~ names[i] ~ "': " ~ e.msg);
			}
		}
		return PromptResponse.complete(toPromptResult(__traits(getMember,
			parent, memberName)(argv.expand)));
	});
}

private ResourceContents toResourceContents(R)(R ret, string uri, string mimeType) @safe
{
	static if (is(R == ResourceContents))
		return ret;
	else static if (isSomeString!R)
		return ResourceContents.makeText(uri, mimeType, ret);
	else
		static assert(false, "@resource method must return ResourceContents or string");
}

private void registerResourceMethod(string memberName, alias overload, alias parent)(
		McpServer server, resource attr) @safe
{
	Resource descriptor;
	descriptor.uri = attr.uri;
	descriptor.name = attr.name;
	if (attr.mimeType.length)
		descriptor.mimeType = nullable(attr.mimeType);
	if (attr.description.length)
		descriptor.description = nullable(attr.description);
	if (attr.title.length)
		descriptor.title = nullable(attr.title);

	applyResourceMetadata!overload(descriptor);

	server.registerResource(descriptor, () @safe {
		return toResourceContents(__traits(getMember, parent, memberName)(),
			attr.uri, attr.mimeType);
	}, collectCache!overload());
}

private void registerTemplateMethod(string memberName, alias overload, alias parent)(
		McpServer server, resourceTemplate attr) @safe
{
	ResourceTemplate descriptor;
	descriptor.uriTemplate = attr.uriTemplate;
	descriptor.name = attr.name;
	if (attr.mimeType.length)
		descriptor.mimeType = nullable(attr.mimeType);
	if (attr.description.length)
		descriptor.description = nullable(attr.description);
	if (attr.title.length)
		descriptor.title = nullable(attr.title);

	applyResourceMetadata!overload(descriptor);

	server.registerResourceTemplate(descriptor, (string uri,
			string[string] params, RequestContext ctx) @safe {
		import mcp.protocol.errors : invalidParams;

		alias names = ParameterIdentifierTuple!overload;
		Tuple!(Parameters!overload) argv;
		static foreach (i, P; Parameters!overload)
		{
			// A declared RequestContext parameter binds to the real per-request
			// context so context-dependent features work from resource templates,
			// exactly as the tool path does.
			static if (is(P : RequestContext))
				argv[i] = ctx;
			else static if (is(P == string))
				argv[i] = (names[i] in params) ? params[names[i]] : "";
			else
			{
				// A captured URI variable is always a string; convert it into the
				// declared parameter type instead of silently defaulting it to
				// `P.init`. Surface a conversion failure as InvalidParams
				// rather than throwing a raw exception.
				if (auto pv = names[i] in params)
				{
					try
						argv[i] = marshalTemplateVar!P(*pv);
					catch (Exception e)
						throw invalidParams("resource template parameter '" ~ names[i]
							~ "' could not be parsed as " ~ P.stringof ~ ": " ~ e.msg);
				}
				else
					argv[i] = P.init;
			}
		}
		auto ret = __traits(getMember, parent, memberName)(argv.expand);
		return toResourceContents(ret, uri, attr.mimeType);
	}, collectCache!overload());
}

version (unittest)
{
	import core.time : seconds;

	private enum Priority
	{
		low,
		high
	}

	private struct Stats
	{
		int count;
		double total;
	}

	private final class DemoApi
	{
		@tool("add", "Add two integers")
		int add(int a, int b) @safe
		{
			return a + b;
		}

		@tool("stats", "Summarize a list of integers")
		Stats stats(int[] values) @safe
		{
			Stats s;
			foreach (v; values)
			{
				s.count++;
				s.total += v;
			}
			return s;
		}

		@tool("greet", "Greet someone")
		string greet(string name) @safe
		{
			return "Hello, " ~ name ~ "!";
		}

		@tool("classify", "Classify with an enum + optional note")
		string classify(Priority p, Nullable!string note) @safe
		{
			return note.isNull ? "p" : "n";
		}

		@tool("erase", "Erase a record", "Erase Record")
		@destructive @idempotent string erase(string id) @safe
		{
			return "erased " ~ id;
		}

		@resource("test://doc", "Doc", "text/plain")
		string doc() @safe
		{
			return "document body";
		}

		@resource("test://readme", "Readme", "text/markdown")
		@priority(0.9) @audience("user") string readme() @safe
		{
			return "readme body";
		}

		@tool("query", "Query a region")
		@mcpHeader("region", "Region")
		string query(string region, int limit) @safe
		{
			return region;
		}

		@tool("annotate", "Tool with described parameters")
		@describeParam("id", "the document id")
		@describeParam("count", "how many copies")
		string annotate(string id, int count) @safe
		{
			return id;
		}

		@prompt("describedPrompt", "Prompt with a described argument")
		@describeParam("topic", "the subject to write about")
		string describedPrompt(string topic) @safe
		{
			return "Tell me about " ~ topic;
		}

		@prompt("intro", "Intro prompt")
		string intro(string topic) @safe
		{
			return "Tell me about " ~ topic;
		}

		@prompt("summary", "Summary prompt", "Summarize Text")
		string summary(string topic) @safe
		{
			return "Summarize " ~ topic;
		}

		@prompt("byPriority", "Prompt taking an enum argument")
		string byPriority(Priority p) @safe
		{
			return "priority " ~ (p == Priority.high ? "high" : "low");
		}

		@prompt("repeat", "Prompt taking an integer argument")
		string repeat(int count) @safe
		{
			return "count " ~ (count > 0 ? "pos" : "nonpos");
		}
	}

	import vibe.data.json : parseJsonString;
	import mcp.server.server : ToolResponse;
	import mcp.protocol.modern : InputRequest;

	// Fixture exercising icons, _meta, annotation title, per-resource cache
	// hint, and MRTR (ToolResponse) tools.
	private final class ExtApi
	{
		@tool("draw", "Draw something")
		@icon("https://example.com/draw.png", "image/png", ["48x48"])
		@meta(parseJsonString(`{"category":"art"}`))
		@readOnly @hintTitle("Draw Tool") string draw(string spec) @safe
		{
			return "drew " ~ spec;
		}

		@tool("ask", "MRTR tool that may ask for more input")
		ToolResponse ask(string seed) @safe
		{
			if (seed.length == 0)
				return ToolResponse.inputRequired([
				InputRequest("req1", "elicitation", Json.emptyObject)
			]);
			CallToolResult r;
			r.content = [Content.makeText("seeded " ~ seed)];
			return ToolResponse.complete(r);
		}

		@resource("ext://cached", "Cached", "application/json")
		@icon("https://example.com/res.svg")
		@meta(parseJsonString(`{"origin":"db"}`))
		@cache(5.seconds, "private")
		string cached() @safe
		{
			return "{}";
		}

		@prompt("greeting", "A greeting prompt")
		@icon("https://example.com/prompt.png", "image/png", ["32x32"])
		@meta(parseJsonString(`{"audience":"all"}`))
		string greeting() @safe
		{
			return "hello";
		}
	}
}

unittest  // @tool reflection: schema derivation + typed dispatch
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	Json lp = Json.emptyObject;
	auto list = s.handle(Message(makeRequest(Json(1), "tools/list", lp))).get;
	assert(list["result"]["tools"].length == 7);

	// add -> scalar return wrapped under `result`, with an inferred outputSchema.
	Json p = Json.emptyObject;
	p["name"] = "add";
	p["arguments"] = Json(["a": Json(4), "b": Json(5)]);
	auto r = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
	assert(r["result"]["structuredContent"]["result"].get!int == 9);
}

unittest  // @tool reflection: outputSchema is inferred from the return type
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json addSchema, statsSchema, greetTool;
	foreach (i; 0 .. tools.length)
	{
		const name = tools[i]["name"].get!string;
		if (name == "add")
			addSchema = tools[i]["outputSchema"];
		else if (name == "stats")
			statsSchema = tools[i]["outputSchema"];
		else if (name == "greet")
			greetTool = tools[i];
	}

	// Scalar return -> object schema wrapping the value under `result`.
	assert(addSchema["type"].get!string == "object");
	assert(addSchema["properties"]["result"]["type"].get!string == "integer");

	// Struct return -> the struct's object schema directly.
	assert(statsSchema["type"].get!string == "object");
	assert(statsSchema["properties"]["count"]["type"].get!string == "integer");
	assert(statsSchema["properties"]["total"]["type"].get!string == "number");

	// String return -> unstructured text, no outputSchema.
	assert("outputSchema" !in greetTool);
}

unittest  // @tool reflection: struct return produces matching structuredContent
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	Json p = Json.emptyObject;
	p["name"] = "stats";
	p["arguments"] = Json(["values": Json([Json(2), Json(3), Json(5)])]);
	auto r = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
	assert(r["result"]["structuredContent"]["count"].get!int == 3);
	// `total` (a double) serializes as a JSON number; just confirm it's present
	// and numeric (int/float representation is vibe's choice for whole values).
	auto total = r["result"]["structuredContent"]["total"];
	assert(total.type == Json.Type.float_ || total.type == Json.Type.int_);
}

unittest  // @tool reflection: string return becomes text content
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	Json p = Json.emptyObject;
	p["name"] = "greet";
	p["arguments"] = Json(["name": Json("Sam")]);
	auto r = s.handle(Message(makeRequest(Json(3), "tools/call", p))).get;
	assert(r["result"]["content"][0]["text"].get!string == "Hello, Sam!");
}

unittest  // @tool reflection: a void-returning tool compiles, registers, and dispatches
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	static final class VoidApi
	{
		string lastCommand;

		@tool("doThing", "Perform a side-effecting command")
		void doThing(string what) @safe
		{
			lastCommand = what;
		}
	}

	auto api = new VoidApi;
	auto s = new McpServer("t", "1");
	registerHandlers(s, api);

	// The void tool is registered like any other.
	auto tools = s.handle(MakeListMessage()).get["result"]["tools"];
	assert(tools.length == 1);
	assert(tools[0]["name"].get!string == "doThing");

	// Dispatching invokes the method and returns an empty, non-error result.
	Json p = Json.emptyObject;
	p["name"] = "doThing";
	p["arguments"] = Json(["what": Json("erase")]);
	auto r = s.handle(Message(makeRequest(Json(7), "tools/call", p))).get;
	assert(api.lastCommand == "erase");
	assert(("error" in r) is null);
	assert(r["result"]["content"].length == 0);
	assert(("structuredContent" in r["result"]) is null);
}

unittest  // @tool reflection: a void-returning tool advertises no outputSchema
{
	static final class VoidSchemaApi
	{
		@tool("noop", "Does nothing observable")
		void noop() @safe
		{
		}
	}

	auto s = new McpServer("t", "1");
	registerHandlers(s, new VoidSchemaApi);
	auto tools = s.handle(MakeListMessage()).get["result"]["tools"];
	assert(tools.length == 1);
	assert(("outputSchema" in tools[0]) is null);
}

unittest  // @tool reflection: enum param schema + optional Nullable param
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(MakeListMessage()).get["result"]["tools"];
	// find classify
	bool found;
	foreach (i; 0 .. tools.length)
	{
		if (tools[i]["name"].get!string == "classify")
		{
			found = true;
			auto schema = tools[i]["inputSchema"];
			assert(schema["properties"]["p"]["type"].get!string == "string");
			assert(schema["properties"]["p"]["enum"].length == 2);
			// only p is required (note is Nullable)
			assert(schema["required"].length == 1);
		}
	}
	assert(found);
}

unittest  // @resource and @prompt reflection register and dispatch
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	Json rp = Json.emptyObject;
	rp["uri"] = "test://doc";
	auto rr = s.handle(Message(makeRequest(Json(1), "resources/read", rp))).get;
	assert(rr["result"]["contents"][0]["text"].get!string == "document body");

	Json pp = Json.emptyObject;
	pp["name"] = "intro";
	pp["arguments"] = Json(["topic": Json("MCP")]);
	auto pr = s.handle(Message(makeRequest(Json(2), "prompts/get", pp))).get;
	assert(pr["result"]["messages"][0]["content"]["text"].get!string == "Tell me about MCP");
}

unittest  // @prompt enum arg given an invalid member -> InvalidParams (-32602)
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.errors : ErrorCode;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	Json pp = Json.emptyObject;
	pp["name"] = "byPriority";
	pp["arguments"] = Json(["p": Json("urgent")]); // not a Priority member
	auto resp = s.handle(Message(makeRequest(Json(2), "prompts/get", pp))).get;
	assert("error" in resp, "expected an error for an invalid enum prompt argument");
	assert(resp["error"]["code"].get!int == ErrorCode.invalidParams,
			"invalid enum prompt arg must map to -32602, not -32603");
}

unittest  // @prompt integer arg given a non-numeric string -> InvalidParams (-32602)
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.errors : ErrorCode;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	Json pp = Json.emptyObject;
	pp["name"] = "repeat";
	pp["arguments"] = Json(["count": Json("abc")]); // not an integer
	auto resp = s.handle(Message(makeRequest(Json(3), "prompts/get", pp))).get;
	assert("error" in resp, "expected an error for a non-numeric integer prompt argument");
	assert(resp["error"]["code"].get!int == ErrorCode.invalidParams,
			"non-numeric integer prompt arg must map to -32602, not -32603");
}

unittest  // @prompt string arg given JSON null -> clean InvalidParams, not vibe deserialization error
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.errors : ErrorCode;
	import std.algorithm : canFind;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	Json pp = Json.emptyObject;
	pp["name"] = "intro";
	pp["arguments"] = Json(["topic": Json(null)]); // null for required string arg
	auto resp = s.handle(Message(makeRequest(Json(4), "prompts/get", pp))).get;
	assert("error" in resp, "expected an error for a null required prompt argument");
	assert(resp["error"]["code"].get!int == ErrorCode.invalidParams,
			"null required prompt arg must map to -32602, not -32603");
	// The clean error path treats null as absent and reports a missing-required diagnostic.
	// The indirect path (vibe deserialization) produces an "argument 'topic': ..." prefix.
	const msg = resp["error"]["message"].get!string;
	assert(msg.canFind("Missing required argument") || msg.canFind("required argument is missing"),
			"expected a clean missing-required diagnostic, got: " ~ msg);
}

unittest  // @prompt reflection: optional title is emitted in prompts/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	auto prompts = s.handle(Message(makeRequest(Json(1), "prompts/list",
			Json.emptyObject))).get["result"]["prompts"];

	bool foundIntro, foundSummary;
	foreach (i; 0 .. prompts.length)
	{
		auto name = prompts[i]["name"].get!string;
		if (name == "intro")
		{
			foundIntro = true;
			// A prompt without a title carries none on the wire.
			assert("title" !in prompts[i]);
		}
		else if (name == "summary")
		{
			foundSummary = true;
			assert(prompts[i]["title"].get!string == "Summarize Text");
		}
	}
	assert(foundIntro && foundSummary);
}

unittest  // @audience/@priority value UDAs: annotations appear in resources/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);

	auto res = s.handle(Message(makeRequest(Json(1), "resources/list",
			Json.emptyObject))).get["result"]["resources"];

	bool foundReadme, foundDoc;
	foreach (i; 0 .. res.length)
	{
		auto uri = res[i]["uri"].get!string;
		if (uri == "test://readme")
		{
			foundReadme = true;
			assert(res[i]["annotations"]["audience"][0].get!string == "user");
			assert(res[i]["annotations"]["priority"].get!double == 0.9);
		}
		else if (uri == "test://doc")
		{
			foundDoc = true;
			// A resource without annotation UDAs carries no annotations.
			assert("annotations" !in res[i]);
		}
	}
	assert(foundReadme && foundDoc);
}

unittest  // @audience value UDA: multiple roles round-trip into annotations
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	@safe final class MultiAudienceApi
	{
		@resource("test://both", "Both", "text/plain")
		@audience("user", "assistant") @priority(0.5)
		string both() @safe
		{
			return "both";
		}
	}

	auto s = new McpServer("t", "1");
	registerHandlers(s, new MultiAudienceApi);
	auto res = s.handle(Message(makeRequest(Json(1), "resources/list",
			Json.emptyObject))).get["result"]["resources"];

	Json bothRes;
	foreach (i; 0 .. res.length)
		if (res[i]["uri"].get!string == "test://both")
			bothRes = res[i];
	assert(bothRes.type == Json.Type.object);
	auto anns = bothRes["annotations"];
	assert(anns["audience"].length == 2);
	assert(anns["audience"][0].get!string == "user");
	assert(anns["audience"][1].get!string == "assistant");
	assert(anns["priority"].get!double == 0.5);
	// lastModified was not set, so it is omitted.
	assert("lastModified" !in anns);
}

unittest  // @tool reflection: optional title is emitted in tools/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json eraseTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "erase")
			eraseTool = tools[i];
	assert(eraseTool.type == Json.Type.object);
	assert(eraseTool["title"].get!string == "Erase Record");
}

unittest  // marker hint UDAs: hints are serialized into annotations
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json eraseTool, addTool;
	foreach (i; 0 .. tools.length)
	{
		const name = tools[i]["name"].get!string;
		if (name == "erase")
			eraseTool = tools[i];
		else if (name == "add")
			addTool = tools[i];
	}

	auto anns = eraseTool["annotations"];
	assert(anns["destructiveHint"].get!bool == true);
	assert(anns["idempotentHint"].get!bool == true);
	// Unset hints are omitted entirely.
	assert("readOnlyHint" !in anns);
	assert("openWorldHint" !in anns);

	// A tool without any hint UDA carries no annotations object.
	assert("annotations" !in addTool);
}

unittest  // marker-UDA hints: @readOnly + @hintTitle produce the wire shape
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	@safe final class ReadOnlyApi
	{
		@tool("peek", "Read-only peek")
		@readOnly @hintTitle("Peek")
		string peek() @safe
		{
			return "peek";
		}
	}

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ReadOnlyApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json peekTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "peek")
			peekTool = tools[i];
	assert(peekTool.type == Json.Type.object);
	auto anns = peekTool["annotations"];
	// The @readOnly marker sets readOnlyHint=true; @hintTitle sets the title.
	assert(anns["readOnlyHint"].get!bool == true);
	assert(anns["title"].get!string == "Peek");
	// The unset markers are omitted entirely.
	assert("destructiveHint" !in anns);
	assert("idempotentHint" !in anns);
	assert("openWorldHint" !in anns);
}

unittest  // method-level marker UDAs coexist with a @describeParam'd parameter
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	// Method-level marker UDAs (`@readOnly`/`@idempotent`) and `@describeParam`
	// live side by side on the declaration. The schema builder must fold the
	// description into the named property without the markers adding spurious
	// facet keys, and the markers must still populate ToolAnnotations.
	@safe final class MarkedParamApi
	{
		@tool("calc", "Read-only calc with a described parameter")
		@readOnly @idempotent @describeParam("a", "the left operand")
		int calc(int a, int b) @safe
		{
			return a + b;
		}
	}

	auto s = new McpServer("t", "1");
	registerHandlers(s, new MarkedParamApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json calcTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "calc")
			calcTool = tools[i];
	assert(calcTool.type == Json.Type.object);

	// The described parameter keeps its description; the leaked markers add no
	// spurious facet keys to its schema.
	auto aSchema = calcTool["inputSchema"]["properties"]["a"];
	assert(aSchema["description"].get!string == "the left operand");
	assert("minimum" !in aSchema);
	assert("maximum" !in aSchema);

	// The method-level markers still set the behavioral hints.
	auto anns = calcTool["annotations"];
	assert(anns["readOnlyHint"].get!bool == true);
	assert(anns["idempotentHint"].get!bool == true);
}

version (unittest) private struct HeaderPayload
{
	string id;
}

version (unittest) private class StructHeaderApi
{
	@tool("agg", "Aggregate header")
	@mcpHeader("p", "X-Payload")
	string agg(HeaderPayload p) @safe
	{
		return p.id;
	}
}

version (unittest) private class ArrayHeaderApi
{
	@tool("arr", "Array header")
	@mcpHeader("tags", "X-Tags")
	string arr(string[] tags) @safe
	{
		return tags.length ? tags[0] : "";
	}
}

version (unittest) private class NullableHeaderApi
{
	@tool("opt", "Optional primitive header")
	@mcpHeader("region", "X-Region")
	string opt(Nullable!int region) @safe
	{
		return region.isNull ? "" : "set";
	}
}

version (unittest) private class UnknownHeaderParamApi
{
	@tool("q", "Header naming a missing parameter")
	@mcpHeader("nope", "X-Region")
	string q(string region) @safe
	{
		return region;
	}
}

version (unittest) private class CtxHeaderParamApi
{
	@tool("q", "Header naming an injected context parameter")
	@mcpHeader("ctx", "X-Region")
	string q(string region, RequestContext ctx) @safe
	{
		return region;
	}
}

unittest  // @mcpHeader: a struct-typed parameter is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new StructHeaderApi)));
}

unittest  // @mcpHeader: an array-typed parameter is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new ArrayHeaderApi)));
}

unittest  // @mcpHeader: a Nullable-of-primitive parameter is accepted at compile time
{
	auto s = new McpServer("t", "1");
	assert(__traits(compiles, registerHandlers(s, new NullableHeaderApi)));
}

unittest  // @mcpHeader: naming a non-existent parameter is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new UnknownHeaderParamApi)));
}

unittest  // @mcpHeader: naming an injected context parameter is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new CtxHeaderParamApi)));
}

unittest  // @mcpHeader reflection: x-mcp-header is emitted into the param schema
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.modern : paramHeaders;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json queryTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "query")
			queryTool = tools[i];
	assert(queryTool.type == Json.Type.object);

	auto schema = queryTool["inputSchema"];
	// The annotated parameter carries the x-mcp-header property.
	assert(schema["properties"]["region"]["x-mcp-header"].get!string == "Region");
	// The non-annotated parameter does not.
	assert("x-mcp-header" !in schema["properties"]["limit"]);

	// paramHeaders surfaces top-level annotations; filter to path.length == 1 for the flat map.
	string[string] m;
	foreach (ph; paramHeaders(schema))
		if (ph.path.length == 1)
			m[ph.path[0]] = ph.header;
	assert(m["region"] == "Mcp-Param-Region");
}

unittest  // @tool dispatch: a malformed arg (validation off) yields a clean attributed message
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import std.algorithm.searching : canFind;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	// With schema validation off the coarse pre-dispatch check is bypassed, so the
	// marshaller sees the malformed value and must report a clean, attributed error.
	s.disableInputSchemaValidation();

	Json cp = Json.emptyObject;
	cp["name"] = "query";
	cp["arguments"] = Json(["region": Json("us"), "limit": Json("abc")]);
	auto resp = s.handle(Message(makeRequest(Json(4), "tools/call", cp))).get;
	// Tool input failures are classified as isError:true results, not -32602.
	assert("result" in resp, "malformed tool arg must be an isError result, not a protocol error");
	assert(resp["result"]["isError"].get!bool);
	auto text = resp["result"]["content"][0]["text"].get!string;
	assert(text.canFind("argument 'limit'"),
			"the error text must attribute the failure to the named argument: " ~ text);
}

unittest  // @describeParam UDA: parameter descriptions appear in tool inputSchema
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json annotateTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "annotate")
			annotateTool = tools[i];
	assert(annotateTool.type == Json.Type.object);

	auto props = annotateTool["inputSchema"]["properties"];
	// Each method-level @describeParam documents the named property.
	assert(props["id"]["description"].get!string == "the document id");
	assert(props["count"]["description"].get!string == "how many copies");
}

unittest  // @describeParam UDA: prompt argument descriptions appear in prompts/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DemoApi);
	auto prompts = s.handle(Message(makeRequest(Json(1), "prompts/list",
			Json.emptyObject))).get["result"]["prompts"];

	Json described;
	foreach (i; 0 .. prompts.length)
		if (prompts[i]["name"].get!string == "describedPrompt")
			described = prompts[i];
	assert(described.type == Json.Type.object);

	auto args = described["arguments"];
	assert(args.length == 1);
	assert(args[0]["name"].get!string == "topic");
	assert(args[0]["description"].get!string == "the subject to write about");

	// A prompt argument without @describeParam carries no description on the wire.
	Json intro;
	foreach (i; 0 .. prompts.length)
		if (prompts[i]["name"].get!string == "intro")
			intro = prompts[i];
	assert("description" !in intro["arguments"][0]);
}

unittest  // ToolAnnotations: typed struct round-trips through JSON
{
	ToolAnnotations a;
	a.title = "Display";
	a.readOnlyHint = true;
	a.openWorldHint = false;
	auto j = a.toJson();
	auto b = ToolAnnotations.fromJson(j);
	assert(b.title.get == "Display");
	assert(b.readOnlyHint.get == true);
	assert(b.openWorldHint.get == false);
	assert(b.destructiveHint.isNull);
}

unittest  // ToolAnnotations: empty struct produces an empty object
{
	ToolAnnotations a;
	assert(a.empty);
	assert(a.toJson().length == 0);
}

version (unittest) private auto MakeListMessage()
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	return Message(makeRequest(Json(99), "tools/list", Json.emptyObject));
}

unittest  // @icon UDA: tool icons appear in tools/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json drawTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "draw")
			drawTool = tools[i];
	assert(drawTool.type == Json.Type.object);
	assert(drawTool["icons"].length == 1);
	assert(drawTool["icons"][0]["src"].get!string == "https://example.com/draw.png");
	assert(drawTool["icons"][0]["mimeType"].get!string == "image/png");
	assert(drawTool["icons"][0]["sizes"][0].get!string == "48x48");
}

unittest  // @meta UDA: tool descriptor `_meta` appears in tools/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json drawTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "draw")
			drawTool = tools[i];
	assert(drawTool["_meta"]["category"].get!string == "art");
}

unittest  // @hintTitle: annotation-level title appears in annotations
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json drawTool;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "draw")
			drawTool = tools[i];
	// The annotation-level title is distinct from tool.title and lives under annotations.
	assert(drawTool["annotations"]["title"].get!string == "Draw Tool");
	assert(drawTool["annotations"]["readOnlyHint"].get!bool == true);
}

unittest  // MRTR UDA tool: returning ToolResponse.inputRequired surfaces inputRequests
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.modern : MetaKey;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);

	// Empty seed -> the tool asks for more input (MRTR InputRequiredResult). MRTR
	// exists only on the draft (stateless) protocol, so the request must negotiate
	// the draft version via `_meta`; otherwise the projection layer rejects an
	// input-required result for a non-MRTR peer.
	Json p = Json.emptyObject;
	p["name"] = "ask";
	p["arguments"] = Json(["seed": Json("")]);
	Json meta = Json.emptyObject;
	meta[MetaKey.protocolVersion] = "2026-07-28";
	meta[MetaKey.clientCapabilities] = Json(["elicitation": Json.emptyObject]);
	p["_meta"] = meta;
	auto r = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
	// An InputRequiredResult carries `inputRequests` (a map keyed by id), not content.
	assert(r["result"]["inputRequests"].type == Json.Type.object);
	assert(r["result"]["inputRequests"]["req1"]["method"].get!string == "elicitation/create");
}

unittest  // MRTR on a non-draft session: an input-required result is rejected, not emitted off-schema
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.errors : ErrorCode;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);

	// No draft `_meta.protocolVersion` -> the session is non-draft (no MRTR). A
	// handler that nonetheless returns ToolResponse.inputRequired would emit the
	// draft-only `{inputRequests}` shape (no `content`) to a peer whose
	// CallToolResult schema requires content; the projection layer rejects this
	// programming error with an internal error rather than letting it reach the wire.
	Json p = Json.emptyObject;
	p["name"] = "ask";
	p["arguments"] = Json(["seed": Json("")]);
	auto r = s.handle(Message(makeRequest(Json(4), "tools/call", p))).get;
	assert(r["error"]["code"].get!int == ErrorCode.internalError);
}

unittest  // argsAs deserializes a typed struct through the enum-by-name policy
{
	enum Color
	{
		red,
		green
	}

	struct Args
	{
		int n;
		Color c;
	}

	Json j = Json(["n": Json(3), "c": Json("green")]);
	auto a = argsAs!Args(j);
	assert(a.n == 3);
	assert(a.c == Color.green);
}

unittest  // argsAs maps a conversion failure to invalidParams (-32602)
{
	import mcp.protocol.errors : McpException, ErrorCode;

	struct Args
	{
		int n;
	}

	// `n` is a string, not an int -> vibe conversion fails -> invalidParams.
	Json j = Json(["n": Json("not-a-number")]);
	bool threw;
	try
		cast(void) argsAs!Args(j);
	catch (McpException e)
	{
		threw = true;
		assert(e.code == ErrorCode.invalidParams);
	}
	assert(threw, "argsAs must surface a conversion failure as invalidParams");
}

unittest  // MRTR UDA tool: returning ToolResponse.complete produces a normal result
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);

	Json p = Json.emptyObject;
	p["name"] = "ask";
	p["arguments"] = Json(["seed": Json("X")]);
	auto r = s.handle(Message(makeRequest(Json(3), "tools/call", p))).get;
	assert("inputRequests" !in r["result"]);
	assert(r["result"]["content"][0]["text"].get!string == "seeded X");
}

unittest  // @icon / @meta UDA on a resource: appear in resources/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	auto res = s.handle(Message(makeRequest(Json(1), "resources/list",
			Json.emptyObject))).get["result"]["resources"];

	Json cachedRes;
	foreach (i; 0 .. res.length)
		if (res[i]["uri"].get!string == "ext://cached")
			cachedRes = res[i];
	assert(cachedRes.type == Json.Type.object);
	assert(cachedRes["icons"][0]["src"].get!string == "https://example.com/res.svg");
	assert(cachedRes["_meta"]["origin"].get!string == "db");
}

unittest  // @icon UDA on a @prompt: icons appear in prompts/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	auto prompts = s.handle(Message(makeRequest(Json(1), "prompts/list",
			Json.emptyObject))).get["result"]["prompts"];

	Json greeting;
	foreach (i; 0 .. prompts.length)
		if (prompts[i]["name"].get!string == "greeting")
			greeting = prompts[i];
	assert(greeting.type == Json.Type.object);
	assert(greeting["icons"].length == 1);
	assert(greeting["icons"][0]["src"].get!string == "https://example.com/prompt.png");
	assert(greeting["icons"][0]["mimeType"].get!string == "image/png");
	assert(greeting["icons"][0]["sizes"][0].get!string == "32x32");
}

unittest  // @meta UDA on a @prompt: descriptor `_meta` appears in prompts/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	auto prompts = s.handle(Message(makeRequest(Json(1), "prompts/list",
			Json.emptyObject))).get["result"]["prompts"];

	Json greeting;
	foreach (i; 0 .. prompts.length)
		if (prompts[i]["name"].get!string == "greeting")
			greeting = prompts[i];
	assert(greeting.type == Json.Type.object);
	assert(greeting["_meta"]["audience"].get!string == "all");
}

version (unittest) private final class ThemedIconApi
{
	@tool("night", "A tool with a dark-theme icon")
	@icon("https://example.com/night.png", "image/png", ["48x48"], "dark")
	string night(string x) @safe
	{
		return x;
	}
}

unittest  // @icon UDA: theme field propagates through collectIcons to tools/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ThemedIconApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	assert(tools.length == 1);
	assert(tools[0]["icons"].length == 1);
	assert(tools[0]["icons"][0]["src"].get!string == "https://example.com/night.png");
	assert(tools[0]["icons"][0]["theme"].get!string == "dark");
}

version (unittest) private auto draftRead(string uri) @safe
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.protocol.modern : MetaKey;

	Json meta = Json.emptyObject;
	meta[MetaKey.protocolVersion] = "2026-07-28";
	meta[MetaKey.clientInfo] = Json(["name": Json("c"), "version": Json("1")]);
	meta[MetaKey.clientCapabilities] = Json.emptyObject;
	Json params = Json.emptyObject;
	params["uri"] = uri;
	params["_meta"] = meta;
	return Message(makeRequest(Json(1), "resources/read", params));
}

unittest  // @cache UDA on a resource: draft resources/read carries CacheableResult fields
{
	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	// A draft request (carrying the protocol-version _meta) gets cache fields.
	auto rr = s.handle(draftRead("ext://cached")).get;
	assert(rr["result"]["ttlMs"].get!long == 5000);
	assert(rr["result"]["cacheScope"].get!string == "private");
}

unittest  // @cache UDA: pre-draft resources/read has NO cache fields (no wire regression)
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ExtApi);
	// A plain (non-draft) request must NOT carry any cache fields.
	Json rp = Json.emptyObject;
	rp["uri"] = "ext://cached";
	auto rr = s.handle(Message(makeRequest(Json(1), "resources/read", rp))).get;
	assert("ttlMs" !in rr["result"]);
	assert("cacheScope" !in rr["result"]);
}

version (unittest) private class InvalidCacheScopeApi
{
	@resource("ext://bad", "Bad", "application/json")
	@cache(5.seconds, "Private")
	string bad() @safe
	{
		return "{}";
	}
}

unittest  // @cache: an unrecognised scope_ value is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new InvalidCacheScopeApi)));
}

version (unittest)
{
	private enum Color
	{
		red,
		green,
		blue
	}

	private struct ColorBox
	{
		Color e;
	}

	private struct Palette
	{
		Color[] colors;
	}

	// Fixtures for enum (de)serialization, default values, and resource-template
	// typed parameters.
	private final class EnumApi
	{
		// Returning a struct holding an enum must emit the enum's string name.
		@tool("box", "Return a struct holding a color")
		ColorBox box(Color c) @safe
		{
			return ColorBox(c);
		}

		// Bare enum return is wrapped under `result` as a string.
		@tool("pick", "Return a bare color")
		Color pick() @safe
		{
			return Color.blue;
		}

		// Array of enums nested in a struct.
		@tool("palette", "Return a palette")
		Palette palette() @safe
		{
			return Palette([Color.red, Color.green]);
		}

		// A struct param containing an enum supplied by name.
		@tool("name", "Name the color in a box")
		string name(ColorBox b) @safe
		{
			import std.conv : to;

			return b.e.to!string;
		}

		// A parameter with a D-level default.
		@tool("limited", "Tool with a defaulted parameter")
		int limited(int n, int limit = 7) @safe
		{
			return n + limit;
		}

		@resourceTemplate("widget://{id}", "Widget", "text/plain")
		string widget(int id) @safe
		{
			import std.conv : to;

			return "widget-" ~ id.to!string;
		}

		@resourceTemplate("hue://{shade}", "Hue", "text/plain")
		string hue(Color shade) @safe
		{
			import std.conv : to;

			return "hue-" ~ shade.to!string;
		}
	}
}

unittest  // enum field in a returned struct serializes by member name
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EnumApi);
	Json p = Json.emptyObject;
	p["name"] = "box";
	p["arguments"] = Json(["c": Json("green")]);
	auto r = s.handle(Message(makeRequest(Json(1), "tools/call", p))).get;
	assert(r["result"]["structuredContent"]["e"].get!string == "green");
}

unittest  // bare enum return is wrapped under `result` as its string name
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EnumApi);
	Json p = Json.emptyObject;
	p["name"] = "pick";
	p["arguments"] = Json.emptyObject;
	auto r = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
	assert(r["result"]["structuredContent"]["result"].get!string == "blue");
}

unittest  // array of enums inside a struct serializes by name
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EnumApi);
	Json p = Json.emptyObject;
	p["name"] = "palette";
	p["arguments"] = Json.emptyObject;
	auto r = s.handle(Message(makeRequest(Json(3), "tools/call", p))).get;
	auto colors = r["result"]["structuredContent"]["colors"];
	assert(colors[0].get!string == "red");
	assert(colors[1].get!string == "green");
}

unittest  // enum output passes the tool's own outputSchema validation
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	s.enableOutputSchemaValidation();
	registerHandlers(s, new EnumApi);
	Json p = Json.emptyObject;
	p["name"] = "box";
	p["arguments"] = Json(["c": Json("red")]);
	auto r = s.handle(Message(makeRequest(Json(4), "tools/call", p))).get;
	// The server must not reject its own structured output as schema-invalid.
	assert("error" !in r);
	assert(r["result"]["structuredContent"]["e"].get!string == "red");
}

unittest  // enum nested in a struct param is supplied as its schema string
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EnumApi);
	Json p = Json.emptyObject;
	p["name"] = "name";
	Json box = Json.emptyObject;
	box["e"] = "blue";
	p["arguments"] = Json(["b": box]);
	auto r = s.handle(Message(makeRequest(Json(5), "tools/call", p))).get;
	assert(r["result"]["content"][0]["text"].get!string == "blue");
}

unittest  // a defaulted parameter is absent from inputSchema required
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EnumApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json limited;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "limited")
			limited = tools[i];
	assert(limited.type == Json.Type.object);
	auto req = limited["inputSchema"]["required"];
	bool hasLimit;
	foreach (i; 0 .. req.length)
		if (req[i].get!string == "limit")
			hasLimit = true;
	assert(!hasLimit);
	// `n` (no default) is still required.
	bool hasN;
	foreach (i; 0 .. req.length)
		if (req[i].get!string == "n")
			hasN = true;
	assert(hasN);
}

unittest  // omitting a defaulted arg passes the declared default, not P.init
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EnumApi);
	Json p = Json.emptyObject;
	p["name"] = "limited";
	p["arguments"] = Json(["n": Json(3)]);
	auto r = s.handle(Message(makeRequest(Json(6), "tools/call", p))).get;
	// limit defaults to 7, so 3 + 7 = 10 (not 3 + 0 = 3 from int.init).
	assert(r["result"]["structuredContent"]["result"].get!int == 10);
}

unittest  // a required tool arg missing (schema validation disabled) is an isError, not a default value
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	s.disableInputSchemaValidation();
	registerHandlers(s, new EnumApi);
	Json p = Json.emptyObject;
	p["name"] = "limited";
	p["arguments"] = Json.emptyObject; // omit the required 'n'
	auto r = s.handle(Message(makeRequest(Json(7), "tools/call", p))).get;
	assert(r["result"]["isError"].get!bool);
}

unittest  // resource-template int param receives the captured value, not T.init
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EnumApi);
	Json rp = Json.emptyObject;
	rp["uri"] = "widget://42";
	auto rr = s.handle(Message(makeRequest(Json(1), "resources/read", rp))).get;
	assert(rr["result"]["contents"][0]["text"].get!string == "widget-42");
}

unittest  // resource-template enum param is parsed by member name
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EnumApi);
	Json rp = Json.emptyObject;
	rp["uri"] = "hue://green";
	auto rr = s.handle(Message(makeRequest(Json(2), "resources/read", rp))).get;
	assert(rr["result"]["contents"][0]["text"].get!string == "hue-green");
}

unittest  // resource-template invalid scalar yields an InvalidParams error
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new EnumApi);
	Json rp = Json.emptyObject;
	rp["uri"] = "widget://not-a-number";
	auto rr = s.handle(Message(makeRequest(Json(3), "resources/read", rp))).get;
	assert("error" in rr);
	assert(rr["error"]["code"].get!int == -32602);
}

version (unittest)
{
	import mcp.protocol.capabilities : ClientCapability;

	/// A context that advertises elicitation, so a handler receiving the real
	/// context observes a capability a `NullContext` (which reports no
	/// capabilities) never would.
	private final class ContextProbe : BaseRequestContext
	{
		override bool clientSupports(ClientCapability cap) @safe
		{
			return cap == ClientCapability.elicitationForm;
		}
	}

	private final class ContextPromptApi
	{
		@prompt("ctxPrompt", "Prompt exercising the request context")
		string ctxPrompt(string topic, RequestContext ctx) @safe
		{
			return ctx.clientSupports(ClientCapability.elicitationForm)
				? "elicit-capable: " ~ topic : "no-elicit: " ~ topic;
		}
	}

	private final class ContextTemplateApi
	{
		@resourceTemplate("ctx://{topic}", "ctxTpl", "text/plain")
		string ctxTpl(string topic, RequestContext ctx) @safe
		{
			return ctx.clientSupports(ClientCapability.elicitationForm)
				? "elicit-capable: " ~ topic : "no-elicit: " ~ topic;
		}
	}
}

unittest  // @prompt RequestContext parameter binds to the real request context
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ContextPromptApi);

	auto probe = new ContextProbe;
	Json pp = Json.emptyObject;
	pp["name"] = "ctxPrompt";
	pp["arguments"] = Json(["topic": Json("MCP")]);
	auto pr = s.handle(Message(makeRequest(Json(1), "prompts/get", pp)), probe).get;

	// The handler observed the real context's capabilities; a dummy NullContext
	// would report no capabilities and yield "no-elicit".
	assert(pr["result"]["messages"][0]["content"]["text"].get!string == "elicit-capable: MCP");
}

unittest  // @resourceTemplate RequestContext parameter binds to the real request context
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new ContextTemplateApi);

	auto probe = new ContextProbe;
	Json rp = Json.emptyObject;
	rp["uri"] = "ctx://MCP";
	auto rr = s.handle(Message(makeRequest(Json(1), "resources/read", rp)), probe).get;

	// The handler observed the real context's capabilities; a dummy NullContext
	// would report no capabilities and yield "no-elicit".
	assert(rr["result"]["contents"][0]["text"].get!string == "elicit-capable: MCP");
}

version (unittest) private final class DescribedResourceApi
{
	@resource("res://described", "Described", "text/plain",
			"A human-readable description", "Display Title")
	string described() @safe
	{
		return "body";
	}

	@resource("res://bare", "Bare", "text/plain")
	string bare() @safe
	{
		return "bare body";
	}

	@resourceTemplate("tmpl://{id}", "DescribedTmpl", "text/plain",
			"Template description", "Template Title")
	string describedTmpl(string id) @safe
	{
		return "tmpl " ~ id;
	}

	@resourceTemplate("tmpl2://{id}", "BareTmpl", "text/plain")
	string bareTmpl(string id) @safe
	{
		return "bare tmpl " ~ id;
	}
}

unittest  // @resource description and title fields are emitted in resources/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DescribedResourceApi);
	auto res = s.handle(Message(makeRequest(Json(1), "resources/list",
			Json.emptyObject))).get["result"]["resources"];

	Json described, bare;
	foreach (i; 0 .. res.length)
	{
		auto uri = res[i]["uri"].get!string;
		if (uri == "res://described")
			described = res[i];
		else if (uri == "res://bare")
			bare = res[i];
	}

	assert(described.type == Json.Type.object);
	assert(described["description"].get!string == "A human-readable description");
	assert(described["title"].get!string == "Display Title");

	assert(bare.type == Json.Type.object);
	// A resource without description or title carries neither on the wire.
	assert("description" !in bare);
	assert("title" !in bare);
}

unittest  // @resourceTemplate description and title fields are emitted in resources/templates/list
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new DescribedResourceApi);
	auto tmpl = s.handle(Message(makeRequest(Json(1), "resources/templates/list",
			Json.emptyObject))).get["result"]["resourceTemplates"];

	Json described, bare;
	foreach (i; 0 .. tmpl.length)
	{
		auto ut = tmpl[i]["uriTemplate"].get!string;
		if (ut == "tmpl://{id}")
			described = tmpl[i];
		else if (ut == "tmpl2://{id}")
			bare = tmpl[i];
	}

	assert(described.type == Json.Type.object);
	assert(described["description"].get!string == "Template description");
	assert(described["title"].get!string == "Template Title");

	assert(bare.type == Json.Type.object);
	// A template without description or title carries neither on the wire.
	assert("description" !in bare);
	assert("title" !in bare);
}

// A @describeParam naming a parameter the method does not declare matches
// nothing and silently documents no argument: a programmer error rejected at
// compile time.
version (unittest) private final class DescribeUnknownParamApi
{
	@tool("ping", "Ping tool")
	@describeParam("nope", "names no parameter of ping")
	string ping(string msg) @safe
	{
		return msg;
	}
}

// A @describeParam naming an injected context parameter (excluded from the
// input schema) has no property to document: also a compile-time error.
version (unittest) private final class DescribeCtxParamApi
{
	@tool("ping", "Ping tool")
	@describeParam("ctx", "names the injected context parameter")
	string ping(string msg, RequestContext ctx) @safe
	{
		return msg;
	}
}

unittest  // @describeParam naming an unknown parameter is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new DescribeUnknownParamApi)));
}

unittest  // @describeParam naming an injected context parameter is rejected at compile time
{
	auto s = new McpServer("t", "1");
	assert(!__traits(compiles, registerHandlers(s, new DescribeCtxParamApi)));
}

version (unittest) private final class FacetParamApi
{
	@tool("clamp", "Clamp a value to a range")
	int clamp(@minimum(0) @maximum(100) int value)@safe
	{
		return value < 0 ? 0 : value > 100 ? 100 : value;
	}

	@tool("email", "Send to an email address")
	string email(@format("email") string address)@safe
	{
		return address;
	}
}

unittest  // facet UDAs on bare tool parameters are emitted into inputSchema
{
	import mcp.protocol.jsonrpc : Message, makeRequest;

	auto s = new McpServer("t", "1");
	registerHandlers(s, new FacetParamApi);
	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];

	Json clampTool, emailTool;
	foreach (i; 0 .. tools.length)
	{
		const name = tools[i]["name"].get!string;
		if (name == "clamp")
			clampTool = tools[i];
		else if (name == "email")
			emailTool = tools[i];
	}

	// @minimum and @maximum on a bare int parameter must appear in its schema.
	// A whole-number facet is emitted as a JSON integer (`0`, not `0.0`), so read
	// the bound as an integer rather than asserting a float storage type.
	auto valueProp = clampTool["inputSchema"]["properties"]["value"];
	assert(valueProp["type"].get!string == "integer");
	assert(valueProp["minimum"].get!long == 0);
	assert(valueProp["maximum"].get!long == 100);

	// @format on a bare string parameter must appear in its schema.
	auto addrProp = emailTool["inputSchema"]["properties"]["address"];
	assert(addrProp["type"].get!string == "string");
	assert(addrProp["format"].get!string == "email");
}

version (unittest) private final class TaskUdaApi
{
	import mcp.server.task_context : TaskContext;
	import mcp.protocol.modern : InputRequest;
	import core.time : msecs;

	struct Doubled
	{
		int value;
	}

	struct Approved
	{
		string topic;
		bool approved;
	}

	/// A plain async task: returns a typed result the framework wraps. The
	/// @taskTtl / @taskPollInterval set this task's TTL and poll cadence.
	@task("async_double", "Double a number asynchronously")
	@taskTtl(12_345.msecs) @taskPollInterval(250.msecs)
	@readOnly Doubled asyncDouble(int n, TaskContext tc) @safe
	{
		tc.progress("doubling");
		return Doubled(n * 2);
	}

	/// A task that elicits mid-execution before finishing (re-entrant model).
	@task("approve", "Ask for approval, then finish")
	Approved approve(string topic, TaskContext tc) @safe
	{
		if (!tc.hasInput("ok"))
			return tc.requireInput([
			InputRequest.elicitation("ok", "Approve " ~ topic ~ "?")
		]);
		return Approved(topic, tc.input("ok").get!bool);
	}
}

version (unittest) private Json draftMeta() @safe
{
	import mcp.protocol.modern : MetaKey;

	Json meta = Json.emptyObject;
	meta[MetaKey.protocolVersion] = "2026-07-28";
	meta[MetaKey.clientCapabilities] = Json.emptyObject;
	return meta;
}

unittest  // @task UDA: tool is listed with an input schema derived from its params
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.server.task_context : SyncTaskDispatcher;

	auto s = new McpServer("t", "1");
	s.enableTasks(null, TaskOptions.init, new SyncTaskDispatcher());
	registerHandlers(s, new TaskUdaApi);

	auto tools = s.handle(Message(makeRequest(Json(1), "tools/list",
			Json.emptyObject))).get["result"]["tools"];
	Json dbl;
	foreach (i; 0 .. tools.length)
		if (tools[i]["name"].get!string == "async_double")
			dbl = tools[i];
	assert(dbl.type == Json.Type.object);
	// The TaskContext parameter is injected and omitted from the schema; `n` is.
	assert(("n" in dbl["inputSchema"]["properties"]) !is null);
	assert("tc" !in dbl["inputSchema"]["properties"]);
	assert(dbl["annotations"]["readOnlyHint"].get!bool);
}

unittest  // @task UDA: tools/call returns a task the executor completes
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.server.task_context : SyncTaskDispatcher;

	auto s = new McpServer("t", "1");
	s.enableTasks(null, TaskOptions.init, new SyncTaskDispatcher());
	registerHandlers(s, new TaskUdaApi);

	Json p = Json.emptyObject;
	p["name"] = "async_double";
	p["arguments"] = Json(["n": Json(21)]);
	p["_meta"] = draftMeta();
	auto call = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
	assert(call["result"]["resultType"].get!string == "task");
	const id = call["result"]["taskId"].get!string;
	// @taskTtl(12_345.msecs) / @taskPollInterval(250.msecs) seed the task timing.
	assert(call["result"]["ttlMs"].get!long == 12_345);
	assert(call["result"]["pollIntervalMs"].get!long == 250);

	Json gp = Json(["taskId": Json(id)]);
	gp["_meta"] = draftMeta();
	auto got = s.handle(Message(makeRequest(Json(3), "tasks/get", gp))).get;
	assert(got["result"]["status"].get!string == "completed");
	assert(got["result"]["result"]["structuredContent"]["value"].get!int == 42);
	assert(got["result"]["pollIntervalMs"].get!long == 250);
}

unittest  // @task UDA: a mid-task elicitation suspends and resumes via tasks/update
{
	import mcp.protocol.jsonrpc : Message, makeRequest;
	import mcp.server.task_context : SyncTaskDispatcher;

	auto s = new McpServer("t", "1");
	s.enableTasks(null, TaskOptions.init, new SyncTaskDispatcher());
	registerHandlers(s, new TaskUdaApi);

	Json p = Json.emptyObject;
	p["name"] = "approve";
	p["arguments"] = Json(["topic": Json("deploy")]);
	p["_meta"] = draftMeta();
	auto call = s.handle(Message(makeRequest(Json(2), "tools/call", p))).get;
	const id = call["result"]["taskId"].get!string;

	Json gp = Json(["taskId": Json(id)]);
	gp["_meta"] = draftMeta();
	auto blocked = s.handle(Message(makeRequest(Json(3), "tasks/get", gp))).get;
	assert(blocked["result"]["status"].get!string == "input_required");
	assert(blocked["result"]["inputRequests"]["ok"]["method"].get!string == "elicitation/create");

	Json up = Json([
		"taskId": Json(id),
		"inputResponses": Json(["ok": Json(true)])
	]);
	up["_meta"] = draftMeta();
	auto ack = s.handle(Message(makeRequest(Json(4), "tasks/update", up))).get;
	assert("error" !in ack);

	auto done = s.handle(Message(makeRequest(Json(5), "tasks/get", gp))).get;
	assert(done["result"]["status"].get!string == "completed");
	assert(done["result"]["result"]["structuredContent"]["topic"].get!string == "deploy");
	assert(done["result"]["result"]["structuredContent"]["approved"].get!bool);
}
