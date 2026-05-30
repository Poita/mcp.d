module mcp.api.schema;

import std.traits;
import std.typecons : Nullable;
import std.conv : to;

import vibe.data.json : Json;

@safe:

/// Generate a JSON Schema fragment describing the D type `T`.
///
/// Mapping: bool -> boolean, integral -> integer, floating point -> number,
/// string -> string, enum -> string with `enum` members, arrays -> array with
/// `items`, structs -> object with `properties`/`required`, `Nullable!T` -> the
/// schema of `T` (optionality is handled by the enclosing object).
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
            static if (!isInstanceOf!(Nullable, typeof(__traits(getMember, T, field))))
                required ~= Json(field);
        }
        s["properties"] = props;
        if (required.length > 0)
            s["required"] = required;
    }
    else
    {
        s["type"] = "string"; // conservative fallback
    }
    return s;
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
