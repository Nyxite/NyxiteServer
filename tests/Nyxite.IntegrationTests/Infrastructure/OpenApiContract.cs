using System.Collections;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Nyxite.Server.Http;

namespace Nyxite.IntegrationTests.Infrastructure;

/// <summary>
/// The contract-first <c>openapi/v1.yaml</c> as something payloads can be checked against (04 §4.1). It understands the
/// JSON Schema keywords the document uses and is strict about objects: a property the contract does not name is drift.
/// </summary>
public static class OpenApiContract
{
    private const string ApiPrefix = "/api/v1";

    private static readonly JsonNode Doc = OpenApiDocument.Load();

    /// <summary>Error statuses every operation can answer with a Problem body, as the document's conventions state.</summary>
    private static readonly HashSet<int> CrossCutting = [400, 401, 403, 429, 500, 503];

    private static readonly (string Template, Regex Pattern, int Literals)[] Paths = Doc["paths"]!.AsObject()
        .Select(p => (p.Key,
            new Regex("^" + Regex.Replace(Regex.Escape(p.Key), @"\\\{[^/]+?}", "[^/]+") + "$", RegexOptions.CultureInvariant),
            p.Key.Split('/').Count(s => !s.StartsWith('{'))))
        .OrderByDescending(p => p.Item3)
        .ToArray();

    /// <summary>The operation a request addresses, or null when the contract has no such path and method.</summary>
    public static JsonObject? Operation(string method, string requestPath)
    {
        var path = requestPath.StartsWith(ApiPrefix + "/", StringComparison.Ordinal) ? requestPath[ApiPrefix.Length..] : requestPath;
        foreach (var (template, pattern, _) in Paths)
        {
            if (pattern.IsMatch(path) && Doc["paths"]![template]![method.ToLowerInvariant()] is JsonObject operation) return operation;
        }

        return null;
    }

    /// <summary>The operation of a route template as the server maps it, constraints like <c>{id:guid}</c> included.</summary>
    public static JsonObject? OperationOfRoute(string method, string routeTemplate)
    {
        var route = "/" + Regex.Replace(routeTemplate.TrimStart('/'), @"\{(\w+):[^}]*\}", "{$1}");
        var path = route.StartsWith(ApiPrefix + "/", StringComparison.Ordinal) ? route[ApiPrefix.Length..] : route;
        return Doc["paths"]![path]?[method.ToLowerInvariant()] as JsonObject;
    }

    /// <summary>What is wrong with a response the server gave, measured against the operation's documented responses.</summary>
    public static List<string> CheckResponse(JsonObject operation, int status, string? mediaType, byte[] body)
    {
        var errors = new List<string>();
        var responses = operation["responses"]!.AsObject();
        var documented = responses[status.ToString(System.Globalization.CultureInfo.InvariantCulture)] ?? responses["default"]
                         ?? (CrossCutting.Contains(status) ? Doc["components"]!["responses"]!["Problem"] : null);
        if (documented is null)
        {
            errors.Add($"status {status} is not documented");
            return errors;
        }

        var content = Resolve(documented)["content"]?.AsObject();
        if (content is null)
        {
            if (body.Length > 0) errors.Add($"status {status} is documented without a body, the server sent {mediaType}");
            return errors;
        }

        if (mediaType is null || content[mediaType]?["schema"] is not { } schema)
        {
            errors.Add($"status {status} is documented as {string.Join(", ", content.Select(c => c.Key))}, the server sent {mediaType ?? "no body"}");
            return errors;
        }

        if (!mediaType.EndsWith("json", StringComparison.Ordinal)) return errors;

        using var json = JsonDocument.Parse(body);
        Validate(json.RootElement, schema, "$", errors);
        return errors;
    }

    /// <summary>
    /// What differs between a request DTO and the operation's JSON request body: property names in both directions, and
    /// the JSON type of each property.
    /// </summary>
    public static List<string> CheckRequestType(JsonObject operation, Type dto)
    {
        var errors = new List<string>();
        if (operation["requestBody"]?["content"]?["application/json"]?["schema"] is not { } schema)
        {
            errors.Add($"the server reads a {dto.Name} body, the contract documents no JSON request body");
            return errors;
        }

        CompareType(dto, schema, dto.Name, errors);
        return errors;
    }

    private static void CompareType(Type dto, JsonNode schema, string path, List<string> errors)
    {
        var documented = Properties(schema);
        var actual = dto.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .ToDictionary(p => JsonNamingPolicy.CamelCase.ConvertName(p.Name), p => p.PropertyType);

        foreach (var name in actual.Keys.Except(documented.Keys)) errors.Add($"{path}.{name} is not in the contract");
        foreach (var name in documented.Keys.Except(actual.Keys)) errors.Add($"{path}.{name} is in the contract, the server does not read it");

        foreach (var (name, type) in actual)
        {
            if (!documented.TryGetValue(name, out var propertySchema)) continue;
            var clr = Nullable.GetUnderlyingType(type) ?? type;
            if (clr == typeof(JsonElement)) continue;
            var types = Types(propertySchema);
            if (types.Count == 0) continue;

            var expected = JsonTypeOf(clr);
            if (!types.Contains(expected) && !(expected == "integer" && types.Contains("number")))
            {
                errors.Add($"{path}.{name} is {expected} on the server and {string.Join("|", types)} in the contract");
                continue;
            }

            if (expected == "object") CompareType(clr, propertySchema, $"{path}.{name}", errors);
        }
    }

    private static string JsonTypeOf(Type clr)
    {
        if (clr == typeof(string) || clr == typeof(Guid) || clr == typeof(DateTimeOffset) || clr == typeof(DateTime) || clr.IsEnum) return "string";
        if (clr == typeof(bool)) return "boolean";
        if (clr == typeof(int) || clr == typeof(long) || clr == typeof(short) || clr == typeof(byte)) return "integer";
        if (clr == typeof(double) || clr == typeof(float) || clr == typeof(decimal)) return "number";
        return typeof(IEnumerable).IsAssignableFrom(clr) ? "array" : "object";
    }

    private static JsonNode Resolve(JsonNode node)
    {
        while (node["$ref"] is { } reference)
        {
            JsonNode target = Doc;
            foreach (var segment in reference.GetValue<string>().TrimStart('#', '/').Split('/'))
                target = target[segment] ?? throw new InvalidOperationException($"Unresolvable $ref {reference}.");
            node = target;
        }

        return node;
    }

    /// <summary>The properties a schema names, through <c>$ref</c> and <c>allOf</c>.</summary>
    private static Dictionary<string, JsonNode> Properties(JsonNode schema)
    {
        schema = Resolve(schema);
        var result = new Dictionary<string, JsonNode>();
        foreach (var part in schema["allOf"]?.AsArray() ?? [])
        {
            foreach (var (name, property) in Properties(part!)) result[name] = property;
        }

        foreach (var (name, property) in schema["properties"]?.AsObject() ?? []) result[name] = property!;
        return result;
    }

    private static HashSet<string> Types(JsonNode schema)
    {
        schema = Resolve(schema);
        return schema["type"] switch
        {
            JsonArray many => many.Select(t => t!.GetValue<string>()).ToHashSet(),
            JsonValue one => [one.GetValue<string>()],
            _ => [],
        };
    }

    private static bool IsOpen(JsonNode schema)
    {
        schema = Resolve(schema);
        if (schema["additionalProperties"] is { } additional && !(additional is JsonValue v && v.TryGetValue<bool>(out var allowed) && !allowed)) return true;
        return (schema["allOf"]?.AsArray() ?? []).Any(part => IsOpen(part!));
    }

    private static void Validate(JsonElement value, JsonNode schema, string path, List<string> errors, bool strict = true)
    {
        schema = Resolve(schema);

        if (schema["oneOf"] is JsonArray oneOf)
        {
            var attempts = oneOf.Select(option =>
            {
                var attempt = new List<string>();
                Validate(value, option!, path, attempt);
                return attempt;
            }).ToList();
            if (attempts.All(a => a.Count > 0)) errors.Add($"{path} matches no oneOf option ({string.Join(" / ", attempts.Select(a => a[0]))})");
        }

        foreach (var part in schema["allOf"]?.AsArray() ?? []) Validate(value, part!, path, errors, strict: false);

        var types = Types(schema);
        if (types.Count > 0 && !types.Contains(KindOf(value)) && !(KindOf(value) == "integer" && types.Contains("number")))
        {
            errors.Add($"{path} is {KindOf(value)}, the contract says {string.Join("|", types)}");
            return;
        }

        if (schema["const"] is { } constant && constant.ToJsonString() != value.GetRawText()) errors.Add($"{path} is {value.GetRawText()}, the contract says {constant.ToJsonString()}");
        if (schema["enum"] is JsonArray allowed && allowed.All(a => a?.ToJsonString() != value.GetRawText()))
            errors.Add($"{path} is {value.GetRawText()}, which is not in the contract's enum");

        switch (value.ValueKind)
        {
            case JsonValueKind.String:
                var text = value.GetString()!;
                if (schema["pattern"] is { } pattern && !Regex.IsMatch(text, pattern.GetValue<string>())) errors.Add($"{path} does not match {pattern.GetValue<string>()}");
                var format = schema["format"]?.GetValue<string>();
                if (format == "uuid" && !Guid.TryParse(text, out _)) errors.Add($"{path} is not a uuid");
                if (format == "date-time" && !value.TryGetDateTimeOffset(out _)) errors.Add($"{path} is not an RFC 3339 timestamp");
                break;

            case JsonValueKind.Array:
                if (schema["items"] is { } items)
                {
                    var index = 0;
                    foreach (var item in value.EnumerateArray()) Validate(item, items, $"{path}[{index++}]", errors);
                }

                break;

            case JsonValueKind.Object:
                foreach (var name in schema["required"]?.AsArray() ?? [])
                {
                    if (!value.TryGetProperty(name!.GetValue<string>(), out _)) errors.Add($"{path}.{name} is required by the contract and missing");
                }

                var properties = Properties(schema);
                var free = properties.Count == 0 || IsOpen(schema);
                foreach (var property in value.EnumerateObject())
                {
                    if (schema["properties"]?[property.Name] is { } propertySchema) Validate(property.Value, propertySchema, $"{path}.{property.Name}", errors);
                    else if (schema["additionalProperties"] is JsonObject additional) Validate(property.Value, additional, $"{path}.{property.Name}", errors);
                    else if (strict && !free && !properties.ContainsKey(property.Name)) errors.Add($"{path}.{property.Name} is not in the contract");
                }

                break;
        }
    }

    private static string KindOf(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Object => "object",
        JsonValueKind.Array => "array",
        JsonValueKind.String => "string",
        JsonValueKind.True or JsonValueKind.False => "boolean",
        JsonValueKind.Null => "null",
        _ => value.TryGetInt64(out _) ? "integer" : "number",
    };
}

/// <summary>Thrown into the test that made the request when the server answers outside the contract.</summary>
public sealed class ContractDriftException(string message) : Exception(message);

/// <summary>
/// Checks every response of every integration test against <c>openapi/v1.yaml</c>: status, media type and body shape.
/// It sits in front of the whole pipeline, so error responses written by the exception handler are checked too.
/// Requests to a path or method the contract does not have are left alone, those are the tests for unknown routes.
/// </summary>
public sealed class ContractCheckFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (context, pipeline) =>
        {
            var operation = OpenApiContract.Operation(context.Request.Method, context.Request.Path.Value ?? "");
            if (operation is null)
            {
                await pipeline(context);
                return;
            }

            var client = context.Response.Body;
            using var buffer = new MemoryStream();
            context.Response.Body = buffer;
            try
            {
                await pipeline(context);
            }
            finally
            {
                context.Response.Body = client;
            }

            var mediaType = context.Response.ContentType?.Split(';')[0].Trim();
            var errors = OpenApiContract.CheckResponse(operation, context.Response.StatusCode, buffer.Length == 0 ? null : mediaType, buffer.ToArray());
            if (errors.Count > 0)
            {
                throw new ContractDriftException(
                    $"{context.Request.Method} {context.Request.Path} answered outside openapi/v1.yaml: {string.Join("; ", errors)}");
            }

            buffer.Position = 0;
            await buffer.CopyToAsync(client, context.RequestAborted);
        });
        next(app);
    };
}
