using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace Nyxite.Server.Http;

/// <summary>
/// Serves the contract-first <c>openapi/v1.yaml</c>, embedded at build time, as JSON at <c>/openapi/v1.json</c>
/// (04 §4.1). Plain YAML scalars are typed by the YAML 1.2 core schema (null, booleans, integers, floats), quoted ones
/// stay strings, so <c>minLength: 12</c> becomes a number and <c>'200'</c> a string, as OpenAPI expects.
/// </summary>
public static partial class OpenApiDocument
{
    public const string ResourceName = "Nyxite.Server.openapi.v1.yaml";

    private static readonly Lazy<string> Json = new(() => Load().ToJsonString());

    public static JsonNode Load()
    {
        using var stream = typeof(OpenApiDocument).Assembly.GetManifestResourceStream(ResourceName)
                           ?? throw new InvalidOperationException($"Embedded resource {ResourceName} is missing.");
        using var reader = new StreamReader(stream);
        var yaml = new YamlStream();
        yaml.Load(reader);
        return Convert(yaml.Documents[0].RootNode) ?? throw new InvalidOperationException("The OpenAPI document is empty.");
    }

    public static IEndpointRouteBuilder MapOpenApiDocument(this IEndpointRouteBuilder app)
    {
        app.MapGet("/openapi/v1.json", () => Results.Text(Json.Value, "application/json"));
        return app;
    }

    private static JsonNode? Convert(YamlNode node) => node switch
    {
        YamlMappingNode map => new JsonObject(map.Children.Select(kv =>
            KeyValuePair.Create(((YamlScalarNode)kv.Key).Value ?? "", Convert(kv.Value)))),
        YamlSequenceNode seq => new JsonArray(seq.Children.Select(Convert).ToArray()),
        YamlScalarNode scalar => Scalar(scalar),
        _ => throw new InvalidOperationException($"Unsupported YAML node {node.NodeType}."),
    };

    private static JsonNode? Scalar(YamlScalarNode scalar)
    {
        var value = scalar.Value ?? "";
        if (scalar.Style != ScalarStyle.Plain) return JsonValue.Create(value);
        if (value is "" or "~" or "null" or "Null" or "NULL") return null;
        if (value is "true" or "True" or "TRUE") return JsonValue.Create(true);
        if (value is "false" or "False" or "FALSE") return JsonValue.Create(false);
        if (IntPattern().IsMatch(value) && long.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var l))
            return JsonValue.Create(l);
        if (FloatPattern().IsMatch(value) && double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var d))
            return JsonValue.Create(d);
        return JsonValue.Create(value);
    }

    [GeneratedRegex(@"^[-+]?[0-9]+$")]
    private static partial Regex IntPattern();

    [GeneratedRegex(@"^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$")]
    private static partial Regex FloatPattern();
}
