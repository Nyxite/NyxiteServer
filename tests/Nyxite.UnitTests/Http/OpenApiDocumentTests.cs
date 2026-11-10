using System.Text.Json.Nodes;
using Nyxite.Server.Http;

namespace Nyxite.UnitTests.Http;

public sealed class OpenApiDocumentTests
{
    private static readonly JsonNode Doc = OpenApiDocument.Load();

    [Fact]
    public void Plain_scalars_are_typed_and_quoted_ones_stay_strings()
    {
        Assert.Equal("3.1.0", Doc["openapi"]!.GetValue<string>());
        Assert.Equal("1.0.0", Doc["info"]!["version"]!.GetValue<string>());
        var login = Doc["paths"]!["/auth/login/totp"]!["post"]!;
        Assert.True(login["requestBody"]!["required"]!.GetValue<bool>());
        Assert.Equal("^[0-9]{6}$", login["requestBody"]!["content"]!["application/json"]!["schema"]!["properties"]!["totpCode"]!["pattern"]!.GetValue<string>());
        Assert.NotNull(login["responses"]!["200"]);
        Assert.Equal(12, Doc["paths"]!["/auth/register"]!["post"]!["requestBody"]!["content"]!["application/json"]!["schema"]!["properties"]!["password"]!["minLength"]!.GetValue<long>());
    }

    [Fact]
    public void Every_problem_code_the_server_emits_is_in_the_contract()
    {
        var codes = Doc["components"]!["schemas"]!["Problem"]!["properties"]!["code"]!["enum"]!.AsArray().Select(c => c!.GetValue<string>()).ToHashSet();
        foreach (var code in new[] { "validation_failed", "unauthenticated", "token_expired", "acl_denied", "2fa_required", "email_unverified",
                     "account_blocked", "not_found", "conflict", "payload_too_large", "rate_limited", "internal", "unavailable" })
            Assert.Contains(code, codes);
    }
}
