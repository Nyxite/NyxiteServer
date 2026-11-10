using System.Text;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Http;

/// <summary>
/// The drift check itself (04 §4.1): <see cref="ContractCheckFilter"/> guards every other test, so these prove that it
/// reports what it is there to find.
/// </summary>
public sealed class OpenApiContractTests
{
    private sealed record LoginWithExtraField(string? Email, string? Password, string? ClientKind, string? Locale);

    private sealed record LoginWithoutPassword(string? Email, string? ClientKind);

    private sealed record LoginWithNumericPassword(string? Email, int Password, string? ClientKind);

    private static List<string> Check(string method, string path, int status, string? mediaType, string body) =>
        OpenApiContract.CheckResponse(OpenApiContract.Operation(method, path)!, status, mediaType, Encoding.UTF8.GetBytes(body));

    private const string Challenge = """{"challenge":"second_factor_required","mfaToken":"t","methods":["totp"],"enrollment":false}""";

    [Fact]
    public void A_response_as_documented_passes()
    {
        Assert.Empty(Check("POST", "/api/v1/auth/login", 200, "application/json", Challenge));
        Assert.Empty(Check("DELETE", $"/api/v1/devices/{Guid.NewGuid()}", 204, null, ""));
    }

    [Theory]
    [InlineData("""{"challenge":"second_factor_required","mfaToken":"t","methods":["totp"],"enrollment":false,"userId":"x"}""", "$.userId is not in the contract")]
    [InlineData("""{"challenge":"second_factor_required","methods":["totp"],"enrollment":false}""", "$.mfaToken is required")]
    [InlineData("""{"challenge":"second_factor_required","mfaToken":"t","methods":["totp"],"enrollment":"no"}""", "$.enrollment is string")]
    [InlineData("""{"challenge":"second_factor_required","mfaToken":"t","methods":["sms"],"enrollment":false}""", "$.methods[0] is \"sms\"")]
    [InlineData("""{"challenge":"other","mfaToken":"t","methods":["totp"],"enrollment":false}""", "$.challenge is \"other\"")]
    public void A_response_body_that_differs_from_the_schema_is_reported(string body, string expected)
    {
        var errors = Check("POST", "/api/v1/auth/login", 200, "application/json", body);
        Assert.Contains(errors, e => e.StartsWith(expected, StringComparison.Ordinal));
    }

    [Fact]
    public void An_undocumented_status_or_media_type_is_reported()
    {
        Assert.NotEmpty(Check("POST", "/api/v1/auth/login", 202, "application/json", Challenge));
        Assert.NotEmpty(Check("POST", "/api/v1/auth/login", 200, "text/plain", "ok"));
        Assert.NotEmpty(Check("POST", "/api/v1/auth/login", 200, null, ""));
        Assert.NotEmpty(Check("DELETE", $"/api/v1/devices/{Guid.NewGuid()}", 204, "application/json", "{}"));
    }

    [Fact]
    public void Cross_cutting_errors_pass_as_problems_and_other_error_statuses_must_be_listed()
    {
        const string problem = """{"type":"urn:nyxite:problem:rate_limited","title":"Slow down.","status":429,"code":"rate_limited"}""";
        Assert.Empty(Check("GET", "/api/v1/devices", 429, "application/problem+json", problem));
        Assert.NotEmpty(Check("GET", "/api/v1/devices", 429, "application/problem+json", """{"error":"slow down"}"""));
        Assert.NotEmpty(Check("GET", "/api/v1/devices", 410, "application/problem+json", problem));
    }

    [Fact]
    public void A_request_type_that_differs_from_the_schema_is_reported()
    {
        var login = OpenApiContract.Operation("POST", "/api/v1/auth/login")!;
        Assert.Empty(OpenApiContract.CheckRequestType(login, typeof(Nyxite.Contracts.Auth.LoginRequest)));
        Assert.Contains(OpenApiContract.CheckRequestType(login, typeof(LoginWithExtraField)), e => e.Contains("locale is not in the contract"));
        Assert.Contains(OpenApiContract.CheckRequestType(login, typeof(LoginWithoutPassword)), e => e.Contains("password is in the contract"));
        Assert.Contains(OpenApiContract.CheckRequestType(login, typeof(LoginWithNumericPassword)), e => e.Contains("password is integer"));
        Assert.NotEmpty(OpenApiContract.CheckRequestType(OpenApiContract.Operation("GET", "/api/v1/devices")!, typeof(LoginWithExtraField)));
    }
}
