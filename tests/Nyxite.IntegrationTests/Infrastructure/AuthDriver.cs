using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using OtpNet;

namespace Nyxite.IntegrationTests.Infrastructure;

/// <summary>Drives the native auth flows over HTTP the way a client does.</summary>
public sealed class AuthDriver(NyxiteApp app)
{
    public const string Password = "correct horse battery staple";

    private readonly Dictionary<string, long> _lastStep = new();

    public HttpClient Client() => app.CreateClient();

    public sealed record Tokens(string AccessToken, string RefreshToken);

    public sealed record Account(string Email, Tokens Tokens, byte[]? TotpSecret);

    public static Tokens TokensOf(JsonElement json) =>
        new(json.GetProperty("accessToken").GetString()!, json.GetProperty("refreshToken").GetString()!);

    /// <summary>Registers and, unless <paramref name="verifyEmail"/> is false, confirms the emailed verification code.</summary>
    public async Task<Tokens> RegisterAsync(string email, string password = Password, bool verifyEmail = true)
    {
        var response = await Client().PostAsJsonAsync("/api/v1/auth/register",
            new { email, displayName = "Test User", password, clientKind = "desktop" });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var tokens = TokensOf(await response.JsonAsync());
        if (verifyEmail) await VerifyEmailAsync(tokens.AccessToken, email);
        return tokens;
    }

    public async Task VerifyEmailAsync(string accessToken, string email)
    {
        var verify = await Client().WithBearer(accessToken).PostAsJsonAsync("/api/v1/auth/email/verify",
            new { code = app.Email.LastCode(email) });
        Assert.Equal(HttpStatusCode.NoContent, verify.StatusCode);
    }

    /// <summary>Registers, enrolls TOTP and refreshes into a full session.</summary>
    public async Task<Account> RegisterWithTotpAsync(string? email = null)
    {
        email ??= $"user-{Guid.NewGuid():N}@example.org";
        var limited = await RegisterAsync(email);
        var secret = await EnrollTotpAsync(limited.AccessToken);
        var refreshed = await Client().PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken = limited.RefreshToken });
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        return new Account(email, TokensOf(await refreshed.JsonAsync()), secret);
    }

    public async Task<byte[]> EnrollTotpAsync(string accessToken, string? stepUpToken = null)
    {
        var client = Client().WithBearer(accessToken);
        var enroll = await client.PostJsonAsync("/api/v1/auth/totp/enroll", stepUpToken is null ? null : new { stepUpToken });
        Assert.Equal(HttpStatusCode.OK, enroll.StatusCode);
        var secret = Base32Encoding.ToBytes((await enroll.JsonAsync()).GetProperty("secret").GetString()!);
        var verify = await client.PostAsJsonAsync("/api/v1/auth/totp/verify", new { totpCode = Code(secret) });
        Assert.Equal(HttpStatusCode.NoContent, verify.StatusCode);
        return secret;
    }

    /// <summary>
    /// A fresh TOTP code. The server accepts each time step once (RFC 6238 §5.2), so when the current step of this secret
    /// was already used, the shared clock moves to the start of the next step first.
    /// </summary>
    public string Code(byte[] secret)
    {
        var key = Convert.ToBase64String(secret);
        var step = app.Clock.GetUtcNow().ToUnixTimeSeconds() / 30;
        if (_lastStep.TryGetValue(key, out var last) && last >= step)
        {
            app.Clock.Now = DateTimeOffset.FromUnixTimeSeconds((last + 1) * 30);
            step = last + 1;
        }

        _lastStep[key] = step;
        return new Totp(secret).ComputeTotp(app.Clock.GetUtcNow().UtcDateTime);
    }

    /// <summary>The code of the current step without marking it used, to test replays.</summary>
    public string CurrentCode(byte[] secret) => new Totp(secret).ComputeTotp(app.Clock.GetUtcNow().UtcDateTime);

    public string WrongCode(byte[] secret) => ((int.Parse(CurrentCode(secret)) + 500_000) % 1_000_000).ToString("D6");

    public async Task<string> PasswordStepAsync(string email, string password = Password, string clientKind = "web")
    {
        var response = await Client().PostAsJsonAsync("/api/v1/auth/login", new { email, password, clientKind });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.JsonAsync();
        Assert.Equal("second_factor_required", json.GetProperty("challenge").GetString());
        return json.GetProperty("mfaToken").GetString()!;
    }

    /// <summary>
    /// Password login of an account without any factor: the emailed code is the second factor, and the session it yields
    /// is limited to factor enrollment.
    /// </summary>
    public async Task<Tokens> EnrollmentLoginAsync(string email, string clientKind = "web")
    {
        var response = await Client().PostAsJsonAsync("/api/v1/auth/login", new { email, password = Password, clientKind });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.JsonAsync();
        Assert.True(json.GetProperty("enrollment").GetBoolean());
        Assert.Equal(["email"], json.GetProperty("methods").EnumerateArray().Select(m => m.GetString()));
        var mfa = json.GetProperty("mfaToken").GetString()!;
        var code = await SendLoginEmailCodeAsync(mfa, email);
        var done = await Client().PostAsJsonAsync("/api/v1/auth/login/email", new { mfaToken = mfa, code });
        Assert.Equal(HttpStatusCode.OK, done.StatusCode);
        return TokensOf(await done.JsonAsync());
    }

    public async Task<Tokens> LoginAsync(string email, byte[] totpSecret)
    {
        var mfa = await PasswordStepAsync(email);
        var response = await Client().PostAsJsonAsync("/api/v1/auth/login/totp", new { mfaToken = mfa, totpCode = Code(totpSecret) });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return TokensOf(await response.JsonAsync());
    }

    /// <summary>Proves TOTP again on a full session and returns the single-use step-up token.</summary>
    public async Task<string> StepUpWithTotpAsync(string accessToken, byte[] totpSecret)
    {
        var response = await Client().WithBearer(accessToken).PostAsJsonAsync("/api/v1/auth/step-up",
            new { method = "totp", code = Code(totpSecret) });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.JsonAsync()).GetProperty("stepUpToken").GetString()!;
    }

    /// <summary>Registers, enables emailed sign-in codes as the only factor and refreshes into a full session.</summary>
    public async Task<Account> RegisterWithEmailOtpAsync(string? email = null)
    {
        email ??= $"mail-{Guid.NewGuid():N}@example.org";
        var limited = await RegisterAsync(email);
        await EnableEmailOtpAsync(limited.AccessToken, email);
        var refreshed = await Refresh(limited.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        return new Account(email, TokensOf(await refreshed.JsonAsync()), null);
    }

    public async Task EnableEmailOtpAsync(string accessToken, string email, string? stepUpToken = null)
    {
        var client = Client().WithBearer(accessToken);
        var enroll = await client.PostJsonAsync("/api/v1/auth/email-otp/enroll", stepUpToken is null ? null : new { stepUpToken });
        Assert.Equal(HttpStatusCode.NoContent, enroll.StatusCode);
        var verify = await client.PostAsJsonAsync("/api/v1/auth/email-otp/verify", new { code = app.Email.LastCode(email) });
        Assert.Equal(HttpStatusCode.NoContent, verify.StatusCode);
    }

    /// <summary>Asks for an emailed sign-in code for <paramref name="mfaToken"/> and returns it from the mailbox.</summary>
    public async Task<string> SendLoginEmailCodeAsync(string mfaToken, string email)
    {
        var send = await Client().PostAsJsonAsync("/api/v1/auth/login/email/send", new { mfaToken });
        Assert.Equal(HttpStatusCode.NoContent, send.StatusCode);
        return app.Email.LastCode(email);
    }

    public async Task<List<string>> BackupCodesAsync(string accessToken, string stepUpToken)
    {
        var response = await Client().WithBearer(accessToken).PostAsJsonAsync("/api/v1/auth/backup-codes", new { stepUpToken });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.JsonAsync()).GetProperty("codes").EnumerateArray().Select(c => c.GetString()!).ToList();
    }

    public Task<HttpResponseMessage> Refresh(string refreshToken) =>
        Client().PostAsJsonAsync("/api/v1/auth/refresh", new { refreshToken });

    public Task<HttpResponseMessage> MeAsync(string accessToken) => Client().WithBearer(accessToken).GetAsync("/api/v1/me");
}
