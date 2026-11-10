using System.Net;
using System.Net.Http.Json;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Auth;

/// <summary>Step-up for factor changes (08 §8.2): a fresh proof of an existing factor, as a single-use session-bound token.</summary>
public sealed class StepUpTests(PostgresFixture pg)
{
    private async Task<(NyxiteApp App, AuthDriver Auth)> StartAsync()
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        return (app, new AuthDriver(app));
    }

    public static async Task<string> StepUpWithPasskeyAsync(AuthDriver auth, string accessToken, VirtualAuthenticator authenticator)
    {
        var client = auth.Client().WithBearer(accessToken);
        var options = await (await client.PostAsync("/api/v1/auth/step-up/passkey/options", null)).JsonAsync();
        var response = await client.PostAsJsonAsync("/api/v1/auth/step-up", new { method = "passkey", credential = authenticator.Get(options) });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.JsonAsync()).GetProperty("stepUpToken").GetString()!;
    }

    private static Task<HttpResponseMessage> EnrollTotp(AuthDriver auth, string accessToken, string? stepUpToken) =>
        auth.Client().WithBearer(accessToken).PostJsonAsync("/api/v1/auth/totp/enroll", stepUpToken is null ? null : new { stepUpToken });

    [Theory]
    [InlineData("/api/v1/auth/totp/enroll")]
    [InlineData("/api/v1/auth/webauthn/register/options")]
    [InlineData("/api/v1/auth/email-otp/enroll")]
    [InlineData("/api/v1/auth/backup-codes")]
    public async Task Every_factor_change_on_an_enrolled_account_needs_a_step_up(string path)
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();

        foreach (var body in new object?[] { null, new { stepUpToken = "made-up" } })
        {
            var response = await auth.Client().WithBearer(account.Tokens.AccessToken).PostJsonAsync(path, body);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal("2fa_required", await response.ProblemCodeAsync());
        }
    }

    [Fact]
    public async Task Step_up_token_is_single_use()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var token = await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!);

        Assert.Equal(HttpStatusCode.OK, (await EnrollTotp(auth, account.Tokens.AccessToken, token)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await EnrollTotp(auth, account.Tokens.AccessToken, token)).StatusCode);
    }

    [Fact]
    public async Task Step_up_token_is_bound_to_its_session_and_expires()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var other = await auth.LoginAsync(account.Email, account.TotpSecret!);

        var foreign = await auth.StepUpWithTotpAsync(other.AccessToken, account.TotpSecret!);
        Assert.Equal(HttpStatusCode.Forbidden, (await EnrollTotp(auth, account.Tokens.AccessToken, foreign)).StatusCode);

        var token = await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!);
        app.Clock.Advance(TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(1));
        var fresh = AuthDriver.TokensOf(await (await auth.Refresh(account.Tokens.RefreshToken)).JsonAsync());
        Assert.Equal(HttpStatusCode.Forbidden, (await EnrollTotp(auth, fresh.AccessToken, token)).StatusCode);
    }

    [Fact]
    public async Task Wrong_or_replayed_factor_is_refused_and_audited()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var client = auth.Client().WithBearer(account.Tokens.AccessToken);

        var wrong = await client.PostAsJsonAsync("/api/v1/auth/step-up", new { method = "totp", code = auth.WrongCode(account.TotpSecret!) });
        Assert.Equal(HttpStatusCode.Forbidden, wrong.StatusCode);
        Assert.Equal("2fa_required", await wrong.ProblemCodeAsync());

        // The code that completed the enrollment was spent and cannot be reused for a step-up.
        var replay = await client.PostAsJsonAsync("/api/v1/auth/step-up", new { method = "totp", code = auth.CurrentCode(account.TotpSecret!) });
        Assert.Equal(HttpStatusCode.Forbidden, replay.StatusCode);
        Assert.Equal(2L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM audit_log WHERE action = 'auth.step_up_failed'"));

        var unknown = await client.PostAsJsonAsync("/api/v1/auth/step-up", new { method = "sms", code = "123456" });
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
    }

    [Fact]
    public async Task A_limited_session_cannot_step_up()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var limited = await auth.RegisterAsync("limited@example.org");
        var response = await auth.Client().WithBearer(limited.AccessToken).PostAsJsonAsync("/api/v1/auth/step-up", new { method = "totp", code = "123456" });
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("2fa_required", await response.ProblemCodeAsync());
    }

    [Fact]
    public async Task Step_up_by_email_only_for_accounts_that_use_email_codes()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var totpAccount = await auth.RegisterWithTotpAsync();
        Assert.Equal(HttpStatusCode.BadRequest,
            (await auth.Client().WithBearer(totpAccount.Tokens.AccessToken).PostAsync("/api/v1/auth/step-up/email", null)).StatusCode);

        var mail = await auth.RegisterWithEmailOtpAsync();
        var client = auth.Client().WithBearer(mail.Tokens.AccessToken);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/api/v1/auth/step-up/email", null)).StatusCode);
        var response = await client.PostAsJsonAsync("/api/v1/auth/step-up", new { method = "email", code = app.Email.LastCode(mail.Email) });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var token = (await response.JsonAsync()).GetProperty("stepUpToken").GetString();

        Assert.Equal(HttpStatusCode.OK, (await EnrollTotp(auth, mail.Tokens.AccessToken, token)).StatusCode);
    }

    [Fact]
    public async Task Step_up_with_a_backup_code_consumes_it()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var codes = await auth.BackupCodesAsync(account.Tokens.AccessToken,
            await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!));
        var client = auth.Client().WithBearer(account.Tokens.AccessToken);

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/v1/auth/step-up", new { method = "backup_code", code = codes[0] })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsJsonAsync("/api/v1/auth/step-up", new { method = "backup_code", code = codes[0] })).StatusCode);
    }

    [Fact]
    public async Task Step_up_with_a_passkey_accepts_only_the_callers_own_passkey()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        using var mine = new VirtualAuthenticator();
        var options = await (await auth.Client().WithBearer(account.Tokens.AccessToken).PostJsonAsync("/api/v1/auth/webauthn/register/options",
            new { stepUpToken = await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!) })).JsonAsync();
        Assert.Equal(HttpStatusCode.NoContent, (await auth.Client().WithBearer(account.Tokens.AccessToken)
            .PostAsJsonAsync("/api/v1/auth/webauthn/register", new { credential = mine.Create(options) })).StatusCode);

        Assert.NotEmpty(await StepUpWithPasskeyAsync(auth, account.Tokens.AccessToken, mine));

        // Someone else's passkey, signing this session's challenge, does not count.
        var stranger = await auth.RegisterWithTotpAsync();
        using var theirs = new VirtualAuthenticator();
        var theirOptions = await (await auth.Client().WithBearer(stranger.Tokens.AccessToken).PostJsonAsync("/api/v1/auth/webauthn/register/options",
            new { stepUpToken = await auth.StepUpWithTotpAsync(stranger.Tokens.AccessToken, stranger.TotpSecret!) })).JsonAsync();
        await auth.Client().WithBearer(stranger.Tokens.AccessToken).PostAsJsonAsync("/api/v1/auth/webauthn/register", new { credential = theirs.Create(theirOptions) });

        var client = auth.Client().WithBearer(account.Tokens.AccessToken);
        var challenge = await (await client.PostAsync("/api/v1/auth/step-up/passkey/options", null)).JsonAsync();
        var response = await client.PostAsJsonAsync("/api/v1/auth/step-up", new { method = "passkey", credential = theirs.Get(challenge) });
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
