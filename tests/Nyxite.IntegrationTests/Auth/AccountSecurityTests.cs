using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Auth;

/// <summary>Own sign-in methods, sessions and the password: overview, removal, change, forgot and reset (08 §8.1, §8.7).</summary>
public sealed class AccountSecurityTests(PostgresFixture pg)
{
    private async Task<(NyxiteApp App, AuthDriver Auth)> StartAsync(IDictionary<string, string?>? overrides = null)
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync(), overrides: overrides);
        return (app, new AuthDriver(app));
    }

    private static Task<HttpResponseMessage> Delete(AuthDriver auth, string accessToken, string path, string? stepUp)
    {
        var request = new HttpRequestMessage(HttpMethod.Delete, path);
        if (stepUp is not null) request.Headers.Add("Nyxite-Step-Up", stepUp);
        return auth.Client().WithBearer(accessToken).SendAsync(request);
    }

    private static async Task<Guid> AddPasskeyAsync(AuthDriver auth, AuthDriver.Account account, VirtualAuthenticator authenticator)
    {
        var client = auth.Client().WithBearer(account.Tokens.AccessToken);
        var options = await (await client.PostJsonAsync("/api/v1/auth/webauthn/register/options",
            new { stepUpToken = await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!) })).JsonAsync();
        Assert.Equal(HttpStatusCode.NoContent,
            (await client.PostAsJsonAsync("/api/v1/auth/webauthn/register", new { credential = authenticator.Create(options), label = "laptop" })).StatusCode);
        var list = await (await client.GetAsync("/api/v1/auth/passkeys")).JsonAsync();
        return list.EnumerateArray().Last().GetProperty("id").GetGuid();
    }

    private static string ResetToken(NyxiteApp app, string email) =>
        Regex.Match(app.Email.To(email).Last().Body, "[A-Za-z0-9_-]{43}").Value;

    [Fact]
    public async Task Factor_overview_follows_the_account()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var limited = await auth.RegisterAsync("overview@example.org", verifyEmail: false);
        var before = await (await auth.Client().WithBearer(limited.AccessToken).GetAsync("/api/v1/auth/factors")).JsonAsync();
        Assert.False(before.GetProperty("emailVerified").GetBoolean());
        Assert.False(before.GetProperty("totp").GetBoolean());

        var account = await auth.RegisterWithTotpAsync();
        await auth.BackupCodesAsync(account.Tokens.AccessToken, await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!));
        var after = await (await auth.Client().WithBearer(account.Tokens.AccessToken).GetAsync("/api/v1/auth/factors")).JsonAsync();
        Assert.True(after.GetProperty("emailVerified").GetBoolean());
        Assert.True(after.GetProperty("totp").GetBoolean());
        Assert.False(after.GetProperty("emailOtp").GetBoolean());
        Assert.Equal(0, after.GetProperty("passkeys").GetInt32());
        Assert.Equal(10, after.GetProperty("backupCodesRemaining").GetInt32());
        Assert.True(after.GetProperty("passwordResetByEmail").GetBoolean());
    }

    [Fact]
    public async Task The_last_factor_cannot_be_removed_and_another_can_with_a_step_up()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();

        var last = await Delete(auth, account.Tokens.AccessToken, "/api/v1/auth/totp", await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!));
        Assert.Equal(HttpStatusCode.Conflict, last.StatusCode);

        using var authenticator = new VirtualAuthenticator();
        await AddPasskeyAsync(auth, account, authenticator);
        Assert.Equal(HttpStatusCode.Forbidden, (await Delete(auth, account.Tokens.AccessToken, "/api/v1/auth/totp", null)).StatusCode);
        var removed = await Delete(auth, account.Tokens.AccessToken, "/api/v1/auth/totp",
            await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!));
        Assert.Equal(HttpStatusCode.NoContent, removed.StatusCode);
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM users WHERE totp_secret_enc IS NOT NULL OR totp_last_step IS NOT NULL"));

        // Now passkey-only: removing TOTP again is 404, the password alone signs nothing in.
        var stepUp = await StepUpTests.StepUpWithPasskeyAsync(auth, account.Tokens.AccessToken, authenticator);
        Assert.Equal(HttpStatusCode.NotFound, (await Delete(auth, account.Tokens.AccessToken, "/api/v1/auth/totp", stepUp)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await auth.Client().PostAsJsonAsync("/api/v1/auth/login",
            new { email = account.Email, password = AuthDriver.Password, clientKind = "web" })).StatusCode);
    }

    [Fact]
    public async Task Turning_email_codes_off_restores_password_reset_by_email()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        await auth.EnableEmailOtpAsync(account.Tokens.AccessToken, account.Email,
            await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!));
        var client = auth.Client().WithBearer(account.Tokens.AccessToken);
        Assert.False((await (await client.GetAsync("/api/v1/auth/factors")).JsonAsync()).GetProperty("passwordResetByEmail").GetBoolean());

        var off = await Delete(auth, account.Tokens.AccessToken, "/api/v1/auth/email-otp",
            await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!));
        Assert.Equal(HttpStatusCode.NoContent, off.StatusCode);
        Assert.True((await (await client.GetAsync("/api/v1/auth/factors")).JsonAsync()).GetProperty("passwordResetByEmail").GetBoolean());
    }

    [Fact]
    public async Task Passkeys_are_listed_and_removed_only_by_their_owner()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        using var authenticator = new VirtualAuthenticator();
        var id = await AddPasskeyAsync(auth, account, authenticator);

        var list = await (await auth.Client().WithBearer(account.Tokens.AccessToken).GetAsync("/api/v1/auth/passkeys")).JsonAsync();
        var entry = Assert.Single(list.EnumerateArray());
        Assert.Equal("laptop", entry.GetProperty("label").GetString());
        Assert.False(entry.TryGetProperty("publicKey", out var _));

        var stranger = await auth.RegisterWithTotpAsync();
        var foreign = await Delete(auth, stranger.Tokens.AccessToken, $"/api/v1/auth/passkeys/{id}",
            await auth.StepUpWithTotpAsync(stranger.Tokens.AccessToken, stranger.TotpSecret!));
        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);

        var own = await Delete(auth, account.Tokens.AccessToken, $"/api/v1/auth/passkeys/{id}",
            await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!));
        Assert.Equal(HttpStatusCode.NoContent, own.StatusCode);
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM webauthn_credentials"));
    }

    [Fact]
    public async Task Own_sessions_are_listed_and_one_can_be_signed_out()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var other = await auth.LoginAsync(account.Email, account.TotpSecret!);
        var client = auth.Client().WithBearer(account.Tokens.AccessToken);

        var sessions = (await (await client.GetAsync("/api/v1/auth/sessions")).JsonAsync()).EnumerateArray().ToList();
        Assert.Equal(2, sessions.Count);
        Assert.Single(sessions, s => s.GetProperty("current").GetBoolean());
        var otherId = sessions.Single(s => !s.GetProperty("current").GetBoolean()).GetProperty("id").GetGuid();
        Assert.Equal("web", sessions.Single(s => s.GetProperty("id").GetGuid() == otherId).GetProperty("clientKind").GetString());

        var stranger = await auth.RegisterWithTotpAsync();
        Assert.Equal(HttpStatusCode.NotFound, (await Delete(auth, stranger.Tokens.AccessToken, $"/api/v1/auth/sessions/{otherId}", null)).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await Delete(auth, account.Tokens.AccessToken, $"/api/v1/auth/sessions/{otherId}", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await auth.Refresh(other.RefreshToken)).StatusCode);
        Assert.Single((await (await client.GetAsync("/api/v1/auth/sessions")).JsonAsync()).EnumerateArray());
    }

    [Fact]
    public async Task Password_change_needs_the_current_password_and_a_step_up_and_revokes_the_other_sessions()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var other = await auth.LoginAsync(account.Email, account.TotpSecret!);
        var client = auth.Client().WithBearer(account.Tokens.AccessToken);
        const string newPassword = "a completely new passphrase";

        var noStepUp = await client.PostAsJsonAsync("/api/v1/auth/password/change", new { currentPassword = AuthDriver.Password, newPassword });
        Assert.Equal(HttpStatusCode.Forbidden, noStepUp.StatusCode);

        var wrongCurrent = await client.PostAsJsonAsync("/api/v1/auth/password/change", new
        {
            currentPassword = "not the password", newPassword,
            stepUpToken = await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!),
        });
        Assert.Equal(HttpStatusCode.BadRequest, wrongCurrent.StatusCode);

        var changed = await client.PostAsJsonAsync("/api/v1/auth/password/change", new
        {
            currentPassword = AuthDriver.Password, newPassword,
            stepUpToken = await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!),
        });
        Assert.Equal(HttpStatusCode.NoContent, changed.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await auth.Refresh(other.RefreshToken)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await auth.Refresh(account.Tokens.RefreshToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await auth.Client().PostAsJsonAsync("/api/v1/auth/login",
            new { email = account.Email, password = AuthDriver.Password, clientKind = "web" })).StatusCode);
        await auth.PasswordStepAsync(account.Email, newPassword);
    }

    [Fact]
    public async Task Forgot_always_answers_202_and_mails_only_an_account_that_may_be_reset()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var normal = await auth.RegisterWithTotpAsync();
        var mail = await auth.RegisterWithEmailOtpAsync();
        await app.FlushOutboxAsync();
        var sentBefore = app.Email.Sent.Count;

        foreach (var email in new[] { "nobody@example.org", mail.Email, "not an email" })
            Assert.Equal(HttpStatusCode.Accepted, (await auth.Client().PostAsJsonAsync("/api/v1/auth/password/forgot", new { email })).StatusCode);
        await app.FlushOutboxAsync();
        Assert.Equal(sentBefore, app.Email.Sent.Count);
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM audit_log WHERE action = 'auth.password_reset_refused'"));

        Assert.Equal(HttpStatusCode.Accepted, (await auth.Client().PostAsJsonAsync("/api/v1/auth/password/forgot", new { email = normal.Email.ToUpperInvariant() })).StatusCode);
        await app.FlushOutboxAsync();
        Assert.Equal(sentBefore + 1, app.Email.Sent.Count);
        var token = ResetToken(app, normal.Email);
        Assert.Equal(43, token.Length);
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT count(*) FROM ephemeral_tokens WHERE kind = 'password_reset' AND position(@t::bytea in token_hash) > 0", ("t", token)));
    }

    [Fact]
    public async Task Reset_sets_the_password_revokes_every_session_keeps_the_second_factor_and_works_once()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        await auth.Client().PostAsJsonAsync("/api/v1/auth/password/forgot", new { email = account.Email });
        var token = ResetToken(app, account.Email);
        const string newPassword = "the reset passphrase";

        var tooShort = await auth.Client().PostAsJsonAsync("/api/v1/auth/password/reset", new { resetToken = token, newPassword = "short" });
        Assert.Equal(HttpStatusCode.BadRequest, tooShort.StatusCode);

        Assert.Equal(HttpStatusCode.NoContent,
            (await auth.Client().PostAsJsonAsync("/api/v1/auth/password/reset", new { resetToken = token, newPassword })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await auth.Refresh(account.Tokens.RefreshToken)).StatusCode);
        var again = await auth.Client().PostAsJsonAsync("/api/v1/auth/password/reset", new { resetToken = token, newPassword });
        Assert.Equal(HttpStatusCode.Gone, again.StatusCode);
        Assert.Equal("link_expired", await again.ProblemCodeAsync());

        // The reset restores the password only: the login still asks for TOTP.
        var methods = (await (await auth.Client().PostAsJsonAsync("/api/v1/auth/login",
            new { email = account.Email, password = newPassword, clientKind = "web" })).JsonAsync()).GetProperty("methods");
        Assert.Equal(["totp"], methods.EnumerateArray().Select(m => m.GetString()));
    }

    [Fact]
    public async Task Reset_token_expires_and_dies_when_email_codes_are_enabled_meanwhile()
    {
        var (app, auth) = await StartAsync(new Dictionary<string, string?> { ["Auth:PasswordResetUrl"] = "https://notes.example.org/reset?token={token}" });
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();

        await auth.Client().PostAsJsonAsync("/api/v1/auth/password/forgot", new { email = account.Email });
        Assert.Contains("https://notes.example.org/reset?token=", app.Email.To(account.Email).Last().Body);
        var expiring = ResetToken(app, account.Email);
        app.Clock.Advance(TimeSpan.FromMinutes(31));
        Assert.Equal(HttpStatusCode.Gone, (await auth.Client().PostAsJsonAsync("/api/v1/auth/password/reset",
            new { resetToken = expiring, newPassword = "a fresh passphrase!" })).StatusCode);

        var fresh = AuthDriver.TokensOf(await (await auth.Refresh(account.Tokens.RefreshToken)).JsonAsync());
        await auth.Client().PostAsJsonAsync("/api/v1/auth/password/forgot", new { email = account.Email });
        var pending = ResetToken(app, account.Email);
        await auth.EnableEmailOtpAsync(fresh.AccessToken, account.Email, await auth.StepUpWithTotpAsync(fresh.AccessToken, account.TotpSecret!));
        Assert.Equal(HttpStatusCode.Gone, (await auth.Client().PostAsJsonAsync("/api/v1/auth/password/reset",
            new { resetToken = pending, newPassword = "a fresh passphrase!" })).StatusCode);
    }
}
