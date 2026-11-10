using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Nyxite.Application.Auth;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Auth;

/// <summary>Email verification at registration (08 §8.1): proof of the address before any factor, purge when unverified.</summary>
public sealed class EmailVerificationTests(PostgresFixture pg)
{
    private async Task<(NyxiteApp App, AuthDriver Auth)> StartAsync()
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        return (app, new AuthDriver(app));
    }

    [Fact]
    public async Task Registration_emails_a_code_and_an_unverified_account_cannot_enroll_any_factor()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var tokens = await auth.RegisterAsync("new@example.org", verifyEmail: false);

        var mail = Assert.Single(app.Email.To("new@example.org"));
        Assert.Matches(@"\b\d{8}\b", mail.Body);
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT count(*) FROM users WHERE email_verified_at IS NOT NULL"));

        var client = auth.Client().WithBearer(tokens.AccessToken);
        foreach (var path in new[] { "/api/v1/auth/totp/enroll", "/api/v1/auth/webauthn/register/options", "/api/v1/auth/email-otp/enroll" })
        {
            var response = await client.PostAsync(path, null);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal("email_unverified", await response.ProblemCodeAsync());
        }
    }

    [Fact]
    public async Task Correct_code_verifies_and_unlocks_enrollment()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var tokens = await auth.RegisterAsync("ok@example.org", verifyEmail: false);

        await auth.VerifyEmailAsync(tokens.AccessToken, "ok@example.org");
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM users WHERE email_verified_at IS NOT NULL"));
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM audit_log WHERE action = 'auth.email_verified'"));

        await auth.EnrollTotpAsync(tokens.AccessToken);
        // Verifying again is a harmless no-op.
        var again = await auth.Client().WithBearer(tokens.AccessToken).PostAsJsonAsync("/api/v1/auth/email/verify", new { code = "00000000" });
        Assert.Equal(HttpStatusCode.NoContent, again.StatusCode);
    }

    [Fact]
    public async Task Wrong_code_is_400_audited_and_the_code_dies_at_the_attempt_cap()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var tokens = await auth.RegisterAsync("guess@example.org", verifyEmail: false);
        var client = auth.Client().WithBearer(tokens.AccessToken);
        var right = app.Email.LastCode("guess@example.org");
        var wrong = right == "11111111" ? "22222222" : "11111111";

        for (var i = 0; i < 5; i++)
        {
            var response = await client.PostAsJsonAsync("/api/v1/auth/email/verify", new { code = wrong });
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("validation_failed", await response.ProblemCodeAsync());
        }

        // The right code no longer helps once the cap is reached.
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/v1/auth/email/verify", new { code = right })).StatusCode);
        Assert.Equal(6L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM audit_log WHERE action = 'auth.email_verify_failed'"));
    }

    [Fact]
    public async Task Resend_replaces_the_code_and_is_a_no_op_once_verified()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var tokens = await auth.RegisterAsync("again@example.org", verifyEmail: false);
        var client = auth.Client().WithBearer(tokens.AccessToken);
        var first = app.Email.LastCode("again@example.org");

        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/api/v1/auth/email/verify/resend", null)).StatusCode);
        var second = app.Email.LastCode("again@example.org");
        if (first != second)
            Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/v1/auth/email/verify", new { code = first })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsJsonAsync("/api/v1/auth/email/verify", new { code = second })).StatusCode);

        var sent = app.Email.To("again@example.org").Count;
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/api/v1/auth/email/verify/resend", null)).StatusCode);
        Assert.Equal(sent, app.Email.To("again@example.org").Count);
    }

    [Fact]
    public async Task Code_is_stored_only_as_a_keyed_hash()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        await auth.RegisterAsync("hash@example.org", verifyEmail: false);
        var code = app.Email.LastCode("hash@example.org");

        var detail = await Sql.ScalarAsync<string>(app.ConnectionString, "SELECT detail::text FROM ephemeral_tokens WHERE kind = 'email_verify'");
        Assert.DoesNotContain(code, detail);
    }

    [Fact]
    public async Task Expired_unverified_account_is_purged_at_login_and_by_the_sweep()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        await auth.RegisterAsync("stale@example.org", verifyEmail: false);
        await auth.RegisterAsync("stale2@example.org", verifyEmail: false);
        var verified = await auth.RegisterWithTotpAsync("kept@example.org");

        // Within the lifetime the unverified account can still sign in (and verify) with its password.
        await auth.PasswordStepAsync("stale@example.org");

        app.Clock.Advance(TimeSpan.FromHours(24));
        var late = await auth.Client().PostAsJsonAsync("/api/v1/auth/login", new { email = "stale@example.org", password = AuthDriver.Password, clientKind = "web" });
        Assert.Equal(HttpStatusCode.Unauthorized, late.StatusCode);
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM users WHERE email = 'stale@example.org'"));

        await using (var scope = app.Services.CreateAsyncScope())
            Assert.Equal(1, await scope.ServiceProvider.GetRequiredService<EmailVerificationService>().PurgeExpiredAsync(null, CancellationToken.None));

        Assert.Equal(["kept@example.org"], await Sql.ListAsync<string>(app.ConnectionString, "SELECT email FROM users"));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT count(*) FROM sessions s LEFT JOIN users u ON u.id = s.user_id WHERE u.id IS NULL"));
        Assert.Equal(2L, await Sql.ScalarAsync<long>(app.ConnectionString,
            "SELECT count(*) FROM audit_log WHERE action = 'auth.unverified_account_purged' AND actor_kind = 'system'"));
        Assert.Equal(HttpStatusCode.OK, (await auth.Refresh(verified.Tokens.RefreshToken)).StatusCode);
    }

    [Fact]
    public async Task A_failing_mail_relay_does_not_fail_registration_and_the_outbox_retries()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        app.Email.FailNext = true;

        var tokens = await auth.RegisterAsync("relay@example.org", verifyEmail: false);
        Assert.Empty(app.Email.To("relay@example.org"));

        // The failed mail stays queued, encrypted, and goes out once its retry delay has passed.
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM email_outbox WHERE attempts = 1"));
        app.Clock.Advance(TimeSpan.FromSeconds(11));
        Assert.Single(app.Email.To("relay@example.org"));
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM email_outbox"));

        Assert.Equal(HttpStatusCode.NoContent,
            (await auth.Client().WithBearer(tokens.AccessToken).PostAsync("/api/v1/auth/email/verify/resend", null)).StatusCode);
        await auth.VerifyEmailAsync(tokens.AccessToken, "relay@example.org");
    }
}
