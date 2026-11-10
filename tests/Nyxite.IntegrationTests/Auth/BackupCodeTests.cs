using System.Net;
using System.Net.Http.Json;
using System.Text;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Auth;

/// <summary>Backup codes: single-use stand-ins for a lost factor (08 §8.1(a)).</summary>
public sealed class BackupCodeTests(PostgresFixture pg)
{
    private async Task<(NyxiteApp App, AuthDriver Auth)> StartAsync()
    {
        var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        return (app, new AuthDriver(app));
    }

    private static Task<HttpResponseMessage> LoginWithBackupCode(AuthDriver auth, string mfaToken, string code) =>
        auth.Client().PostAsJsonAsync("/api/v1/auth/login/backup-code", new { mfaToken, code });

    [Fact]
    public async Task Generated_codes_are_shown_once_stored_as_keyed_hashes_and_work_once()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var codes = await auth.BackupCodesAsync(account.Tokens.AccessToken,
            await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!));

        Assert.Equal(10, codes.Distinct().Count());
        Assert.All(codes, c => Assert.Matches("^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$", c));
        var stored = await Sql.ListAsync<byte[]>(app.ConnectionString, "SELECT code_hash FROM backup_codes");
        Assert.Equal(10, stored.Count);
        Assert.All(stored, h => Assert.All(codes, c => Assert.DoesNotContain(c.Replace("-", ""), Encoding.ASCII.GetString(h))));

        var methods = (await (await auth.Client().PostAsJsonAsync("/api/v1/auth/login",
            new { email = account.Email, password = AuthDriver.Password, clientKind = "web" })).JsonAsync()).GetProperty("methods");
        Assert.Equal(["totp", "backup_code"], methods.EnumerateArray().Select(m => m.GetString()));

        // Typed loosely: lower case, without the dash.
        var login = await LoginWithBackupCode(auth, await auth.PasswordStepAsync(account.Email), codes[0].Replace("-", "").ToLowerInvariant());
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.Equal(1L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM sessions WHERE auth_method = 'password_backup_code'"));
        Assert.Equal("9", await Sql.ScalarAsync<string>(app.ConnectionString,
            "SELECT detail->>'remaining' FROM audit_log WHERE action = 'auth.backup_code_used'"));

        Assert.Equal(HttpStatusCode.Unauthorized, (await LoginWithBackupCode(auth, await auth.PasswordStepAsync(account.Email), codes[0])).StatusCode);
    }

    [Fact]
    public async Task Regenerating_invalidates_the_old_set_and_revokes_the_other_sessions()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var account = await auth.RegisterWithTotpAsync();
        var old = await auth.BackupCodesAsync(account.Tokens.AccessToken,
            await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!));
        var other = await auth.LoginAsync(account.Email, account.TotpSecret!);

        var fresh = await auth.BackupCodesAsync(account.Tokens.AccessToken,
            await auth.StepUpWithTotpAsync(account.Tokens.AccessToken, account.TotpSecret!));

        Assert.Empty(old.Intersect(fresh));
        Assert.Equal(HttpStatusCode.Unauthorized, (await LoginWithBackupCode(auth, await auth.PasswordStepAsync(account.Email), old[1])).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await LoginWithBackupCode(auth, await auth.PasswordStepAsync(account.Email), fresh[1])).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await auth.Refresh(other.RefreshToken)).StatusCode);
    }

    [Fact]
    public async Task Generating_codes_needs_a_full_session_and_a_step_up()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        var limited = await auth.RegisterAsync("nofactor@example.org");
        var fromLimited = await auth.Client().WithBearer(limited.AccessToken).PostJsonAsync("/api/v1/auth/backup-codes", new { });
        Assert.Equal(HttpStatusCode.Forbidden, fromLimited.StatusCode);
        Assert.Equal("2fa_required", await fromLimited.ProblemCodeAsync());

        var account = await auth.RegisterWithTotpAsync();
        var bare = await auth.Client().WithBearer(account.Tokens.AccessToken).PostJsonAsync("/api/v1/auth/backup-codes", new { });
        Assert.Equal(HttpStatusCode.Forbidden, bare.StatusCode);
        Assert.Equal("2fa_required", await bare.ProblemCodeAsync());
        Assert.Equal(0L, await Sql.ScalarAsync<long>(app.ConnectionString, "SELECT count(*) FROM backup_codes"));
    }

    [Fact]
    public async Task A_passkey_only_account_with_backup_codes_can_sign_in_with_password_and_a_code()
    {
        var (app, auth) = await StartAsync();
        await using var _ = app;
        using var authenticator = new VirtualAuthenticator();
        var limited = await auth.RegisterAsync("pkonly@example.org");
        var client = auth.Client().WithBearer(limited.AccessToken);
        var options = await (await client.PostAsync("/api/v1/auth/webauthn/register/options", null)).JsonAsync();
        Assert.Equal(HttpStatusCode.NoContent,
            (await client.PostAsJsonAsync("/api/v1/auth/webauthn/register", new { credential = authenticator.Create(options) })).StatusCode);
        var full = AuthDriver.TokensOf(await (await auth.Refresh(limited.RefreshToken)).JsonAsync());

        // Without backup codes the password alone gets nothing.
        Assert.Equal(HttpStatusCode.Unauthorized, (await auth.Client().PostAsJsonAsync("/api/v1/auth/login",
            new { email = "pkonly@example.org", password = AuthDriver.Password, clientKind = "web" })).StatusCode);

        var stepUp = await StepUpTests.StepUpWithPasskeyAsync(auth, full.AccessToken, authenticator);
        var codes = await auth.BackupCodesAsync(full.AccessToken, stepUp);

        var mfa = await auth.PasswordStepAsync("pkonly@example.org");
        Assert.Equal(HttpStatusCode.OK, (await LoginWithBackupCode(auth, mfa, codes[0])).StatusCode);
    }
}
