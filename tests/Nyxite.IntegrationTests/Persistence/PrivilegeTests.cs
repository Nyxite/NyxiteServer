using Npgsql;
using Nyxite.IntegrationTests.Infrastructure;
using Nyxite.Server;

namespace Nyxite.IntegrationTests.Persistence;

/// <summary>P0.1-TC-9 and the migrate step: the app role cannot rewrite append-only tables (12 §12.3, 17 §17.6, 14 §14.4).</summary>
public sealed class PrivilegeTests(PostgresFixture pg)
{
    private static async Task<PostgresException?> TryAsync(string cs, string sql)
    {
        try
        {
            await Sql.ExecAsync(cs, sql);
            return null;
        }
        catch (PostgresException e)
        {
            return e;
        }
    }

    [Fact]
    public async Task Audit_log_and_kt_leaves_are_append_only_for_the_app_role()
    {
        await using var app = new NyxiteApp(await pg.CreateDatabaseAsync());
        var auth = new AuthDriver(app);
        var keys = new KeyDriver(auth);
        // A full flow as the app role: auth, device enrollment and a key publish all write audit and KT rows.
        await keys.AccountWithActiveDeviceAsync();
        var cs = app.ConnectionString;
        Assert.True(await Sql.ScalarAsync<long>(cs, "SELECT count(*) FROM audit_log") > 0);
        Assert.Equal(1L, await Sql.ScalarAsync<long>(cs, "SELECT count(*) FROM kt_leaves"));

        foreach (var sql in new[]
                 {
                     "UPDATE audit_log SET action = 'x'",
                     "DELETE FROM audit_log",
                     "TRUNCATE audit_log",
                     "UPDATE kt_leaves SET leaf_hash = '\\x00'",
                     "DELETE FROM kt_leaves",
                     "INSERT INTO \"__EFMigrationsHistory\" VALUES ('x', 'y')",
                     "ALTER TABLE audit_log DISABLE TRIGGER ALL",
                 })
        {
            var error = await TryAsync(cs, sql);
            Assert.True(error is not null, sql);
            Assert.True(error.SqlState is PostgresErrorCodes.InsufficientPrivilege or "42501", $"{sql}: {error.SqlState}");
        }

        Assert.Null(await TryAsync(cs, "INSERT INTO audit_log (actor_kind, action) VALUES ('system', 'test.insert')"));
        Assert.Null(await TryAsync(cs, "UPDATE users SET display_name = display_name"));
    }

    [Fact]
    public async Task Migrate_command_applies_every_migration_with_the_migration_connection()
    {
        var admin = await pg.CreateEmptyDatabaseAsync();
        Assert.Equal(2, await MigrateCommand.RunAsync([]));
        Assert.Equal(0, await MigrateCommand.RunAsync([$"--Database:MigrationConnectionString={admin}"]));
        Assert.Equal(0, await MigrateCommand.RunAsync([$"--Database:MigrationConnectionString={admin}"]));

        await using var app = new NyxiteApp(PostgresFixture.AppConnectionString(admin));
        await pg.CreateDatabaseAsync(); // makes sure the test login exists
        Assert.Equal(System.Net.HttpStatusCode.OK, (await app.CreateClient().GetAsync("/health/ready")).StatusCode);
    }
}
