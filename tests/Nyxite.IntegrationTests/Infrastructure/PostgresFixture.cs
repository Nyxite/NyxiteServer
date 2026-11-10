using Microsoft.EntityFrameworkCore;
using Npgsql;
using Nyxite.Persistence;
using Testcontainers.PostgreSql;

[assembly: AssemblyFixture(typeof(Nyxite.IntegrationTests.Infrastructure.PostgresFixture))]

namespace Nyxite.IntegrationTests.Infrastructure;

/// <summary>
/// One PostgreSQL 17 container per test run (14 §14.8). Every test gets its own freshly migrated database via
/// <see cref="CreateDatabaseAsync"/>, so tests never share mutable state.
/// </summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    // Every test database keeps its own idle connection pool until the run ends, so the default of 100 connections
    // runs out once the suite passes about a hundred tests.
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:17-alpine")
        .WithCommand("-c", "max_connections=1000")
        .Build();

    public async ValueTask InitializeAsync() => await _container.StartAsync();

    public async ValueTask DisposeAsync() => await _container.DisposeAsync();

    /// <summary>Superuser connection string to the server's maintenance database.</summary>
    public string AdminConnectionString => _container.GetConnectionString();

    /// <summary>Creates an empty database and returns a superuser connection string to it.</summary>
    public async Task<string> CreateEmptyDatabaseAsync()
    {
        var name = "t_" + Guid.NewGuid().ToString("N");
        await using (var conn = new NpgsqlConnection(AdminConnectionString))
        {
            await conn.OpenAsync();
            await using var cmd = new NpgsqlCommand($"CREATE DATABASE \"{name}\"", conn);
            await cmd.ExecuteNonQueryAsync();
        }

        return new NpgsqlConnectionStringBuilder(AdminConnectionString) { Database = name }.ConnectionString;
    }

    /// <summary>Login role the server connects as in tests: a member of the app group role, like a production deploy.</summary>
    public const string AppLogin = "nyxite_app_test";

    private const string AppPassword = "app-test";

    /// <summary>
    /// Creates a database, applies every migration as the superuser (the migration role) and returns a connection string
    /// of <see cref="AppLogin"/>, so every test runs with the privileges of the real server.
    /// </summary>
    public async Task<string> CreateDatabaseAsync() => (await CreateDatabaseWithAdminAsync()).App;

    public async Task<(string App, string Admin)> CreateDatabaseWithAdminAsync()
    {
        var admin = await CreateEmptyDatabaseAsync();
        await using (var db = CreateContext(admin))
        {
            await db.Database.MigrateAsync();
        }

        await EnsureAppLoginAsync();
        return (AppConnectionString(admin), admin);
    }

    public static string AppConnectionString(string adminConnectionString) =>
        new NpgsqlConnectionStringBuilder(adminConnectionString) { Username = AppLogin, Password = AppPassword }.ConnectionString;

    /// <summary>Creates the cluster-wide test login once; parallel tests may race, so an existing role is fine.</summary>
    private async Task EnsureAppLoginAsync()
    {
        await using var conn = new NpgsqlConnection(AdminConnectionString);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand($"""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{AppLogin}') THEN
                    CREATE ROLE {AppLogin} LOGIN PASSWORD '{AppPassword}' IN ROLE {DatabaseRoles.App};
                END IF;
            EXCEPTION WHEN duplicate_object OR unique_violation THEN
                NULL;
            END
            $$;
            """, conn);
        await cmd.ExecuteNonQueryAsync();
    }

    public static NyxiteDbContext CreateContext(string connectionString) =>
        new(new DbContextOptionsBuilder<NyxiteDbContext>().UseNpgsql(connectionString).Options);
}
