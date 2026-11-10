using Microsoft.EntityFrameworkCore;
using Npgsql;
using Nyxite.IntegrationTests.Infrastructure;

namespace Nyxite.IntegrationTests.Persistence;

/// <summary>
/// P0.1-SRV-2: the identity-subset schema applies cleanly and holds no plaintext name, search index or KEK column
/// (03 §3.2, 03 §3.3a; zero-knowledge leakage assertion surface 1).
/// </summary>
public sealed class SchemaTests(PostgresFixture pg)
{
    private const string ColumnsSql =
        "SELECT table_name || '.' || column_name FROM information_schema.columns WHERE table_schema = 'public'";

    [Fact]
    public async Task Migrations_ApplyCleanly_AndLeaveNothingPending()
    {
        var cs = await pg.CreateDatabaseAsync();
        await using var db = PostgresFixture.CreateContext(cs);

        Assert.Empty(await db.Database.GetPendingMigrationsAsync(TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("users")]
    [InlineData("user_keys")]
    [InlineData("devices")]
    [InlineData("recovery_blobs")]
    [InlineData("audit_log")]
    [InlineData("sessions")]
    [InlineData("refresh_tokens")]
    [InlineData("ephemeral_tokens")]
    [InlineData("webauthn_credentials")]
    [InlineData("idempotency_keys")]
    public async Task IdentityTable_Exists(string table)
    {
        var cs = await pg.CreateDatabaseAsync();

        var tables = await Sql.ListAsync<string>(cs, "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'");

        Assert.Contains(table, tables);
    }

    [Fact]
    public async Task Schema_HasNoPlaintextNameColumn()
    {
        var cs = await pg.CreateDatabaseAsync();

        var columns = await Sql.ListAsync<string>(cs, ColumnsSql);

        Assert.DoesNotContain(columns, c => c.EndsWith(".name", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Schema_HasNoSearchIndexOrKekColumnOrTable()
    {
        var cs = await pg.CreateDatabaseAsync();

        var columns = await Sql.ListAsync<string>(cs, ColumnsSql);

        Assert.DoesNotContain(columns, c => c.Contains("search_index", StringComparison.Ordinal));
        Assert.DoesNotContain(columns, c => c.Contains("kek", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(columns, c => c.Contains("wrapped_dek", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Schema_HasNoPrivateOrRecoveryKeyColumn()
    {
        var cs = await pg.CreateDatabaseAsync();

        var columns = await Sql.ListAsync<string>(cs, ColumnsSql);

        Assert.DoesNotContain(columns, c => c.Contains("private", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(columns, c => c.Contains("secret_key", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(columns, c => c == "recovery_blobs.recovery_key");
    }

    [Fact]
    public async Task Users_EmailIsUnique()
    {
        var cs = await pg.CreateDatabaseAsync();
        const string insert = "INSERT INTO users (id, email, display_name) VALUES (@id, 'a@example.org', 'A')";
        await Sql.ExecAsync(cs, insert, ("id", Guid.CreateVersion7()));

        await Assert.ThrowsAsync<PostgresException>(() => Sql.ExecAsync(cs, insert, ("id", Guid.CreateVersion7())));
    }

    [Theory]
    [InlineData("INSERT INTO users (id, email, display_name, role) VALUES (@id, 'r@example.org', 'R', 'root')")]
    [InlineData("INSERT INTO users (id, email, display_name, status) VALUES (@id, 's@example.org', 'S', 'gone')")]
    public async Task Users_CheckConstraints_RejectUnknownValues(string sql)
    {
        var cs = await pg.CreateDatabaseAsync();

        var ex = await Assert.ThrowsAsync<PostgresException>(() => Sql.ExecAsync(cs, sql, ("id", Guid.CreateVersion7())));

        Assert.Equal(PostgresErrorCodes.CheckViolation, ex.SqlState);
    }

    [Fact]
    public async Task Devices_StatusCheck_RejectsUnknownValue()
    {
        var cs = await pg.CreateDatabaseAsync();
        var user = Guid.CreateVersion7();
        await Sql.ExecAsync(cs, "INSERT INTO users (id, email, display_name) VALUES (@id, 'd@example.org', 'D')", ("id", user));

        var ex = await Assert.ThrowsAsync<PostgresException>(() => Sql.ExecAsync(cs,
            "INSERT INTO devices (id, user_id, pubkey, status) VALUES (@id, @u, '\\x01', 'lost')",
            ("id", Guid.CreateVersion7()), ("u", user)));

        Assert.Equal(PostgresErrorCodes.CheckViolation, ex.SqlState);
    }

    [Fact]
    public async Task Defaults_AreApplied_ForNewUserAndDevice()
    {
        var cs = await pg.CreateDatabaseAsync();
        var user = Guid.CreateVersion7();
        await Sql.ExecAsync(cs, "INSERT INTO users (id, email, display_name) VALUES (@id, 'x@example.org', 'X')", ("id", user));
        await Sql.ExecAsync(cs, "INSERT INTO devices (id, user_id, pubkey) VALUES (@id, @u, '\\x01')", ("id", Guid.CreateVersion7()), ("u", user));

        Assert.Equal("user", await Sql.ScalarAsync<string>(cs, "SELECT role FROM users"));
        Assert.Equal("active", await Sql.ScalarAsync<string>(cs, "SELECT status FROM users"));
        Assert.Equal("pending", await Sql.ScalarAsync<string>(cs, "SELECT status FROM devices"));
        Assert.Equal(0, await Sql.ScalarAsync<int>(cs, "SELECT pairing_attempts FROM devices"));
    }

    [Fact]
    public async Task LiveDeviceIndex_IsPartialOnRevokedAt()
    {
        var cs = await pg.CreateDatabaseAsync();

        var def = await Sql.ScalarAsync<string>(cs, "SELECT indexdef FROM pg_indexes WHERE indexname = 'ix_devices_user_live'");

        Assert.Contains("WHERE (revoked_at IS NULL)", def);
    }

    [Fact]
    public async Task UserKeys_RequireExistingUser()
    {
        var cs = await pg.CreateDatabaseAsync();

        var ex = await Assert.ThrowsAsync<PostgresException>(() => Sql.ExecAsync(cs,
            "INSERT INTO user_keys (user_id, key_id, public_x25519, public_ed25519, alg_id, self_sig) VALUES (@u, @k, '\\x01', '\\x01', 'a', '\\x01')",
            ("u", Guid.CreateVersion7()), ("k", Guid.CreateVersion7())));

        Assert.Equal(PostgresErrorCodes.ForeignKeyViolation, ex.SqlState);
    }
}
