using Npgsql;

namespace Nyxite.IntegrationTests.Infrastructure;

/// <summary>Small raw-SQL helpers for direct Postgres inspection (method-api-automated: "server inspection").</summary>
public static class Sql
{
    public static async Task<List<T>> ListAsync<T>(string cs, string sql, params (string Name, object Value)[] args)
    {
        await using var conn = new NpgsqlConnection(cs);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, conn);
        foreach (var (n, v) in args) cmd.Parameters.AddWithValue(n, v);
        var result = new List<T>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync()) result.Add(reader.GetFieldValue<T>(0));
        return result;
    }

    public static async Task<T?> ScalarAsync<T>(string cs, string sql, params (string Name, object Value)[] args) =>
        (await ListAsync<T>(cs, sql, args)).FirstOrDefault();

    public static async Task<int> ExecAsync(string cs, string sql, params (string Name, object Value)[] args)
    {
        await using var conn = new NpgsqlConnection(cs);
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(sql, conn);
        foreach (var (n, v) in args) cmd.Parameters.AddWithValue(n, v);
        return await cmd.ExecuteNonQueryAsync();
    }
}
