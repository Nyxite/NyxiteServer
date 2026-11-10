using Microsoft.EntityFrameworkCore;
using Nyxite.Persistence;

namespace Nyxite.Server;

/// <summary>
/// <c>nyxite-server migrate</c> (14 §14.4): applies pending migrations as the migration role and exits. It runs as a
/// discrete deploy step from the same image as the server, so code and schema versions cannot diverge, and the server
/// itself never migrates at startup. It reads <c>NYXITE__Database__MigrationConnectionString</c> only and needs none of
/// the server's secrets.
/// </summary>
public static class MigrateCommand
{
    public const string Name = "migrate";

    public static async Task<int> RunAsync(string[] args, CancellationToken ct = default)
    {
        var configuration = new ConfigurationBuilder()
            .AddEnvironmentVariables(prefix: "NYXITE__")
            .AddCommandLine(args)
            .Build();
        var cs = configuration["Database:MigrationConnectionString"];
        if (string.IsNullOrWhiteSpace(cs))
        {
            await Console.Error.WriteLineAsync("NYXITE__Database__MigrationConnectionString is not configured.");
            return 2;
        }

        await using var db = new NyxiteDbContext(new DbContextOptionsBuilder<NyxiteDbContext>().UseNpgsql(cs).Options);
        var pending = (await db.Database.GetPendingMigrationsAsync(ct)).ToList();
        await db.Database.MigrateAsync(ct);
        Console.WriteLine(pending.Count == 0 ? "Database is up to date." : $"Applied {pending.Count} migration(s): {string.Join(", ", pending)}");
        return 0;
    }
}
