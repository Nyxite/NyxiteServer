using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Nyxite.Application.Diagnostics;
using Nyxite.Persistence;

namespace Nyxite.Application.Maintenance;

/// <summary>Configuration section <c>Retention</c> (<c>NYXITE__Retention__*</c>, 14).</summary>
public sealed class RetentionOptions
{
    public const string Section = "Retention";

    /// <summary>How long revoked or expired <c>sessions</c> rows, and with them their refresh-token chain, are kept.</summary>
    public int SessionRetentionDays { get; set; } = 30;

    /// <summary>
    /// How long a deleted project, folder or file stays in Trash, where its owner can restore it (03 §3.3, DL-1).
    /// After that only an admin can bring it back, until it is purged.
    /// </summary>
    public int TrashWindowDays { get; set; } = 30;

    /// <summary>How often the maintenance job deletes expired rows.</summary>
    public TimeSpan CleanupInterval { get; set; } = TimeSpan.FromHours(1);
}

/// <summary>
/// The cleanup of 03 §3.2: deletes <c>ephemeral_tokens</c> and <c>idempotency_keys</c> past <c>expires_at</c>, and
/// sessions revoked or expired longer than the retention ago, whose refresh-token chain goes with them by cascade.
/// Nothing here is kept for audit, because the events are in <c>audit_log</c>.
/// </summary>
public sealed class ExpiredRowCleaner(NyxiteDbContext db, TimeProvider time, IOptions<RetentionOptions> options)
{
    public async Task<int> RunAsync(CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var sessionCutoff = now - TimeSpan.FromDays(options.Value.SessionRetentionDays);
        var tokens = await db.EphemeralTokens.Where(t => t.ExpiresAt <= now).ExecuteDeleteAsync(ct);
        var keys = await db.IdempotencyKeys.Where(k => k.ExpiresAt <= now).ExecuteDeleteAsync(ct);
        var sessions = await db.Sessions
            .Where(s => s.ExpiresAt <= sessionCutoff || (s.RevokedAt != null && s.RevokedAt <= sessionCutoff))
            .ExecuteDeleteAsync(ct);
        Count("ephemeral_tokens", tokens);
        Count("idempotency_keys", keys);
        Count("sessions", sessions);
        return tokens + keys + sessions;
    }

    private static void Count(string table, int rows)
    {
        if (rows > 0) NyxiteMetrics.RowsCleaned.Add(rows, new KeyValuePair<string, object?>("table", table));
    }
}

/// <summary>Runs <see cref="ExpiredRowCleaner"/> every <see cref="RetentionOptions.CleanupInterval"/>.</summary>
public sealed class MaintenanceWorker(
    IServiceScopeFactory scopes, TimeProvider time, IOptions<RetentionOptions> options, ILogger<MaintenanceWorker> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(options.Value.CleanupInterval, time, stoppingToken);
                await using var scope = scopes.CreateAsyncScope();
                var deleted = await scope.ServiceProvider.GetRequiredService<ExpiredRowCleaner>().RunAsync(stoppingToken);
                if (deleted > 0) logger.LogInformation("Maintenance deleted {Count} expired rows.", deleted);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception e)
            {
                logger.LogWarning(e, "The maintenance run failed.");
            }
        }
    }
}
