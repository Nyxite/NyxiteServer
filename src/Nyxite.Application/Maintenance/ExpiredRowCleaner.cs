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

    /// <summary>
    /// How long a deleted object stays restorable by an admin after its Trash window, before it is purged for good
    /// (03 §3.3, DL-4). Purge happens at Trash window plus grace window, about 60 days by default.
    /// </summary>
    public int GraceWindowDays { get; set; } = 30;

    /// <summary>How often the maintenance job deletes expired rows.</summary>
    public TimeSpan CleanupInterval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>How often purged content is removed and the blob store is swept for unreferenced ciphertext.</summary>
    public TimeSpan PurgeInterval { get; set; } = TimeSpan.FromHours(6);

    /// <summary>
    /// Minimum age of an unreferenced blob or staging file before the sweep deletes it, so an upload in flight is left
    /// alone. A day covers the slowest upload by far.
    /// </summary>
    public int OrphanBlobAgeHours { get; set; } = 24;

    /// <summary>
    /// How long <c>change_log</c> rows are kept (06 §6.3.2). A sync cursor older than this gets <c>410 cursor_expired</c>
    /// and the client runs the manifest again. A quarter, so a device that was offline that long still resumes by delta.
    /// </summary>
    public int ChangeLogDays { get; set; } = 90;
}

/// <summary>
/// The cleanup of 03 §3.2: deletes <c>ephemeral_tokens</c> and <c>idempotency_keys</c> past <c>expires_at</c>, and
/// sessions revoked or expired longer than the retention ago, whose refresh-token chain goes with them by cascade, and
/// staged rotation heads older than <see cref="RetentionOptions.OrphanBlobAgeHours"/> that no commit took.
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
        // A staged rotation head no commit took within the orphan age is abandoned; its blob is then an orphan. A stage a
        // commit holds locked right now is skipped, so the commit never turns a stage into a head whose blob is gone.
        var stageCutoff = now - TimeSpan.FromHours(options.Value.OrphanBlobAgeHours);
        var stages = await db.Database.ExecuteSqlAsync($"""
            DELETE FROM file_rotation_heads WHERE (file_id, key_id) IN (
                SELECT file_id, key_id FROM file_rotation_heads WHERE created_at <= {stageCutoff} FOR UPDATE SKIP LOCKED)
            """, ct);
        Count("ephemeral_tokens", tokens);
        Count("idempotency_keys", keys);
        Count("sessions", sessions);
        Count("file_rotation_heads", stages);
        return tokens + keys + sessions + stages;
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
                deleted += await scope.ServiceProvider.GetRequiredService<Content.CrdtLogPruner>().RunAsync(stoppingToken);
                deleted += await scope.ServiceProvider.GetRequiredService<Sync.ChangeLogPruner>().RunAsync(stoppingToken);
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

/// <summary>
/// Runs the purge of the deletion lifecycle and the blob garbage collection every <c>Retention:PurgeInterval</c>
/// (03 §3.3, 10 §10.6). Separate from <see cref="MaintenanceWorker"/>, because sweeping the blob store reads every
/// file name and is too heavy for the hourly row cleanup.
/// </summary>
public sealed class StorageCollectionWorker(
    IServiceScopeFactory scopes, TimeProvider time, IOptions<RetentionOptions> options, ILogger<StorageCollectionWorker> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(options.Value.PurgeInterval, time, stoppingToken);
                await using var scope = scopes.CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<Structure.TrashPurger>().RunAsync(stoppingToken);
                await scope.ServiceProvider.GetRequiredService<Structure.TrashPurger>().PurgeExcludedContentAsync(stoppingToken);
                await scope.ServiceProvider.GetRequiredService<Content.BlobCollector>().SweepAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception e)
            {
                logger.LogWarning(e, "The storage collection run failed.");
            }
        }
    }
}
