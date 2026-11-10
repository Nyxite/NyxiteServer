using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Nyxite.Persistence;

namespace Nyxite.Server.Http;

/// <summary>
/// <c>/health/live</c> and <c>/health/ready</c> (14 §14.5). Liveness runs no check: the process answering is the signal.
/// Readiness needs Postgres reachable and fully migrated and the blob store writable. The IdP check of P0.1-SRV-5 joins
/// once the enterprise sign-in exists.
/// </summary>
public static class Health
{
    private const string Ready = "ready";

    public static IServiceCollection AddNyxiteHealth(this IServiceCollection services)
    {
        services.AddHealthChecks()
            .AddCheck<DatabaseReadyCheck>("database", tags: [Ready])
            .AddCheck<BlobStoreReadyCheck>("blob-store", tags: [Ready]);
        return services;
    }

    public static IEndpointRouteBuilder MapNyxiteHealth(this IEndpointRouteBuilder app)
    {
        app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false });
        app.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = c => c.Tags.Contains(Ready) });
        return app;
    }

    private sealed class BlobStoreReadyCheck(Nyxite.BlobStore.IBlobStore blobs) : IHealthCheck
    {
        public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct)
        {
            try
            {
                await blobs.ProbeAsync(ct);
                return HealthCheckResult.Healthy();
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                // No exception text: the endpoint is public and an I/O error names paths.
                return HealthCheckResult.Unhealthy("Blob store is not writable.");
            }
        }
    }

    private sealed class DatabaseReadyCheck(IServiceScopeFactory scopes) : IHealthCheck
    {
        public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct)
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                var db = scope.ServiceProvider.GetRequiredService<NyxiteDbContext>();
                if (!await db.Database.CanConnectAsync(ct)) return HealthCheckResult.Unhealthy("Database unreachable.");
                var pending = (await db.Database.GetPendingMigrationsAsync(ct)).Count();
                return pending == 0 ? HealthCheckResult.Healthy() : HealthCheckResult.Unhealthy($"{pending} migrations pending.");
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                // No exception text: the endpoint is public and a connection error may name hosts or users.
                return HealthCheckResult.Unhealthy("Database check failed.");
            }
        }
    }
}
