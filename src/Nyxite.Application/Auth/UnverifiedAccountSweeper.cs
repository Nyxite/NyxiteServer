using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Nyxite.Application.Auth;

/// <summary>Background job that purges accounts left unverified past their lifetime (08 §8.1, 14).</summary>
public sealed class UnverifiedAccountSweeper(
    IServiceScopeFactory scopes, TimeProvider time, IOptions<AuthOptions> options, ILogger<UnverifiedAccountSweeper> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(options.Value.UnverifiedAccountSweepInterval, time, stoppingToken);
                await using var scope = scopes.CreateAsyncScope();
                var purged = await scope.ServiceProvider.GetRequiredService<EmailVerificationService>().PurgeExpiredAsync(null, stoppingToken);
                if (purged > 0) logger.LogInformation("Purged {Count} unverified accounts.", purged);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception e)
            {
                // A failed sweep is retried at the next interval; the purge at registration covers the gap meanwhile.
                logger.LogWarning(e, "Purging unverified accounts failed.");
            }
        }
    }
}
