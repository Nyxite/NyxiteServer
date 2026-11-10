using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Nyxite.Application.Audit;
using Nyxite.Application.Auth;
using Nyxite.Application.Email;
using Nyxite.Application.Keys;
using Nyxite.Application.Licensing;
using Nyxite.Application.Maintenance;

namespace Nyxite.Application;

public static class ServiceCollectionExtensions
{
    /// <summary>Registers the auth module. Secrets are parsed on first use, so a missing secret fails loudly at startup checks.</summary>
    public static IServiceCollection AddNyxiteAuth(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<AuthOptions>().Bind(configuration.GetSection(AuthOptions.Section));
        services.AddOptions<EmailOptions>().Bind(configuration.GetSection(EmailOptions.Section));
        services.TryAddSingleton<IEmailSender, SmtpEmailSender>();
        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<PasswordHasher>();
        services.AddSingleton<TotpSecretProtector>();
        services.AddSingleton<TotpCodes>();
        services.AddSingleton<OneTimeCodes>();
        services.AddSingleton<AccessTokenService>();
        services.AddSingleton<KeycloakOidcProvider>();
        services.AddSingleton<ExternalIdentityProviderResolver>();
        services.AddScoped<IEphemeralTokenStore, PostgresEphemeralTokenStore>();
        services.AddScoped<AuditWriter>();
        services.AddScoped<SessionService>();
        services.AddScoped<SecondFactors>();
        services.AddScoped<EmailCodes>();
        services.AddScoped<FactorChangeGuard>();
        services.AddScoped<EmailVerificationService>();
        services.AddScoped<NativeAuthService>();
        services.AddScoped<PasskeyService>();
        services.AddScoped<StepUpService>();
        services.AddScoped<AccountSecurityService>();
        services.AddScoped<IdempotencyStore>();
        services.AddScoped<KeyTransparencyLog>();
        services.AddScoped<DeviceGuard>();
        services.AddScoped<KeyDirectoryService>();
        services.AddScoped<DeviceService>();
        services.AddScoped<RecoveryService>();
        services.AddOptions<Structure.StructureOptions>().Bind(configuration.GetSection(Structure.StructureOptions.Section));
        services.AddScoped<Structure.StructureService>();
        services.AddOptions<Content.ContentOptions>().Bind(configuration.GetSection(Structure.StructureOptions.Section));
        services.AddOptions<Content.RelayOptions>().Bind(configuration.GetSection(Content.RelayOptions.Section));
        services.AddScoped<Content.ContentService>();
        services.AddScoped<Content.CrdtLogPruner>();
        services.AddScoped<Content.BlobCollector>();
        services.AddScoped<Structure.TrashPurger>();
        services.TryAddSingleton(LicenseKeys.Embedded);
        services.AddSingleton<IEntitlement, Entitlement>();
        services.AddOptions<RetentionOptions>().Bind(configuration.GetSection(RetentionOptions.Section));
        services.AddSingleton<EmailOutboxProtector>();
        services.AddSingleton<EmailOutboxSignal>();
        services.AddScoped<EmailOutbox>();
        services.AddScoped<EmailOutboxDispatcher>();
        services.AddScoped<ExpiredRowCleaner>();
        services.AddHostedService<UnverifiedAccountSweeper>();
        services.AddHostedService<EmailOutboxWorker>();
        services.AddHostedService<MaintenanceWorker>();
        services.AddHostedService<StorageCollectionWorker>();
        return services;
    }

    /// <summary>
    /// Fails fast at startup: the token-signing key, the password pepper and the mail relay are always required (14).
    /// Mail is required because no account can be verified, and so none can become usable, without it.
    /// </summary>
    public static void ValidateNyxiteAuthSecrets(this IServiceProvider services)
    {
        _ = services.GetRequiredService<AccessTokenService>();
        _ = services.GetRequiredService<PasswordHasher>();
        _ = services.GetRequiredService<IEmailSender>();
        _ = services.GetRequiredService<EmailOutboxProtector>();
        // Verifies the license token now, so its outcome is logged at startup. It never throws: a bad token is community.
        _ = services.GetRequiredService<IEntitlement>();
    }
}
