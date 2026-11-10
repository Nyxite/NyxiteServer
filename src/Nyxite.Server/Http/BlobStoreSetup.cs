using Nyxite.BlobStore;

namespace Nyxite.Server.Http;

/// <summary>
/// Registers the ciphertext store from <c>NYXITE__BlobStore__Provider</c> and <c>__RootPath</c> (14 §14.3). The store is
/// required: the server refuses to start without a writable one (14 §14.4), because every file version lives in it.
/// </summary>
public static class BlobStoreSetup
{
    public static IServiceCollection AddNyxiteBlobStore(this IServiceCollection services)
    {
        services.AddSingleton<IBlobStore>(sp =>
        {
            var configuration = sp.GetRequiredService<IConfiguration>();
            var provider = configuration["BlobStore:Provider"] ?? "filesystem";
            if (provider != "filesystem") throw new InvalidOperationException($"BlobStore:Provider '{provider}' is not supported yet; use 'filesystem'.");
            var root = configuration["BlobStore:RootPath"];
            return string.IsNullOrWhiteSpace(root)
                ? throw new InvalidOperationException("BlobStore:RootPath is not configured.")
                : new FilesystemBlobStore(root);
        });
        return services;
    }

    /// <summary>Fails fast at startup when the store cannot be written.</summary>
    public static void ValidateNyxiteBlobStore(this IServiceProvider services) =>
        services.GetRequiredService<IBlobStore>().ProbeAsync(CancellationToken.None).GetAwaiter().GetResult();
}
