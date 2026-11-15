using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Nyxite.Persistence.Entities;

namespace Nyxite.Persistence;

/// <summary>
/// The server's EF Core context (03). It maps only server-visible data: structure, ACLs, wrapped keys, public keys,
/// opaque blobs and audit metadata. There is no plaintext name, search index or KEK column anywhere.
/// </summary>
public sealed class NyxiteDbContext(DbContextOptions<NyxiteDbContext> options) : DbContext(options)
{
    public DbSet<UserEntity> Users => Set<UserEntity>();
    public DbSet<UserKeyEntity> UserKeys => Set<UserKeyEntity>();
    public DbSet<DeviceEntity> Devices => Set<DeviceEntity>();
    public DbSet<RecoveryBlobEntity> RecoveryBlobs => Set<RecoveryBlobEntity>();
    public DbSet<AuditLogEntity> AuditLog => Set<AuditLogEntity>();
    public DbSet<SessionEntity> Sessions => Set<SessionEntity>();
    public DbSet<RefreshTokenEntity> RefreshTokens => Set<RefreshTokenEntity>();
    public DbSet<EphemeralTokenEntity> EphemeralTokens => Set<EphemeralTokenEntity>();
    public DbSet<WebAuthnCredentialEntity> WebAuthnCredentials => Set<WebAuthnCredentialEntity>();
    public DbSet<BackupCodeEntity> BackupCodes => Set<BackupCodeEntity>();
    public DbSet<IdempotencyKeyEntity> IdempotencyKeys => Set<IdempotencyKeyEntity>();
    public DbSet<EmailOutboxEntity> EmailOutbox => Set<EmailOutboxEntity>();
    public DbSet<KtLeafEntity> KtLeaves => Set<KtLeafEntity>();
    public DbSet<KtStateEntity> KtState => Set<KtStateEntity>();
    public DbSet<ProjectEntity> Projects => Set<ProjectEntity>();
    public DbSet<FolderEntity> Folders => Set<FolderEntity>();
    public DbSet<FileEntity> Files => Set<FileEntity>();
    public DbSet<FileKeyEntity> FileKeys => Set<FileKeyEntity>();
    public DbSet<StructureKeyEntity> StructureKeys => Set<StructureKeyEntity>();
    public DbSet<FileVersionEntity> FileVersions => Set<FileVersionEntity>();
    public DbSet<CrdtUpdateEntity> CrdtUpdates => Set<CrdtUpdateEntity>();
    public DbSet<ChangeLogEntity> ChangeLog => Set<ChangeLogEntity>();
    public DbSet<FileRotationHeadEntity> FileRotationHeads => Set<FileRotationHeadEntity>();
    public DbSet<ShareEntity> Shares => Set<ShareEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder) =>
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(NyxiteDbContext).Assembly);
}

/// <summary>Design-time factory for <c>dotnet ef</c>; the connection string is never used to connect.</summary>
public sealed class NyxiteDbContextDesignTimeFactory : IDesignTimeDbContextFactory<NyxiteDbContext>
{
    public NyxiteDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<NyxiteDbContext>()
            .UseNpgsql(Environment.GetEnvironmentVariable("NYXITE__Database__ConnectionString") ?? "Host=localhost;Database=nyxite_design")
            .Options);
}
