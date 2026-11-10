using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Nyxite.Domain.Identity;
using Nyxite.Persistence.Entities;

namespace Nyxite.Persistence.Configurations;

internal static class Converters
{
    public static readonly ValueConverter<UserRole, string> Role = new(v => DbValue.Of(v), s => DbValue.ParseRole(s));
    public static readonly ValueConverter<UserStatus, string> UserStatus = new(v => DbValue.Of(v), s => DbValue.ParseUserStatus(s));
    public static readonly ValueConverter<DeviceStatus, string> DeviceStatus = new(v => DbValue.Of(v), s => DbValue.ParseDeviceStatus(s));
    public static readonly ValueConverter<ActorKind, string> ActorKind = new(v => DbValue.Of(v), s => DbValue.ParseActorKind(s));
}

internal sealed class UserConfiguration : IEntityTypeConfiguration<UserEntity>
{
    public void Configure(EntityTypeBuilder<UserEntity> b)
    {
        b.ToTable("users", t =>
        {
            t.HasCheckConstraint("ck_users_role", "role IN ('user','admin')");
            t.HasCheckConstraint("ck_users_status", "status IN ('active','blocked')");
        });
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasColumnName("id").ValueGeneratedNever();
        b.Property(x => x.Email).HasColumnName("email");
        b.HasIndex(x => x.Email).IsUnique().HasDatabaseName("ux_users_email");
        b.Property(x => x.DisplayName).HasColumnName("display_name");
        b.Property(x => x.PasswordVerifier).HasColumnName("password_verifier");
        b.Property(x => x.PasswordPepperVersion).HasColumnName("password_pepper_version");
        b.Property(x => x.TotpSecretEnc).HasColumnName("totp_secret_enc");
        b.Property(x => x.TotpLastStep).HasColumnName("totp_last_step");
        b.Property(x => x.EmailVerifiedAt).HasColumnName("email_verified_at");
        b.Property(x => x.EmailOtpEnabledAt).HasColumnName("email_otp_enabled_at");
        b.Property(x => x.ExternalIdp).HasColumnName("external_idp");
        b.Property(x => x.ExternalIdpSub).HasColumnName("external_idp_sub");
        b.HasIndex(x => new { x.ExternalIdp, x.ExternalIdpSub }).IsUnique().HasDatabaseName("ux_users_external_idp");
        b.Property(x => x.Role).HasColumnName("role").HasConversion(Converters.Role).HasDefaultValueSql("'user'").HasSentinel(UserRole.User);
        b.Property(x => x.Status).HasColumnName("status").HasConversion(Converters.UserStatus).HasDefaultValueSql("'active'").HasSentinel(UserStatus.Active);
        b.Property(x => x.StorageQuotaBytes).HasColumnName("storage_quota_bytes");
        b.Property(x => x.SettingsEnc).HasColumnName("settings_enc");
        b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasDefaultValueSql("now()");
    }
}

internal sealed class UserKeyConfiguration : IEntityTypeConfiguration<UserKeyEntity>
{
    public void Configure(EntityTypeBuilder<UserKeyEntity> b)
    {
        b.ToTable("user_keys");
        b.HasKey(x => new { x.UserId, x.KeyId });
        b.Property(x => x.UserId).HasColumnName("user_id");
        b.Property(x => x.KeyId).HasColumnName("key_id");
        b.Property(x => x.PublicX25519).HasColumnName("public_x25519");
        b.Property(x => x.PublicEd25519).HasColumnName("public_ed25519");
        b.Property(x => x.AlgId).HasColumnName("alg_id");
        b.Property(x => x.Generation).HasColumnName("generation").HasDefaultValue(1);
        b.Property(x => x.SelfSig).HasColumnName("self_sig");
        b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        b.Property(x => x.RevokedAt).HasColumnName("revoked_at");
        b.HasOne<UserEntity>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Restrict);
        b.HasIndex(x => x.UserId).HasFilter("revoked_at IS NULL").HasDatabaseName("ix_user_keys_user_live");
    }
}

internal sealed class DeviceConfiguration : IEntityTypeConfiguration<DeviceEntity>
{
    public void Configure(EntityTypeBuilder<DeviceEntity> b)
    {
        b.ToTable("devices", t => t.HasCheckConstraint("ck_devices_status", "status IN ('pending','active','revoked')"));
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasColumnName("id").ValueGeneratedNever();
        b.Property(x => x.UserId).HasColumnName("user_id");
        b.Property(x => x.Label).HasColumnName("label");
        b.Property(x => x.Pubkey).HasColumnName("pubkey");
        b.Property(x => x.Status).HasColumnName("status").HasConversion(Converters.DeviceStatus).HasDefaultValueSql("'pending'").HasSentinel(DeviceStatus.Pending);
        b.Property(x => x.PendingKeyBlob).HasColumnName("pending_key_blob");
        b.Property(x => x.PairingCodeHash).HasColumnName("pairing_code_hash");
        b.Property(x => x.PairingExpiresAt).HasColumnName("pairing_expires_at");
        b.Property(x => x.PairingAttempts).HasColumnName("pairing_attempts").HasDefaultValue(0);
        b.Property(x => x.EnrolledAt).HasColumnName("enrolled_at").HasDefaultValueSql("now()");
        b.Property(x => x.RevokedAt).HasColumnName("revoked_at");
        b.HasOne<UserEntity>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Restrict);
        b.HasIndex(x => x.UserId).HasFilter("revoked_at IS NULL").HasDatabaseName("ix_devices_user_live");
    }
}

internal sealed class RecoveryBlobConfiguration : IEntityTypeConfiguration<RecoveryBlobEntity>
{
    public void Configure(EntityTypeBuilder<RecoveryBlobEntity> b)
    {
        b.ToTable("recovery_blobs");
        b.HasKey(x => x.UserId);
        b.Property(x => x.UserId).HasColumnName("user_id").ValueGeneratedNever();
        b.Property(x => x.Version).HasColumnName("version").HasDefaultValue(1);
        b.Property(x => x.Blob).HasColumnName("blob");
        b.Property(x => x.KdfParams).HasColumnName("kdf_params").HasColumnType("jsonb");
        b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasDefaultValueSql("now()");
        b.HasOne<UserEntity>().WithOne().HasForeignKey<RecoveryBlobEntity>(x => x.UserId).OnDelete(DeleteBehavior.Restrict);
    }
}

internal sealed class AuditLogConfiguration : IEntityTypeConfiguration<AuditLogEntity>
{
    public void Configure(EntityTypeBuilder<AuditLogEntity> b)
    {
        b.ToTable("audit_log");
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasColumnName("id").UseIdentityByDefaultColumn();
        b.Property(x => x.OccurredAt).HasColumnName("occurred_at").HasDefaultValueSql("now()");
        b.Property(x => x.ActorId).HasColumnName("actor_id");
        b.Property(x => x.ActorKind).HasColumnName("actor_kind").HasConversion(Converters.ActorKind);
        b.Property(x => x.Action).HasColumnName("action");
        b.Property(x => x.TargetType).HasColumnName("target_type");
        b.Property(x => x.TargetId).HasColumnName("target_id");
        b.Property(x => x.Detail).HasColumnName("detail").HasColumnType("jsonb").HasDefaultValueSql("'{}'::jsonb");
        b.Property(x => x.Ip).HasColumnName("ip").HasColumnType("inet");
        b.Property(x => x.UserAgent).HasColumnName("user_agent");
        b.HasIndex(x => x.OccurredAt).IsDescending().HasDatabaseName("ix_audit_time");
        // Actor plus time: the second-factor failure cap reads one account's recent events on every code attempt.
        b.HasIndex(x => new { x.ActorId, x.OccurredAt }).IsDescending(false, true).HasDatabaseName("ix_audit_actor");
        b.HasIndex(x => x.Action).HasDatabaseName("ix_audit_action");
    }
}
