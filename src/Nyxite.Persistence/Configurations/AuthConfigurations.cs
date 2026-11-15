using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Nyxite.Domain.Identity;
using Nyxite.Persistence.Entities;

namespace Nyxite.Persistence.Configurations;

internal static class AuthConverters
{
    public static readonly ValueConverter<ClientKind, string> ClientKind = new(v => AuthDbValue.Of(v), s => AuthDbValue.ParseClientKind(s));
    public static readonly ValueConverter<AuthMethod, string> AuthMethod = new(v => AuthDbValue.Of(v), s => AuthDbValue.ParseAuthMethod(s));
    public static readonly ValueConverter<RevokeReason, string> RevokeReason = new(v => AuthDbValue.Of(v), s => AuthDbValue.ParseRevokeReason(s));
    public static readonly ValueConverter<EphemeralTokenKind, string> EphemeralKind = new(v => AuthDbValue.Of(v), s => AuthDbValue.ParseEphemeralTokenKind(s));
}

internal sealed class SessionConfiguration : IEntityTypeConfiguration<SessionEntity>
{
    public void Configure(EntityTypeBuilder<SessionEntity> b)
    {
        b.ToTable("sessions", t =>
        {
            t.HasCheckConstraint("ck_sessions_client_kind", "client_kind IN ('desktop','android','web','admin')");
            t.HasCheckConstraint("ck_sessions_auth_method",
                "auth_method IN ('password_totp','passkey','oidc','password_email','password_backup_code')");
            t.HasCheckConstraint("ck_sessions_revoke_reason",
                "revoke_reason IN ('logout','admin','device_revoked','user_blocked','credential_change','reuse_detected')");
        });
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasColumnName("id").ValueGeneratedNever();
        b.Property(x => x.UserId).HasColumnName("user_id");
        b.Property(x => x.DeviceId).HasColumnName("device_id");
        b.Property(x => x.ClientKind).HasColumnName("client_kind").HasConversion(AuthConverters.ClientKind);
        b.Property(x => x.AuthMethod).HasColumnName("auth_method").HasConversion(AuthConverters.AuthMethod);
        b.Property(x => x.MfaVerifiedAt).HasColumnName("mfa_verified_at");
        b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        b.Property(x => x.LastSeenAt).HasColumnName("last_seen_at").HasDefaultValueSql("now()");
        b.Property(x => x.ExpiresAt).HasColumnName("expires_at");
        b.Property(x => x.LastIp).HasColumnName("last_ip").HasColumnType("inet");
        b.Property(x => x.UserAgent).HasColumnName("user_agent");
        b.Property(x => x.RevokedAt).HasColumnName("revoked_at");
        b.Property(x => x.RevokeReason).HasColumnName("revoke_reason").HasConversion(AuthConverters.RevokeReason);
        b.HasOne<UserEntity>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<DeviceEntity>().WithMany().HasForeignKey(x => x.DeviceId).OnDelete(DeleteBehavior.Restrict);
        b.HasIndex(x => x.UserId).HasFilter("revoked_at IS NULL").HasDatabaseName("ix_sessions_user_active");
        b.HasIndex(x => x.DeviceId).HasFilter("revoked_at IS NULL").HasDatabaseName("ix_sessions_device");
    }
}

internal sealed class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshTokenEntity>
{
    public void Configure(EntityTypeBuilder<RefreshTokenEntity> b)
    {
        b.ToTable("refresh_tokens");
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasColumnName("id").ValueGeneratedNever();
        b.Property(x => x.SessionId).HasColumnName("session_id");
        b.Property(x => x.ParentId).HasColumnName("parent_id");
        b.Property(x => x.TokenHash).HasColumnName("token_hash");
        b.HasIndex(x => x.TokenHash).IsUnique().HasDatabaseName("ux_refresh_token_hash");
        b.Property(x => x.IssuedAt).HasColumnName("issued_at").HasDefaultValueSql("now()");
        b.Property(x => x.ExpiresAt).HasColumnName("expires_at");
        b.Property(x => x.UsedAt).HasColumnName("used_at");
        b.HasOne<SessionEntity>().WithMany().HasForeignKey(x => x.SessionId).OnDelete(DeleteBehavior.Cascade);
        b.HasOne<RefreshTokenEntity>().WithMany().HasForeignKey(x => x.ParentId).OnDelete(DeleteBehavior.Cascade);
        b.HasIndex(x => x.ParentId).IsUnique().HasFilter("parent_id IS NOT NULL").HasDatabaseName("ux_refresh_parent");
        b.HasIndex(x => x.SessionId).HasDatabaseName("ix_refresh_session");
    }
}

internal sealed class EphemeralTokenConfiguration : IEntityTypeConfiguration<EphemeralTokenEntity>
{
    public void Configure(EntityTypeBuilder<EphemeralTokenEntity> b)
    {
        b.ToTable("ephemeral_tokens", t =>
        {
            t.HasCheckConstraint("ck_ephemeral_kind",
                "kind IN ('mfa','socket_ticket','password_reset','invite','oidc_state','oidc_handoff','webauthn_challenge','totp_enroll'," +
                "'email_verify','email_code','step_up','guest_socket_ticket')");
            t.HasCheckConstraint("ck_ephemeral_user", "user_id IS NOT NULL OR kind IN ('oidc_state','webauthn_challenge','guest_socket_ticket')");
        });
        b.HasKey(x => x.TokenHash);
        b.Property(x => x.TokenHash).HasColumnName("token_hash");
        b.Property(x => x.Kind).HasColumnName("kind").HasConversion(AuthConverters.EphemeralKind);
        b.Property(x => x.UserId).HasColumnName("user_id");
        b.Property(x => x.SessionId).HasColumnName("session_id");
        b.Property(x => x.Attempts).HasColumnName("attempts").HasDefaultValue(0);
        b.Property(x => x.Detail).HasColumnName("detail").HasColumnType("jsonb");
        b.Property(x => x.IssuedAt).HasColumnName("issued_at").HasDefaultValueSql("now()");
        b.Property(x => x.ExpiresAt).HasColumnName("expires_at");
        b.Property(x => x.UsedAt).HasColumnName("used_at");
        b.HasOne<UserEntity>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<SessionEntity>().WithMany().HasForeignKey(x => x.SessionId).OnDelete(DeleteBehavior.Cascade);
        b.HasIndex(x => x.ExpiresAt).HasDatabaseName("ix_ephemeral_expires");
    }
}

internal sealed class WebAuthnCredentialConfiguration : IEntityTypeConfiguration<WebAuthnCredentialEntity>
{
    public void Configure(EntityTypeBuilder<WebAuthnCredentialEntity> b)
    {
        b.ToTable("webauthn_credentials");
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasColumnName("id").ValueGeneratedNever();
        b.Property(x => x.UserId).HasColumnName("user_id");
        b.Property(x => x.CredentialId).HasColumnName("credential_id");
        b.HasIndex(x => x.CredentialId).IsUnique().HasDatabaseName("ux_webauthn_credential_id");
        b.Property(x => x.PublicKey).HasColumnName("public_key");
        b.Property(x => x.SignCount).HasColumnName("sign_count").HasDefaultValue(0L);
        b.Property(x => x.Label).HasColumnName("label");
        b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        b.HasOne<UserEntity>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Restrict);
        b.HasIndex(x => x.UserId).HasDatabaseName("ix_webauthn_user");
    }
}

internal sealed class BackupCodeConfiguration : IEntityTypeConfiguration<BackupCodeEntity>
{
    public void Configure(EntityTypeBuilder<BackupCodeEntity> b)
    {
        b.ToTable("backup_codes");
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasColumnName("id").ValueGeneratedNever();
        b.Property(x => x.UserId).HasColumnName("user_id");
        b.Property(x => x.CodeHash).HasColumnName("code_hash");
        b.Property(x => x.PepperVersion).HasColumnName("pepper_version");
        b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        b.Property(x => x.UsedAt).HasColumnName("used_at");
        b.HasOne<UserEntity>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        b.HasIndex(x => x.UserId).HasFilter("used_at IS NULL").HasDatabaseName("ix_backup_codes_user_unused");
    }
}

internal sealed class EmailOutboxConfiguration : IEntityTypeConfiguration<EmailOutboxEntity>
{
    public void Configure(EntityTypeBuilder<EmailOutboxEntity> b)
    {
        b.ToTable("email_outbox");
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasColumnName("id").ValueGeneratedNever();
        b.Property(x => x.PayloadEnc).HasColumnName("payload_enc");
        b.Property(x => x.Attempts).HasColumnName("attempts").HasDefaultValue(0);
        b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        b.Property(x => x.NextAttemptAt).HasColumnName("next_attempt_at");
        b.Property(x => x.ExpiresAt).HasColumnName("expires_at");
        b.HasIndex(x => x.NextAttemptAt).HasDatabaseName("ix_email_outbox_due");
    }
}

internal sealed class IdempotencyKeyConfiguration : IEntityTypeConfiguration<IdempotencyKeyEntity>
{
    public void Configure(EntityTypeBuilder<IdempotencyKeyEntity> b)
    {
        b.ToTable("idempotency_keys");
        b.HasKey(x => new { x.UserId, x.Endpoint, x.Key });
        b.Property(x => x.UserId).HasColumnName("user_id");
        b.Property(x => x.Endpoint).HasColumnName("endpoint");
        b.Property(x => x.Key).HasColumnName("key");
        b.Property(x => x.RequestHash).HasColumnName("request_hash");
        b.Property(x => x.StatusCode).HasColumnName("status_code");
        b.Property(x => x.ResponseBody).HasColumnName("response_body");
        b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        b.Property(x => x.ExpiresAt).HasColumnName("expires_at");
        b.HasOne<UserEntity>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        b.HasIndex(x => x.ExpiresAt).HasDatabaseName("ix_idempotency_expires");
    }
}
