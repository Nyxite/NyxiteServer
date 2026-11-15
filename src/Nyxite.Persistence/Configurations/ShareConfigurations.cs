using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Nyxite.Persistence.Entities;

namespace Nyxite.Persistence.Configurations;

internal sealed class ShareConfiguration : IEntityTypeConfiguration<ShareEntity>
{
    public void Configure(EntityTypeBuilder<ShareEntity> b)
    {
        b.ToTable("shares", t =>
        {
            t.HasCheckConstraint("ck_shares_kind", "kind IN ('user_grant','link')");
            t.HasCheckConstraint("ck_shares_permission", "permission IN ('read','write')");
            t.HasCheckConstraint("ck_shares_one_target", "num_nonnulls(file_id, folder_id, project_id) = 1");
            // An account share names a grantee and has no token; a link share has a 32-byte token hash, no grantee and
            // one file as its target, because its URL fragment carries one file key (09 §9.4).
            t.HasCheckConstraint("ck_shares_kind_fields",
                "(kind = 'user_grant' AND grantee_id IS NOT NULL AND link_token_hash IS NULL) OR " +
                "(kind = 'link' AND grantee_id IS NULL AND octet_length(link_token_hash) = 32 AND file_id IS NOT NULL)");
        });
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasColumnName("id").ValueGeneratedNever();
        b.Property(x => x.FileId).HasColumnName("file_id");
        b.Property(x => x.FolderId).HasColumnName("folder_id");
        b.Property(x => x.ProjectId).HasColumnName("project_id");
        b.Property(x => x.Kind).HasColumnName("kind");
        b.Property(x => x.GranteeId).HasColumnName("grantee_id");
        b.Property(x => x.LinkTokenHash).HasColumnName("link_token_hash");
        b.Property(x => x.Permission).HasColumnName("permission");
        b.Property(x => x.CreatedBy).HasColumnName("created_by");
        b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        b.Property(x => x.ExpiresAt).HasColumnName("expires_at");
        b.Property(x => x.RevokedAt).HasColumnName("revoked_at");
        b.HasOne<FileEntity>().WithMany().HasForeignKey(x => x.FileId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<FolderEntity>().WithMany().HasForeignKey(x => x.FolderId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<ProjectEntity>().WithMany().HasForeignKey(x => x.ProjectId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<UserEntity>().WithMany().HasForeignKey(x => x.GranteeId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<UserEntity>().WithMany().HasForeignKey(x => x.CreatedBy).OnDelete(DeleteBehavior.Restrict);
        b.HasIndex(x => x.FileId).HasFilter("revoked_at IS NULL").HasDatabaseName("ix_shares_target_file");
        b.HasIndex(x => x.FolderId).HasFilter("revoked_at IS NULL").HasDatabaseName("ix_shares_target_folder");
        b.HasIndex(x => x.ProjectId).HasFilter("revoked_at IS NULL").HasDatabaseName("ix_shares_target_project");
        b.HasIndex(x => x.GranteeId).HasFilter("revoked_at IS NULL").HasDatabaseName("ix_shares_grantee");
        // Unique, so a token resolves to exactly one share; revoked links keep their hash and answer 410, not 404.
        b.HasIndex(x => x.LinkTokenHash).IsUnique().HasFilter("link_token_hash IS NOT NULL").HasDatabaseName(ShareEntity.LinkIndex);
        // One unrevoked account share per target and grantee, so two concurrent creates cannot both store one and a
        // revoke never leaves a twin behind. Nulls are not distinct, because two of the three target columns are always
        // null. An expired share is revoked by the create that replaces it.
        b.HasIndex(x => new { x.GranteeId, x.FileId, x.FolderId, x.ProjectId }).IsUnique().AreNullsDistinct(false)
            .HasFilter("kind = 'user_grant' AND revoked_at IS NULL").HasDatabaseName(ShareEntity.LiveGrantIndex);
    }
}
