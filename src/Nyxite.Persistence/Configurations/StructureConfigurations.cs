using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Nyxite.Persistence.Entities;

namespace Nyxite.Persistence.Configurations;

internal static class StructureSql
{
    public const string Live = "deleted_at IS NULL";
    public const string SyncPolicy = "sync_policy IN ('server-default','excluded')";
    public const string MemberXorShare = "(member_id IS NOT NULL) <> (share_id IS NOT NULL)";
}

internal sealed class ProjectConfiguration : IEntityTypeConfiguration<ProjectEntity>
{
    public void Configure(EntityTypeBuilder<ProjectEntity> b)
    {
        b.ToTable("projects", t => t.HasCheckConstraint("ck_projects_sync_policy", StructureSql.SyncPolicy));
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasColumnName("id").ValueGeneratedNever();
        b.Property(x => x.OwnerId).HasColumnName("owner_id");
        b.Property(x => x.NameEnc).HasColumnName("name_enc");
        b.Property(x => x.MetadataEnc).HasColumnName("metadata_enc");
        b.Property(x => x.SyncPolicy).HasColumnName("sync_policy").HasDefaultValueSql("'server-default'");
        b.Property(x => x.KeyGeneration).HasColumnName("key_generation").HasDefaultValue(1);
        b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasDefaultValueSql("now()");
        b.Property(x => x.DeletedAt).HasColumnName("deleted_at");
        b.HasOne<UserEntity>().WithMany().HasForeignKey(x => x.OwnerId).OnDelete(DeleteBehavior.Restrict);
        b.HasIndex(x => x.OwnerId).HasFilter(StructureSql.Live).HasDatabaseName("ix_projects_owner");
    }
}

internal sealed class FolderConfiguration : IEntityTypeConfiguration<FolderEntity>
{
    public void Configure(EntityTypeBuilder<FolderEntity> b)
    {
        b.ToTable("folders", t =>
        {
            t.HasCheckConstraint("ck_folders_sync_policy", "sync_policy IS NULL OR " + StructureSql.SyncPolicy);
            t.HasCheckConstraint("ck_folders_not_own_parent", "parent_folder_id IS NULL OR parent_folder_id <> id");
        });
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasColumnName("id").ValueGeneratedNever();
        b.Property(x => x.ProjectId).HasColumnName("project_id");
        b.Property(x => x.ParentFolderId).HasColumnName("parent_folder_id");
        b.Property(x => x.NameEnc).HasColumnName("name_enc");
        b.Property(x => x.MetadataEnc).HasColumnName("metadata_enc");
        b.Property(x => x.SyncPolicy).HasColumnName("sync_policy");
        b.Property(x => x.KeyGeneration).HasColumnName("key_generation").HasDefaultValue(1);
        b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasDefaultValueSql("now()");
        b.Property(x => x.DeletedAt).HasColumnName("deleted_at");
        b.Property(x => x.DeletedRootId).HasColumnName("deleted_root_id");
        b.HasIndex(x => x.DeletedRootId).HasFilter("deleted_root_id IS NOT NULL").HasDatabaseName("ix_folders_deleted_root");
        b.HasOne<ProjectEntity>().WithMany().HasForeignKey(x => x.ProjectId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<FolderEntity>().WithMany().HasForeignKey(x => x.ParentFolderId).OnDelete(DeleteBehavior.Restrict);
        b.HasIndex(x => x.ProjectId).HasFilter(StructureSql.Live).HasDatabaseName("ix_folders_project");
        b.HasIndex(x => x.ParentFolderId).HasFilter(StructureSql.Live).HasDatabaseName("ix_folders_parent");
    }
}

internal sealed class FileConfiguration : IEntityTypeConfiguration<FileEntity>
{
    public void Configure(EntityTypeBuilder<FileEntity> b)
    {
        b.ToTable("files", t =>
        {
            t.HasCheckConstraint("ck_files_content_type", "content_type IN ('markdown','plaintext','ink','office','sourcecode','image','binary')");
            t.HasCheckConstraint("ck_files_sync_policy", StructureSql.SyncPolicy);
        });
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasColumnName("id").ValueGeneratedNever();
        b.Property(x => x.ProjectId).HasColumnName("project_id");
        b.Property(x => x.FolderId).HasColumnName("folder_id");
        b.Property(x => x.OwnerId).HasColumnName("owner_id");
        b.Property(x => x.NameEnc).HasColumnName("name_enc");
        b.Property(x => x.ContentType).HasColumnName("content_type");
        b.Property(x => x.SyncPolicy).HasColumnName("sync_policy").HasDefaultValueSql("'server-default'");
        b.Property(x => x.CurrentVersionId).HasColumnName("current_version_id");
        b.Property(x => x.CrdtDocId).HasColumnName("crdt_doc_id");
        b.Property(x => x.VersionSeq).HasColumnName("version_seq").HasDefaultValue(0L);
        b.Property(x => x.CrdtHeadSeq).HasColumnName("crdt_head_seq").HasDefaultValue(0L);
        b.Property(x => x.PendingRestoreSeq).HasColumnName("pending_restore_seq");
        b.HasOne<FileVersionEntity>().WithMany().HasForeignKey(x => x.CurrentVersionId).OnDelete(DeleteBehavior.Restrict)
            .HasConstraintName("fk_files_current_version");
        b.HasIndex(x => x.CrdtDocId).IsUnique().HasFilter("crdt_doc_id IS NOT NULL").HasDatabaseName("uq_files_crdt_doc");
        b.Property(x => x.KeyGeneration).HasColumnName("key_generation").HasDefaultValue(1);
        b.Property(x => x.MetadataEnc).HasColumnName("metadata_enc");
        b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasDefaultValueSql("now()");
        b.Property(x => x.DeletedAt).HasColumnName("deleted_at");
        b.Property(x => x.DeletedRootId).HasColumnName("deleted_root_id");
        b.HasIndex(x => x.DeletedRootId).HasFilter("deleted_root_id IS NOT NULL").HasDatabaseName("ix_files_deleted_root");
        b.Property(x => x.ExcludedAt).HasColumnName("excluded_at");
        b.HasIndex(x => x.ExcludedAt).HasFilter("excluded_at IS NOT NULL").HasDatabaseName("ix_files_excluded");
        b.HasOne<ProjectEntity>().WithMany().HasForeignKey(x => x.ProjectId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<FolderEntity>().WithMany().HasForeignKey(x => x.FolderId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<UserEntity>().WithMany().HasForeignKey(x => x.OwnerId).OnDelete(DeleteBehavior.Restrict);
        b.HasIndex(x => x.ProjectId).HasFilter(StructureSql.Live).HasDatabaseName("ix_files_project");
        b.HasIndex(x => x.FolderId).HasFilter(StructureSql.Live).HasDatabaseName("ix_files_folder");
        b.HasIndex(x => x.OwnerId).HasFilter(StructureSql.Live).HasDatabaseName("ix_files_owner");
    }
}

internal sealed class FileKeyConfiguration : IEntityTypeConfiguration<FileKeyEntity>
{
    public void Configure(EntityTypeBuilder<FileKeyEntity> b)
    {
        b.ToTable("file_keys", t => t.HasCheckConstraint("ck_file_keys_member_xor_share", StructureSql.MemberXorShare));
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasColumnName("id").ValueGeneratedNever();
        b.Property(x => x.FileId).HasColumnName("file_id");
        b.Property(x => x.MemberId).HasColumnName("member_id");
        b.Property(x => x.ShareId).HasColumnName("share_id");
        b.Property(x => x.KeyId).HasColumnName("key_id");
        b.Property(x => x.WrappedKey).HasColumnName("wrapped_key");
        b.Property(x => x.Generation).HasColumnName("generation").HasDefaultValue(1);
        b.Property(x => x.AlgId).HasColumnName("alg_id");
        b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        b.Property(x => x.RevokedAt).HasColumnName("revoked_at");
        b.HasOne<FileEntity>().WithMany().HasForeignKey(x => x.FileId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<UserEntity>().WithMany().HasForeignKey(x => x.MemberId).OnDelete(DeleteBehavior.Restrict);
        b.HasIndex(x => new { x.FileId, x.KeyId, x.MemberId }).IsUnique().HasFilter("member_id IS NOT NULL").HasDatabaseName("uq_file_keys_member");
        b.HasIndex(x => new { x.FileId, x.KeyId, x.ShareId }).IsUnique().HasFilter("share_id IS NOT NULL").HasDatabaseName("uq_file_keys_share");
        b.HasIndex(x => x.MemberId).HasFilter("revoked_at IS NULL").HasDatabaseName("ix_file_keys_member_live");
    }
}

internal sealed class StructureKeyConfiguration : IEntityTypeConfiguration<StructureKeyEntity>
{
    public void Configure(EntityTypeBuilder<StructureKeyEntity> b)
    {
        b.ToTable("structure_keys", t =>
        {
            t.HasCheckConstraint("ck_structure_keys_member_xor_share", StructureSql.MemberXorShare);
            t.HasCheckConstraint("ck_structure_keys_one_target", "(project_id IS NOT NULL) <> (folder_id IS NOT NULL)");
        });
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasColumnName("id").ValueGeneratedNever();
        b.Property(x => x.ProjectId).HasColumnName("project_id");
        b.Property(x => x.FolderId).HasColumnName("folder_id");
        b.Property(x => x.MemberId).HasColumnName("member_id");
        b.Property(x => x.ShareId).HasColumnName("share_id");
        b.Property(x => x.KeyId).HasColumnName("key_id");
        b.Property(x => x.WrappedKey).HasColumnName("wrapped_key");
        b.Property(x => x.Generation).HasColumnName("generation").HasDefaultValue(1);
        b.Property(x => x.AlgId).HasColumnName("alg_id");
        b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        b.Property(x => x.RevokedAt).HasColumnName("revoked_at");
        b.HasOne<ProjectEntity>().WithMany().HasForeignKey(x => x.ProjectId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<FolderEntity>().WithMany().HasForeignKey(x => x.FolderId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<UserEntity>().WithMany().HasForeignKey(x => x.MemberId).OnDelete(DeleteBehavior.Restrict);
        b.HasIndex(x => new { x.ProjectId, x.KeyId, x.MemberId }).IsUnique().HasFilter("project_id IS NOT NULL AND member_id IS NOT NULL")
            .HasDatabaseName("uq_structure_keys_project_member");
        b.HasIndex(x => new { x.FolderId, x.KeyId, x.MemberId }).IsUnique().HasFilter("folder_id IS NOT NULL AND member_id IS NOT NULL")
            .HasDatabaseName("uq_structure_keys_folder_member");
        b.HasIndex(x => x.MemberId).HasFilter("revoked_at IS NULL").HasDatabaseName("ix_structure_keys_member_live");
    }
}
