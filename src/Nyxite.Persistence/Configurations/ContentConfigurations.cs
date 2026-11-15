using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Nyxite.Persistence.Entities;

namespace Nyxite.Persistence.Configurations;

internal sealed class FileVersionConfiguration : IEntityTypeConfiguration<FileVersionEntity>
{
    public void Configure(EntityTypeBuilder<FileVersionEntity> b)
    {
        b.ToTable("file_versions", t => t.HasCheckConstraint("ck_file_versions_layout", "layout IN ('single','chunked')"));
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasColumnName("id").ValueGeneratedNever();
        b.Property(x => x.FileId).HasColumnName("file_id");
        b.Property(x => x.Seq).HasColumnName("seq");
        b.Property(x => x.ContentHash).HasColumnName("content_hash");
        b.Property(x => x.BlobRef).HasColumnName("blob_ref");
        b.Property(x => x.SizeCipher).HasColumnName("size_cipher");
        b.Property(x => x.KeyId).HasColumnName("key_id");
        b.Property(x => x.Layout).HasColumnName("layout").HasDefaultValueSql("'single'");
        b.Property(x => x.AuthorId).HasColumnName("author_id");
        b.Property(x => x.CrdtSeq).HasColumnName("crdt_seq");
        b.Property(x => x.RestoredFromSeq).HasColumnName("restored_from_seq");
        b.Property(x => x.ParentSeq).HasColumnName("parent_seq");
        b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        b.HasOne<FileEntity>().WithMany().HasForeignKey(x => x.FileId).OnDelete(DeleteBehavior.Restrict);
        b.HasOne<UserEntity>().WithMany().HasForeignKey(x => x.AuthorId).OnDelete(DeleteBehavior.Restrict);
        b.HasIndex(x => new { x.FileId, x.Seq }).IsUnique().IsDescending(false, true).HasDatabaseName("ix_versions_file");
        b.HasIndex(x => x.BlobRef).HasDatabaseName("ix_versions_blob_ref");
    }
}

internal sealed class CrdtUpdateConfiguration : IEntityTypeConfiguration<CrdtUpdateEntity>
{
    public void Configure(EntityTypeBuilder<CrdtUpdateEntity> b)
    {
        b.ToTable("crdt_updates");
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasColumnName("id").UseIdentityByDefaultColumn();
        b.Property(x => x.CrdtDocId).HasColumnName("crdt_doc_id");
        b.Property(x => x.Seq).HasColumnName("seq");
        b.Property(x => x.UpdateEnc).HasColumnName("update_enc");
        b.Property(x => x.KeyId).HasColumnName("key_id");
        b.Property(x => x.AuthorId).HasColumnName("author_id");
        b.Property(x => x.ClientUpdateId).HasColumnName("client_update_id");
        b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        b.HasIndex(x => new { x.CrdtDocId, x.Seq }).IsUnique().HasDatabaseName("ix_crdt_updates_doc");
        b.HasIndex(x => new { x.CrdtDocId, x.ClientUpdateId }).IsUnique().HasFilter("client_update_id IS NOT NULL").HasDatabaseName("uq_crdt_updates_client_id");
    }
}

internal sealed class ChangeLogConfiguration : IEntityTypeConfiguration<ChangeLogEntity>
{
    public void Configure(EntityTypeBuilder<ChangeLogEntity> b)
    {
        b.ToTable("change_log", t =>
        {
            t.HasCheckConstraint("ck_change_log_kind", "kind IN ('structure','blob','crdt','delete','keyrotate')");
            t.HasCheckConstraint("ck_change_log_entity", "entity IN ('project','folder','file')");
        });
        b.HasKey(x => x.Seq);
        b.Property(x => x.Seq).HasColumnName("seq").UseIdentityByDefaultColumn();
        b.Property(x => x.ProjectId).HasColumnName("project_id");
        b.Property(x => x.Kind).HasColumnName("kind");
        b.Property(x => x.Entity).HasColumnName("entity");
        b.Property(x => x.EntityId).HasColumnName("entity_id");
        b.Property(x => x.Ref).HasColumnName("ref").HasColumnType("jsonb");
        b.Property(x => x.At).HasColumnName("at").HasDefaultValueSql("now()");
        b.HasOne<ProjectEntity>().WithMany().HasForeignKey(x => x.ProjectId).OnDelete(DeleteBehavior.Restrict);
        b.HasIndex(x => new { x.ProjectId, x.Seq }).HasDatabaseName("ix_change_log_project");
        // The pruning deletes by age.
        b.HasIndex(x => x.At).HasDatabaseName("ix_change_log_at");
    }
}

internal sealed class FileRotationHeadConfiguration : IEntityTypeConfiguration<FileRotationHeadEntity>
{
    public void Configure(EntityTypeBuilder<FileRotationHeadEntity> b)
    {
        b.ToTable("file_rotation_heads", t => t.HasCheckConstraint("ck_file_rotation_heads_base", "(crdt_seq IS NULL) <> (parent_seq IS NULL)"));
        b.HasKey(x => new { x.FileId, x.KeyId });
        b.Property(x => x.FileId).HasColumnName("file_id");
        b.Property(x => x.KeyId).HasColumnName("key_id");
        b.Property(x => x.ContentHash).HasColumnName("content_hash");
        b.Property(x => x.BlobRef).HasColumnName("blob_ref");
        b.Property(x => x.SizeCipher).HasColumnName("size_cipher");
        b.Property(x => x.CrdtSeq).HasColumnName("crdt_seq");
        b.Property(x => x.ParentSeq).HasColumnName("parent_seq");
        b.Property(x => x.AuthorId).HasColumnName("author_id");
        b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        // A purge deletes the file row; what it staged goes with it, and its blob is an orphan for the collector.
        b.HasOne<FileEntity>().WithMany().HasForeignKey(x => x.FileId).OnDelete(DeleteBehavior.Cascade);
        b.HasOne<UserEntity>().WithMany().HasForeignKey(x => x.AuthorId).OnDelete(DeleteBehavior.Restrict);
        // The garbage collector asks whether a staged head references a blob; the cleanup deletes by age.
        b.HasIndex(x => x.BlobRef).HasDatabaseName("ix_file_rotation_heads_blob_ref");
        b.HasIndex(x => x.CreatedAt).HasDatabaseName("ix_file_rotation_heads_created");
    }
}
