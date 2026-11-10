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
