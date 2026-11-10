using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Nyxite.Persistence.Entities;

namespace Nyxite.Persistence.Configurations;

internal sealed class KtLeafConfiguration : IEntityTypeConfiguration<KtLeafEntity>
{
    public void Configure(EntityTypeBuilder<KtLeafEntity> b)
    {
        b.ToTable("kt_leaves", t => t.HasCheckConstraint("ck_kt_leaves_entry_type", "entry_type IN (1,2,3)"));
        b.HasKey(x => x.LeafIndex);
        b.Property(x => x.LeafIndex).HasColumnName("leaf_index").ValueGeneratedNever();
        b.Property(x => x.EntryType).HasColumnName("entry_type");
        b.Property(x => x.SubjectId).HasColumnName("subject_id");
        b.Property(x => x.KeyId).HasColumnName("key_id");
        b.Property(x => x.LeafData).HasColumnName("leaf_data");
        b.Property(x => x.LeafHash).HasColumnName("leaf_hash");
        b.Property(x => x.LoggedAt).HasColumnName("logged_at");
        b.HasIndex(x => new { x.SubjectId, x.LeafIndex }).HasDatabaseName("ix_kt_subject");
    }
}

internal sealed class KtStateConfiguration : IEntityTypeConfiguration<KtStateEntity>
{
    public void Configure(EntityTypeBuilder<KtStateEntity> b)
    {
        b.ToTable("kt_state", t => t.HasCheckConstraint("ck_kt_state_single_row", "id"));
        b.HasKey(x => x.Id);
        b.Property(x => x.Id).HasColumnName("id").HasDefaultValue(true).ValueGeneratedNever();
        b.Property(x => x.TreeSize).HasColumnName("tree_size").HasDefaultValue(0L);
        b.HasData(new KtStateEntity { Id = true, TreeSize = 0 });
    }
}
