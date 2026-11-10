using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Nyxite.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class ContentVersionsAndUpdates : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "crdt_head_seq",
                table: "files",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<long>(
                name: "pending_restore_seq",
                table: "files",
                type: "bigint",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "version_seq",
                table: "files",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.CreateTable(
                name: "crdt_updates",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    crdt_doc_id = table.Column<Guid>(type: "uuid", nullable: false),
                    seq = table.Column<long>(type: "bigint", nullable: false),
                    update_enc = table.Column<byte[]>(type: "bytea", nullable: false),
                    key_id = table.Column<Guid>(type: "uuid", nullable: false),
                    author_id = table.Column<Guid>(type: "uuid", nullable: true),
                    client_update_id = table.Column<Guid>(type: "uuid", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_crdt_updates", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "file_versions",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    file_id = table.Column<Guid>(type: "uuid", nullable: false),
                    seq = table.Column<long>(type: "bigint", nullable: false),
                    content_hash = table.Column<byte[]>(type: "bytea", nullable: false),
                    blob_ref = table.Column<string>(type: "text", nullable: false),
                    size_cipher = table.Column<long>(type: "bigint", nullable: false),
                    key_id = table.Column<Guid>(type: "uuid", nullable: false),
                    layout = table.Column<string>(type: "text", nullable: false, defaultValueSql: "'single'"),
                    author_id = table.Column<Guid>(type: "uuid", nullable: true),
                    crdt_seq = table.Column<long>(type: "bigint", nullable: true),
                    restored_from_seq = table.Column<long>(type: "bigint", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_file_versions", x => x.id);
                    table.CheckConstraint("ck_file_versions_layout", "layout IN ('single','chunked')");
                    table.ForeignKey(
                        name: "FK_file_versions_files_file_id",
                        column: x => x.file_id,
                        principalTable: "files",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_file_versions_users_author_id",
                        column: x => x.author_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_files_current_version_id",
                table: "files",
                column: "current_version_id");

            migrationBuilder.CreateIndex(
                name: "uq_files_crdt_doc",
                table: "files",
                column: "crdt_doc_id",
                unique: true,
                filter: "crdt_doc_id IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ix_crdt_updates_doc",
                table: "crdt_updates",
                columns: new[] { "crdt_doc_id", "seq" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "uq_crdt_updates_client_id",
                table: "crdt_updates",
                columns: new[] { "crdt_doc_id", "client_update_id" },
                unique: true,
                filter: "client_update_id IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_file_versions_author_id",
                table: "file_versions",
                column: "author_id");

            migrationBuilder.CreateIndex(
                name: "ix_versions_blob_ref",
                table: "file_versions",
                column: "blob_ref");

            migrationBuilder.CreateIndex(
                name: "ix_versions_file",
                table: "file_versions",
                columns: new[] { "file_id", "seq" },
                unique: true,
                descending: new[] { false, true });

            migrationBuilder.AddForeignKey(
                name: "fk_files_current_version",
                table: "files",
                column: "current_version_id",
                principalTable: "file_versions",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "fk_files_current_version",
                table: "files");

            migrationBuilder.DropTable(
                name: "crdt_updates");

            migrationBuilder.DropTable(
                name: "file_versions");

            migrationBuilder.DropIndex(
                name: "IX_files_current_version_id",
                table: "files");

            migrationBuilder.DropIndex(
                name: "uq_files_crdt_doc",
                table: "files");

            migrationBuilder.DropColumn(
                name: "crdt_head_seq",
                table: "files");

            migrationBuilder.DropColumn(
                name: "pending_restore_seq",
                table: "files");

            migrationBuilder.DropColumn(
                name: "version_seq",
                table: "files");
        }
    }
}
