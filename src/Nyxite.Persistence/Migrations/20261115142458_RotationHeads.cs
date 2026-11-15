using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Nyxite.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class RotationHeads : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "file_rotation_heads",
                columns: table => new
                {
                    file_id = table.Column<Guid>(type: "uuid", nullable: false),
                    key_id = table.Column<Guid>(type: "uuid", nullable: false),
                    content_hash = table.Column<byte[]>(type: "bytea", nullable: false),
                    blob_ref = table.Column<string>(type: "text", nullable: false),
                    size_cipher = table.Column<long>(type: "bigint", nullable: false),
                    crdt_seq = table.Column<long>(type: "bigint", nullable: true),
                    parent_seq = table.Column<long>(type: "bigint", nullable: true),
                    author_id = table.Column<Guid>(type: "uuid", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_file_rotation_heads", x => new { x.file_id, x.key_id });
                    table.CheckConstraint("ck_file_rotation_heads_base", "(crdt_seq IS NULL) <> (parent_seq IS NULL)");
                    table.ForeignKey(
                        name: "FK_file_rotation_heads_files_file_id",
                        column: x => x.file_id,
                        principalTable: "files",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_file_rotation_heads_users_author_id",
                        column: x => x.author_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_file_rotation_heads_author_id",
                table: "file_rotation_heads",
                column: "author_id");

            migrationBuilder.CreateIndex(
                name: "ix_file_rotation_heads_blob_ref",
                table: "file_rotation_heads",
                column: "blob_ref");

            migrationBuilder.CreateIndex(
                name: "ix_file_rotation_heads_created",
                table: "file_rotation_heads",
                column: "created_at");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "file_rotation_heads");
        }
    }
}
