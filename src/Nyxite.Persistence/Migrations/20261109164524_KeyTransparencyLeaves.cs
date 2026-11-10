using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Nyxite.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class KeyTransparencyLeaves : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "kt_leaves",
                columns: table => new
                {
                    leaf_index = table.Column<long>(type: "bigint", nullable: false),
                    entry_type = table.Column<short>(type: "smallint", nullable: false),
                    subject_id = table.Column<Guid>(type: "uuid", nullable: false),
                    key_id = table.Column<Guid>(type: "uuid", nullable: false),
                    leaf_data = table.Column<byte[]>(type: "bytea", nullable: false),
                    leaf_hash = table.Column<byte[]>(type: "bytea", nullable: false),
                    logged_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_kt_leaves", x => x.leaf_index);
                    table.CheckConstraint("ck_kt_leaves_entry_type", "entry_type IN (1,2,3)");
                });

            migrationBuilder.CreateTable(
                name: "kt_state",
                columns: table => new
                {
                    id = table.Column<bool>(type: "boolean", nullable: false, defaultValue: true),
                    tree_size = table.Column<long>(type: "bigint", nullable: false, defaultValue: 0L)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_kt_state", x => x.id);
                    table.CheckConstraint("ck_kt_state_single_row", "id");
                });

            migrationBuilder.InsertData(
                table: "kt_state",
                column: "id",
                value: true);

            migrationBuilder.CreateIndex(
                name: "ix_kt_subject",
                table: "kt_leaves",
                columns: new[] { "subject_id", "leaf_index" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "kt_leaves");

            migrationBuilder.DropTable(
                name: "kt_state");
        }
    }
}
