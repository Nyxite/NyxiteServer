using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Nyxite.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class RotationLinksAndParentSeq : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "frozen_generation",
                table: "shares",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "frozen_metadata_enc",
                table: "shares",
                type: "bytea",
                nullable: true);

            migrationBuilder.AddColumn<byte[]>(
                name: "frozen_name_enc",
                table: "shares",
                type: "bytea",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "frozen_version_seq",
                table: "shares",
                type: "bigint",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "pending_restore_at",
                table: "files",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "rotation_pending_at",
                table: "files",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "parent_seq",
                table: "file_versions",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            // A version written before this column recorded no base. The previous seq is the base of every version that
            // won, and kept losers were not marked before either, so nothing is labelled wrongly that was right before.
            migrationBuilder.Sql("UPDATE file_versions SET parent_seq = seq - 1;");
            // A mark recorded before this column gets the full lifetime from now, instead of lapsing at once.
            migrationBuilder.Sql("UPDATE files SET pending_restore_at = now() WHERE pending_restore_seq IS NOT NULL;");

            migrationBuilder.AddCheckConstraint(
                name: "ck_shares_frozen_link",
                table: "shares",
                sql: "frozen_generation IS NULL OR (kind = 'link' AND frozen_name_enc IS NOT NULL)");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_shares_frozen_link",
                table: "shares");

            migrationBuilder.DropColumn(
                name: "frozen_generation",
                table: "shares");

            migrationBuilder.DropColumn(
                name: "frozen_metadata_enc",
                table: "shares");

            migrationBuilder.DropColumn(
                name: "frozen_name_enc",
                table: "shares");

            migrationBuilder.DropColumn(
                name: "frozen_version_seq",
                table: "shares");

            migrationBuilder.DropColumn(
                name: "pending_restore_at",
                table: "files");

            migrationBuilder.DropColumn(
                name: "rotation_pending_at",
                table: "files");

            migrationBuilder.DropColumn(
                name: "parent_seq",
                table: "file_versions");
        }
    }
}
