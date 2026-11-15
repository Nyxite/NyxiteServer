using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Nyxite.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class PendingRestoreBy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "pending_restore_by",
                table: "files",
                type: "uuid",
                nullable: true);

            // A restore recorded before this column names no account, so no version could ever take it.
            migrationBuilder.Sql("UPDATE files SET pending_restore_seq = NULL WHERE pending_restore_seq IS NOT NULL;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "pending_restore_by",
                table: "files");
        }
    }
}
