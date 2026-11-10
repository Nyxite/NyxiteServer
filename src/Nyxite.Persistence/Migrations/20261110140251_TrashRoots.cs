using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Nyxite.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class TrashRoots : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "deleted_root_id",
                table: "folders",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "deleted_root_id",
                table: "files",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "ix_folders_deleted_root",
                table: "folders",
                column: "deleted_root_id",
                filter: "deleted_root_id IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ix_files_deleted_root",
                table: "files",
                column: "deleted_root_id",
                filter: "deleted_root_id IS NOT NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "ix_folders_deleted_root",
                table: "folders");

            migrationBuilder.DropIndex(
                name: "ix_files_deleted_root",
                table: "files");

            migrationBuilder.DropColumn(
                name: "deleted_root_id",
                table: "folders");

            migrationBuilder.DropColumn(
                name: "deleted_root_id",
                table: "files");
        }
    }
}
