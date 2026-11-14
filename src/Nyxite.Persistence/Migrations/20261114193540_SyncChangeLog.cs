using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Nyxite.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class SyncChangeLog : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "excluded_at",
                table: "files",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "change_log",
                columns: table => new
                {
                    seq = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    project_id = table.Column<Guid>(type: "uuid", nullable: false),
                    kind = table.Column<string>(type: "text", nullable: false),
                    entity = table.Column<string>(type: "text", nullable: false),
                    entity_id = table.Column<Guid>(type: "uuid", nullable: false),
                    @ref = table.Column<string>(name: "ref", type: "jsonb", nullable: false),
                    at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_change_log", x => x.seq);
                    table.CheckConstraint("ck_change_log_entity", "entity IN ('project','folder','file')");
                    table.CheckConstraint("ck_change_log_kind", "kind IN ('structure','blob','crdt','delete','keyrotate')");
                    table.ForeignKey(
                        name: "FK_change_log_projects_project_id",
                        column: x => x.project_id,
                        principalTable: "projects",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "ix_files_excluded",
                table: "files",
                column: "excluded_at",
                filter: "excluded_at IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ix_change_log_at",
                table: "change_log",
                column: "at");

            migrationBuilder.CreateIndex(
                name: "ix_change_log_project",
                table: "change_log",
                columns: new[] { "project_id", "seq" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "change_log");

            migrationBuilder.DropIndex(
                name: "ix_files_excluded",
                table: "files");

            migrationBuilder.DropColumn(
                name: "excluded_at",
                table: "files");
        }
    }
}
