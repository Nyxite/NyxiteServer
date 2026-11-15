using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Nyxite.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class LiveAccountShareUnique : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Before this index a create only checked for a live share, so a pair may hold an expired but unrevoked share
            // next to a newer one, or two live ones from a race. All but the newest (ids are UUIDv7) are revoked.
            migrationBuilder.Sql("""
                UPDATE shares s SET revoked_at = now()
                WHERE s.kind = 'user_grant' AND s.revoked_at IS NULL AND EXISTS (
                    SELECT 1 FROM shares t
                    WHERE t.kind = 'user_grant' AND t.revoked_at IS NULL AND t.grantee_id = s.grantee_id AND t.id > s.id
                      AND t.file_id IS NOT DISTINCT FROM s.file_id AND t.folder_id IS NOT DISTINCT FROM s.folder_id
                      AND t.project_id IS NOT DISTINCT FROM s.project_id)
                """);

            migrationBuilder.CreateIndex(
                name: "uq_shares_live_grant",
                table: "shares",
                columns: new[] { "grantee_id", "file_id", "folder_id", "project_id" },
                unique: true,
                filter: "kind = 'user_grant' AND revoked_at IS NULL")
                .Annotation("Npgsql:NullsDistinct", false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "uq_shares_live_grant",
                table: "shares");
        }
    }
}
