using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Nyxite.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Sharing : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_ephemeral_kind",
                table: "ephemeral_tokens");

            migrationBuilder.DropCheckConstraint(
                name: "ck_ephemeral_user",
                table: "ephemeral_tokens");

            migrationBuilder.CreateTable(
                name: "shares",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    file_id = table.Column<Guid>(type: "uuid", nullable: true),
                    folder_id = table.Column<Guid>(type: "uuid", nullable: true),
                    project_id = table.Column<Guid>(type: "uuid", nullable: true),
                    kind = table.Column<string>(type: "text", nullable: false),
                    grantee_id = table.Column<Guid>(type: "uuid", nullable: true),
                    link_token_hash = table.Column<byte[]>(type: "bytea", nullable: true),
                    permission = table.Column<string>(type: "text", nullable: false),
                    created_by = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_shares", x => x.id);
                    table.CheckConstraint("ck_shares_kind", "kind IN ('user_grant','link')");
                    table.CheckConstraint("ck_shares_kind_fields", "(kind = 'user_grant' AND grantee_id IS NOT NULL AND link_token_hash IS NULL) OR (kind = 'link' AND grantee_id IS NULL AND octet_length(link_token_hash) = 32 AND file_id IS NOT NULL)");
                    table.CheckConstraint("ck_shares_one_target", "num_nonnulls(file_id, folder_id, project_id) = 1");
                    table.CheckConstraint("ck_shares_permission", "permission IN ('read','write')");
                    table.ForeignKey(
                        name: "FK_shares_files_file_id",
                        column: x => x.file_id,
                        principalTable: "files",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_shares_folders_folder_id",
                        column: x => x.folder_id,
                        principalTable: "folders",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_shares_projects_project_id",
                        column: x => x.project_id,
                        principalTable: "projects",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_shares_users_created_by",
                        column: x => x.created_by,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_shares_users_grantee_id",
                        column: x => x.grantee_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_structure_keys_share_id",
                table: "structure_keys",
                column: "share_id");

            migrationBuilder.CreateIndex(
                name: "IX_file_keys_share_id",
                table: "file_keys",
                column: "share_id");

            migrationBuilder.AddCheckConstraint(
                name: "ck_ephemeral_kind",
                table: "ephemeral_tokens",
                sql: "kind IN ('mfa','socket_ticket','password_reset','invite','oidc_state','oidc_handoff','webauthn_challenge','totp_enroll','email_verify','email_code','step_up','guest_socket_ticket')");

            migrationBuilder.AddCheckConstraint(
                name: "ck_ephemeral_user",
                table: "ephemeral_tokens",
                sql: "user_id IS NOT NULL OR kind IN ('oidc_state','webauthn_challenge','guest_socket_ticket')");

            migrationBuilder.CreateIndex(
                name: "IX_shares_created_by",
                table: "shares",
                column: "created_by");

            migrationBuilder.CreateIndex(
                name: "ix_shares_grantee",
                table: "shares",
                column: "grantee_id",
                filter: "revoked_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "ix_shares_target_file",
                table: "shares",
                column: "file_id",
                filter: "revoked_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "ix_shares_target_folder",
                table: "shares",
                column: "folder_id",
                filter: "revoked_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "ix_shares_target_project",
                table: "shares",
                column: "project_id",
                filter: "revoked_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "uq_shares_link",
                table: "shares",
                column: "link_token_hash",
                unique: true,
                filter: "link_token_hash IS NOT NULL");

            migrationBuilder.AddForeignKey(
                name: "FK_file_keys_shares_share_id",
                table: "file_keys",
                column: "share_id",
                principalTable: "shares",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_structure_keys_shares_share_id",
                table: "structure_keys",
                column: "share_id",
                principalTable: "shares",
                principalColumn: "id",
                onDelete: ReferentialAction.Restrict);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_file_keys_shares_share_id",
                table: "file_keys");

            migrationBuilder.DropForeignKey(
                name: "FK_structure_keys_shares_share_id",
                table: "structure_keys");

            migrationBuilder.DropTable(
                name: "shares");

            migrationBuilder.DropIndex(
                name: "IX_structure_keys_share_id",
                table: "structure_keys");

            migrationBuilder.DropIndex(
                name: "IX_file_keys_share_id",
                table: "file_keys");

            migrationBuilder.DropCheckConstraint(
                name: "ck_ephemeral_kind",
                table: "ephemeral_tokens");

            migrationBuilder.DropCheckConstraint(
                name: "ck_ephemeral_user",
                table: "ephemeral_tokens");

            migrationBuilder.AddCheckConstraint(
                name: "ck_ephemeral_kind",
                table: "ephemeral_tokens",
                sql: "kind IN ('mfa','socket_ticket','password_reset','invite','oidc_state','oidc_handoff','webauthn_challenge','totp_enroll','email_verify','email_code','step_up')");

            migrationBuilder.AddCheckConstraint(
                name: "ck_ephemeral_user",
                table: "ephemeral_tokens",
                sql: "user_id IS NOT NULL OR kind IN ('oidc_state','webauthn_challenge')");
        }
    }
}
