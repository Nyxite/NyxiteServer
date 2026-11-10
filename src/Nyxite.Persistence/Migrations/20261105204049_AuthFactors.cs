using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Nyxite.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AuthFactors : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropCheckConstraint(
                name: "ck_sessions_auth_method",
                table: "sessions");

            migrationBuilder.DropCheckConstraint(
                name: "ck_ephemeral_kind",
                table: "ephemeral_tokens");

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "email_otp_enabled_at",
                table: "users",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "email_verified_at",
                table: "users",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "totp_last_step",
                table: "users",
                type: "bigint",
                nullable: true);

            // Accounts created before email verification existed keep working: they would otherwise be purged as unverified.
            migrationBuilder.Sql("UPDATE users SET email_verified_at = created_at");

            migrationBuilder.CreateTable(
                name: "backup_codes",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    code_hash = table.Column<byte[]>(type: "bytea", nullable: false),
                    pepper_version = table.Column<int>(type: "integer", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_backup_codes", x => x.id);
                    table.ForeignKey(
                        name: "FK_backup_codes_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.AddCheckConstraint(
                name: "ck_sessions_auth_method",
                table: "sessions",
                sql: "auth_method IN ('password_totp','passkey','oidc','password_email','password_backup_code')");

            migrationBuilder.AddCheckConstraint(
                name: "ck_ephemeral_kind",
                table: "ephemeral_tokens",
                sql: "kind IN ('mfa','socket_ticket','password_reset','invite','oidc_state','oidc_handoff','webauthn_challenge','totp_enroll','email_verify','email_code','step_up')");

            migrationBuilder.CreateIndex(
                name: "ix_backup_codes_user_unused",
                table: "backup_codes",
                column: "user_id",
                filter: "used_at IS NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "backup_codes");

            migrationBuilder.DropCheckConstraint(
                name: "ck_sessions_auth_method",
                table: "sessions");

            migrationBuilder.DropCheckConstraint(
                name: "ck_ephemeral_kind",
                table: "ephemeral_tokens");

            migrationBuilder.DropColumn(
                name: "email_otp_enabled_at",
                table: "users");

            migrationBuilder.DropColumn(
                name: "email_verified_at",
                table: "users");

            migrationBuilder.DropColumn(
                name: "totp_last_step",
                table: "users");

            migrationBuilder.AddCheckConstraint(
                name: "ck_sessions_auth_method",
                table: "sessions",
                sql: "auth_method IN ('password_totp','passkey','oidc')");

            migrationBuilder.AddCheckConstraint(
                name: "ck_ephemeral_kind",
                table: "ephemeral_tokens",
                sql: "kind IN ('mfa','socket_ticket','password_reset','invite','oidc_state','oidc_handoff','webauthn_challenge','totp_enroll')");
        }
    }
}
