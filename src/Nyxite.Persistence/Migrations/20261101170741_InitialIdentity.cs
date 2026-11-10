using System;
using System.Net;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Nyxite.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialIdentity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "audit_log",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    occurred_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    actor_id = table.Column<Guid>(type: "uuid", nullable: true),
                    actor_kind = table.Column<string>(type: "text", nullable: false),
                    action = table.Column<string>(type: "text", nullable: false),
                    target_type = table.Column<string>(type: "text", nullable: true),
                    target_id = table.Column<Guid>(type: "uuid", nullable: true),
                    detail = table.Column<string>(type: "jsonb", nullable: false, defaultValueSql: "'{}'::jsonb"),
                    ip = table.Column<IPAddress>(type: "inet", nullable: true),
                    user_agent = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_audit_log", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "users",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    email = table.Column<string>(type: "text", nullable: false),
                    display_name = table.Column<string>(type: "text", nullable: false),
                    password_verifier = table.Column<byte[]>(type: "bytea", nullable: true),
                    password_pepper_version = table.Column<int>(type: "integer", nullable: true),
                    totp_secret_enc = table.Column<byte[]>(type: "bytea", nullable: true),
                    external_idp = table.Column<string>(type: "text", nullable: true),
                    external_idp_sub = table.Column<string>(type: "text", nullable: true),
                    role = table.Column<string>(type: "text", nullable: false, defaultValueSql: "'user'"),
                    status = table.Column<string>(type: "text", nullable: false, defaultValueSql: "'active'"),
                    storage_quota_bytes = table.Column<long>(type: "bigint", nullable: true),
                    settings_enc = table.Column<byte[]>(type: "bytea", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_users", x => x.id);
                    table.CheckConstraint("ck_users_role", "role IN ('user','admin')");
                    table.CheckConstraint("ck_users_status", "status IN ('active','blocked')");
                });

            migrationBuilder.CreateTable(
                name: "devices",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    label = table.Column<string>(type: "text", nullable: true),
                    pubkey = table.Column<byte[]>(type: "bytea", nullable: false),
                    status = table.Column<string>(type: "text", nullable: false, defaultValueSql: "'pending'"),
                    pending_key_blob = table.Column<byte[]>(type: "bytea", nullable: true),
                    pairing_code_hash = table.Column<byte[]>(type: "bytea", nullable: true),
                    pairing_expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    pairing_attempts = table.Column<int>(type: "integer", nullable: false, defaultValue: 0),
                    enrolled_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_devices", x => x.id);
                    table.CheckConstraint("ck_devices_status", "status IN ('pending','active','revoked')");
                    table.ForeignKey(
                        name: "FK_devices_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "recovery_blobs",
                columns: table => new
                {
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    version = table.Column<int>(type: "integer", nullable: false, defaultValue: 1),
                    blob = table.Column<byte[]>(type: "bytea", nullable: false),
                    kdf_params = table.Column<string>(type: "jsonb", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()")
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_recovery_blobs", x => x.user_id);
                    table.ForeignKey(
                        name: "FK_recovery_blobs_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "user_keys",
                columns: table => new
                {
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    key_id = table.Column<Guid>(type: "uuid", nullable: false),
                    public_x25519 = table.Column<byte[]>(type: "bytea", nullable: false),
                    public_ed25519 = table.Column<byte[]>(type: "bytea", nullable: false),
                    alg_id = table.Column<string>(type: "text", nullable: false),
                    generation = table.Column<int>(type: "integer", nullable: false, defaultValue: 1),
                    self_sig = table.Column<byte[]>(type: "bytea", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_user_keys", x => new { x.user_id, x.key_id });
                    table.ForeignKey(
                        name: "FK_user_keys_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "ix_audit_action",
                table: "audit_log",
                column: "action");

            migrationBuilder.CreateIndex(
                name: "ix_audit_actor",
                table: "audit_log",
                column: "actor_id");

            migrationBuilder.CreateIndex(
                name: "ix_audit_time",
                table: "audit_log",
                column: "occurred_at",
                descending: new bool[0]);

            migrationBuilder.CreateIndex(
                name: "ix_devices_user_live",
                table: "devices",
                column: "user_id",
                filter: "revoked_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "ix_user_keys_user_live",
                table: "user_keys",
                column: "user_id",
                filter: "revoked_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "ux_users_email",
                table: "users",
                column: "email",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ux_users_external_idp",
                table: "users",
                columns: new[] { "external_idp", "external_idp_sub" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "audit_log");

            migrationBuilder.DropTable(
                name: "devices");

            migrationBuilder.DropTable(
                name: "recovery_blobs");

            migrationBuilder.DropTable(
                name: "user_keys");

            migrationBuilder.DropTable(
                name: "users");
        }
    }
}
