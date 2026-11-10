using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Nyxite.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Structure : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "projects",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    owner_id = table.Column<Guid>(type: "uuid", nullable: false),
                    name_enc = table.Column<byte[]>(type: "bytea", nullable: false),
                    metadata_enc = table.Column<byte[]>(type: "bytea", nullable: true),
                    sync_policy = table.Column<string>(type: "text", nullable: false, defaultValueSql: "'server-default'"),
                    key_generation = table.Column<int>(type: "integer", nullable: false, defaultValue: 1),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    deleted_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_projects", x => x.id);
                    table.CheckConstraint("ck_projects_sync_policy", "sync_policy IN ('server-default','excluded')");
                    table.ForeignKey(
                        name: "FK_projects_users_owner_id",
                        column: x => x.owner_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "folders",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    project_id = table.Column<Guid>(type: "uuid", nullable: false),
                    parent_folder_id = table.Column<Guid>(type: "uuid", nullable: true),
                    name_enc = table.Column<byte[]>(type: "bytea", nullable: false),
                    metadata_enc = table.Column<byte[]>(type: "bytea", nullable: true),
                    sync_policy = table.Column<string>(type: "text", nullable: true),
                    key_generation = table.Column<int>(type: "integer", nullable: false, defaultValue: 1),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    deleted_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_folders", x => x.id);
                    table.CheckConstraint("ck_folders_not_own_parent", "parent_folder_id IS NULL OR parent_folder_id <> id");
                    table.CheckConstraint("ck_folders_sync_policy", "sync_policy IS NULL OR sync_policy IN ('server-default','excluded')");
                    table.ForeignKey(
                        name: "FK_folders_folders_parent_folder_id",
                        column: x => x.parent_folder_id,
                        principalTable: "folders",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_folders_projects_project_id",
                        column: x => x.project_id,
                        principalTable: "projects",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "files",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    project_id = table.Column<Guid>(type: "uuid", nullable: false),
                    folder_id = table.Column<Guid>(type: "uuid", nullable: true),
                    owner_id = table.Column<Guid>(type: "uuid", nullable: false),
                    name_enc = table.Column<byte[]>(type: "bytea", nullable: false),
                    content_type = table.Column<string>(type: "text", nullable: false),
                    sync_policy = table.Column<string>(type: "text", nullable: false, defaultValueSql: "'server-default'"),
                    current_version_id = table.Column<Guid>(type: "uuid", nullable: true),
                    crdt_doc_id = table.Column<Guid>(type: "uuid", nullable: true),
                    key_generation = table.Column<int>(type: "integer", nullable: false, defaultValue: 1),
                    metadata_enc = table.Column<byte[]>(type: "bytea", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    deleted_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_files", x => x.id);
                    table.CheckConstraint("ck_files_content_type", "content_type IN ('markdown','plaintext','ink','office','sourcecode','image','binary')");
                    table.CheckConstraint("ck_files_sync_policy", "sync_policy IN ('server-default','excluded')");
                    table.ForeignKey(
                        name: "FK_files_folders_folder_id",
                        column: x => x.folder_id,
                        principalTable: "folders",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_files_projects_project_id",
                        column: x => x.project_id,
                        principalTable: "projects",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_files_users_owner_id",
                        column: x => x.owner_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "structure_keys",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    project_id = table.Column<Guid>(type: "uuid", nullable: true),
                    folder_id = table.Column<Guid>(type: "uuid", nullable: true),
                    member_id = table.Column<Guid>(type: "uuid", nullable: true),
                    share_id = table.Column<Guid>(type: "uuid", nullable: true),
                    key_id = table.Column<Guid>(type: "uuid", nullable: false),
                    wrapped_key = table.Column<byte[]>(type: "bytea", nullable: false),
                    generation = table.Column<int>(type: "integer", nullable: false, defaultValue: 1),
                    alg_id = table.Column<string>(type: "text", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_structure_keys", x => x.id);
                    table.CheckConstraint("ck_structure_keys_member_xor_share", "(member_id IS NOT NULL) <> (share_id IS NOT NULL)");
                    table.CheckConstraint("ck_structure_keys_one_target", "(project_id IS NOT NULL) <> (folder_id IS NOT NULL)");
                    table.ForeignKey(
                        name: "FK_structure_keys_folders_folder_id",
                        column: x => x.folder_id,
                        principalTable: "folders",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_structure_keys_projects_project_id",
                        column: x => x.project_id,
                        principalTable: "projects",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_structure_keys_users_member_id",
                        column: x => x.member_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "file_keys",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    file_id = table.Column<Guid>(type: "uuid", nullable: false),
                    member_id = table.Column<Guid>(type: "uuid", nullable: true),
                    share_id = table.Column<Guid>(type: "uuid", nullable: true),
                    key_id = table.Column<Guid>(type: "uuid", nullable: false),
                    wrapped_key = table.Column<byte[]>(type: "bytea", nullable: false),
                    generation = table.Column<int>(type: "integer", nullable: false, defaultValue: 1),
                    alg_id = table.Column<string>(type: "text", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false, defaultValueSql: "now()"),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_file_keys", x => x.id);
                    table.CheckConstraint("ck_file_keys_member_xor_share", "(member_id IS NOT NULL) <> (share_id IS NOT NULL)");
                    table.ForeignKey(
                        name: "FK_file_keys_files_file_id",
                        column: x => x.file_id,
                        principalTable: "files",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_file_keys_users_member_id",
                        column: x => x.member_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "ix_file_keys_member_live",
                table: "file_keys",
                column: "member_id",
                filter: "revoked_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "uq_file_keys_member",
                table: "file_keys",
                columns: new[] { "file_id", "key_id", "member_id" },
                unique: true,
                filter: "member_id IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "uq_file_keys_share",
                table: "file_keys",
                columns: new[] { "file_id", "key_id", "share_id" },
                unique: true,
                filter: "share_id IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ix_files_folder",
                table: "files",
                column: "folder_id",
                filter: "deleted_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "ix_files_owner",
                table: "files",
                column: "owner_id",
                filter: "deleted_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "ix_files_project",
                table: "files",
                column: "project_id",
                filter: "deleted_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "ix_folders_parent",
                table: "folders",
                column: "parent_folder_id",
                filter: "deleted_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "ix_folders_project",
                table: "folders",
                column: "project_id",
                filter: "deleted_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "ix_projects_owner",
                table: "projects",
                column: "owner_id",
                filter: "deleted_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "ix_structure_keys_member_live",
                table: "structure_keys",
                column: "member_id",
                filter: "revoked_at IS NULL");

            migrationBuilder.CreateIndex(
                name: "uq_structure_keys_folder_member",
                table: "structure_keys",
                columns: new[] { "folder_id", "key_id", "member_id" },
                unique: true,
                filter: "folder_id IS NOT NULL AND member_id IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "uq_structure_keys_project_member",
                table: "structure_keys",
                columns: new[] { "project_id", "key_id", "member_id" },
                unique: true,
                filter: "project_id IS NOT NULL AND member_id IS NOT NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "file_keys");

            migrationBuilder.DropTable(
                name: "structure_keys");

            migrationBuilder.DropTable(
                name: "files");

            migrationBuilder.DropTable(
                name: "folders");

            migrationBuilder.DropTable(
                name: "projects");
        }
    }
}
