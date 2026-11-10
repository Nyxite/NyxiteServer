using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Nyxite.Persistence.Migrations
{
    /// <summary>
    /// Creates the app group role and its privileges (<see cref="DatabaseRoles"/>). The role is cluster-wide, so creation
    /// tolerates an existing one (another Nyxite database on the same cluster, or a parallel migration).
    /// The migration role needs CREATEROLE for this step.
    /// </summary>
    public partial class AppRoleGrants : Migration
    {
        private const string App = DatabaseRoles.App;

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql($"""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{App}') THEN
                        CREATE ROLE {App} NOLOGIN;
                    END IF;
                EXCEPTION WHEN duplicate_object OR unique_violation THEN
                    NULL;
                END
                $$;
                """);
            migrationBuilder.Sql($"""
                GRANT USAGE ON SCHEMA public TO {App};
                GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {App};
                GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {App};
                ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {App};
                ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {App};
                REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON "__EFMigrationsHistory" FROM {App};
                """);
            DatabaseRoles.AppendOnly(migrationBuilder, "audit_log");
            DatabaseRoles.AppendOnly(migrationBuilder, "kt_leaves");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // The role itself stays: it is cluster-wide and may serve other databases.
            migrationBuilder.Sql($"""
                ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM {App};
                ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE USAGE, SELECT ON SEQUENCES FROM {App};
                REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {App};
                REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {App};
                REVOKE USAGE ON SCHEMA public FROM {App};
                """);
        }
    }
}
