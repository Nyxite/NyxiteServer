using Microsoft.EntityFrameworkCore.Migrations;

namespace Nyxite.Persistence;

/// <summary>
/// Database privileges (03 §3.5, 12 §12.3). Migrations run as a separate migration role that owns every table. The running
/// server connects as a login role that is a member of the NOLOGIN group role <see cref="App"/>, which may read and write
/// ordinary tables but only read and insert the append-only ones, so not even a compromised server can rewrite the audit
/// trail or the key-transparency log.
/// </summary>
public static class DatabaseRoles
{
    public const string App = "nyxite_app";

    /// <summary>
    /// Makes <paramref name="table"/> append-only for the app role. Default privileges grant full DML on every new table,
    /// so each migration that creates an append-only table calls this for it.
    /// </summary>
    public static void AppendOnly(MigrationBuilder migration, string table) =>
        migration.Sql($"REVOKE UPDATE, DELETE, TRUNCATE ON \"{table}\" FROM {App};");
}
