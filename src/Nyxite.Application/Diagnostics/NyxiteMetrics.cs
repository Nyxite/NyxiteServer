using System.Diagnostics.Metrics;

namespace Nyxite.Application.Diagnostics;

/// <summary>
/// The server's own metrics (14 §14.5), exposed at <c>/metrics</c>. They count events only: no user id, email, IP or
/// anything content-derived is ever a tag.
/// </summary>
public static class NyxiteMetrics
{
    public const string MeterName = "Nyxite";

    private static readonly Meter Meter = new(MeterName);

    /// <summary>Audit events by <c>action</c>, for example <c>auth.login_failed</c>.</summary>
    public static readonly Counter<long> AuditEvents = Meter.CreateCounter<long>("nyxite.audit.events");

    public static readonly Counter<long> EmailsSent = Meter.CreateCounter<long>("nyxite.email.sent");
    public static readonly Counter<long> EmailsFailed = Meter.CreateCounter<long>("nyxite.email.failed");

    /// <summary>Rows removed by the maintenance job, by <c>table</c>.</summary>
    public static readonly Counter<long> RowsCleaned = Meter.CreateCounter<long>("nyxite.maintenance.rows_deleted");
}
