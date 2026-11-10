using System.Net;
using System.Text.Json;
using Nyxite.Application.Diagnostics;
using Nyxite.Domain.Identity;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Audit;

/// <summary>Request facts recorded with sessions and audit events.</summary>
public sealed record RequestInfo(IPAddress? Ip, string? UserAgent)
{
    public static readonly RequestInfo None = new(null, null);
}

/// <summary>
/// Appends <c>audit_log</c> rows (12). The row is added to the caller's unit of work, so an event commits or rolls back
/// together with the change it records. Details never contain secrets, emails or content.
/// </summary>
public sealed class AuditWriter(NyxiteDbContext db, TimeProvider time)
{
    public void Add(string action, Guid? actorId, RequestInfo request, ActorKind kind = ActorKind.User,
        string? targetType = null, Guid? targetId = null, object? detail = null)
    {
        NyxiteMetrics.AuditEvents.Add(1, new KeyValuePair<string, object?>("action", action));
        db.AuditLog.Add(new AuditLogEntity
        {
            OccurredAt = time.GetUtcNow(),
            ActorId = actorId,
            ActorKind = kind,
            Action = action,
            TargetType = targetType,
            TargetId = targetId,
            Detail = detail is null ? "{}" : JsonSerializer.Serialize(detail, JsonSerializerOptions.Web),
            Ip = request.Ip,
            UserAgent = Truncate(request.UserAgent),
        });
    }

    internal static string? Truncate(string? ua) => ua is { Length: > 512 } ? ua[..512] : ua;
}
