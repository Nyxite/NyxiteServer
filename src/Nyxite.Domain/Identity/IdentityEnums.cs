namespace Nyxite.Domain.Identity;

/// <summary>Bootstrap role of a native account (03 §3.2 <c>users.role</c>); fine-grained access is RBAC.</summary>
public enum UserRole { User, Admin }

/// <summary><c>users.status</c>; <c>Blocked</c> = download-only (12 §12.6).</summary>
public enum UserStatus { Active, Blocked }

/// <summary><c>devices.status</c> (03 §3.2, 08 §8.3).</summary>
public enum DeviceStatus { Pending, Active, Revoked }

/// <summary>Who performed an audited action (03 <c>audit_log.actor_kind</c>).</summary>
public enum ActorKind { User, Admin, Guest, System }

/// <summary>Maps the domain enums to the lower-case text values stored in Postgres CHECK constraints.</summary>
public static class DbValue
{
    public static string Of(UserRole v) => v switch { UserRole.User => "user", UserRole.Admin => "admin", _ => throw new ArgumentOutOfRangeException(nameof(v)) };
    public static string Of(UserStatus v) => v switch { UserStatus.Active => "active", UserStatus.Blocked => "blocked", _ => throw new ArgumentOutOfRangeException(nameof(v)) };
    public static string Of(DeviceStatus v) => v switch { DeviceStatus.Pending => "pending", DeviceStatus.Active => "active", DeviceStatus.Revoked => "revoked", _ => throw new ArgumentOutOfRangeException(nameof(v)) };
    public static string Of(ActorKind v) => v switch { ActorKind.User => "user", ActorKind.Admin => "admin", ActorKind.Guest => "guest", ActorKind.System => "system", _ => throw new ArgumentOutOfRangeException(nameof(v)) };

    public static UserRole ParseRole(string s) => s switch { "user" => UserRole.User, "admin" => UserRole.Admin, _ => throw new FormatException(s) };
    public static UserStatus ParseUserStatus(string s) => s switch { "active" => UserStatus.Active, "blocked" => UserStatus.Blocked, _ => throw new FormatException(s) };
    public static DeviceStatus ParseDeviceStatus(string s) => s switch { "pending" => DeviceStatus.Pending, "active" => DeviceStatus.Active, "revoked" => DeviceStatus.Revoked, _ => throw new FormatException(s) };
    public static ActorKind ParseActorKind(string s) => s switch { "user" => ActorKind.User, "admin" => ActorKind.Admin, "guest" => ActorKind.Guest, "system" => ActorKind.System, _ => throw new FormatException(s) };
}
