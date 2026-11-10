namespace Nyxite.Domain.Identity;

/// <summary><c>sessions.client_kind</c> (03 §3.2), sent by the client as <c>clientKind</c> on every sign-in call.</summary>
public enum ClientKind { Desktop, Android, Web, Admin }

/// <summary><c>sessions.auth_method</c> (03 §3.2).</summary>
public enum AuthMethod { PasswordTotp, Passkey, Oidc, PasswordEmail, PasswordBackupCode }

/// <summary><c>sessions.revoke_reason</c> (03 §3.2).</summary>
public enum RevokeReason { Logout, Admin, DeviceRevoked, UserBlocked, CredentialChange, ReuseDetected }

/// <summary>
/// <c>ephemeral_tokens.kind</c> (03 §3.2), including the passkey-challenge, pending-TOTP, emailed-code and step-up kinds.
/// </summary>
public enum EphemeralTokenKind
{
    Mfa, SocketTicket, PasswordReset, Invite, OidcState, OidcHandoff, WebauthnChallenge, TotpEnroll, EmailVerify, EmailCode, StepUp,
}

/// <summary>Lower-case wire/DB text values of the auth enums.</summary>
public static class AuthDbValue
{
    public static string Of(ClientKind v) => v switch
    {
        ClientKind.Desktop => "desktop", ClientKind.Android => "android", ClientKind.Web => "web", ClientKind.Admin => "admin",
        _ => throw new ArgumentOutOfRangeException(nameof(v)),
    };

    public static string Of(AuthMethod v) => v switch
    {
        AuthMethod.PasswordTotp => "password_totp", AuthMethod.Passkey => "passkey", AuthMethod.Oidc => "oidc",
        AuthMethod.PasswordEmail => "password_email", AuthMethod.PasswordBackupCode => "password_backup_code",
        _ => throw new ArgumentOutOfRangeException(nameof(v)),
    };

    public static string Of(RevokeReason v) => v switch
    {
        RevokeReason.Logout => "logout", RevokeReason.Admin => "admin", RevokeReason.DeviceRevoked => "device_revoked",
        RevokeReason.UserBlocked => "user_blocked", RevokeReason.CredentialChange => "credential_change",
        RevokeReason.ReuseDetected => "reuse_detected",
        _ => throw new ArgumentOutOfRangeException(nameof(v)),
    };

    public static string Of(EphemeralTokenKind v) => v switch
    {
        EphemeralTokenKind.Mfa => "mfa", EphemeralTokenKind.SocketTicket => "socket_ticket",
        EphemeralTokenKind.PasswordReset => "password_reset", EphemeralTokenKind.Invite => "invite",
        EphemeralTokenKind.OidcState => "oidc_state", EphemeralTokenKind.OidcHandoff => "oidc_handoff",
        EphemeralTokenKind.WebauthnChallenge => "webauthn_challenge", EphemeralTokenKind.TotpEnroll => "totp_enroll",
        EphemeralTokenKind.EmailVerify => "email_verify", EphemeralTokenKind.EmailCode => "email_code",
        EphemeralTokenKind.StepUp => "step_up",
        _ => throw new ArgumentOutOfRangeException(nameof(v)),
    };

    public static bool TryParseClientKind(string? s, out ClientKind kind)
    {
        foreach (var k in Enum.GetValues<ClientKind>())
        {
            if (Of(k) == s) { kind = k; return true; }
        }

        kind = default;
        return false;
    }

    public static ClientKind ParseClientKind(string s) => TryParseClientKind(s, out var k) ? k : throw new FormatException(s);
    public static AuthMethod ParseAuthMethod(string s) => Parse<AuthMethod>(s, Of);
    public static RevokeReason ParseRevokeReason(string s) => Parse<RevokeReason>(s, Of);
    public static EphemeralTokenKind ParseEphemeralTokenKind(string s) => Parse<EphemeralTokenKind>(s, Of);

    private static T Parse<T>(string s, Func<T, string> of) where T : struct, Enum
    {
        foreach (var v in Enum.GetValues<T>())
        {
            if (of(v) == s) return v;
        }

        throw new FormatException(s);
    }
}
