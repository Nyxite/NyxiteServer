using System.Security.Claims;
using Nyxite.Domain.Identity;

namespace Nyxite.Application.Auth;

/// <summary>
/// Claim names of the access token (08 §8.2). <c>amr</c> (RFC 8176) marks how the session authenticated; a session
/// without a second factor carries only <c>pwd</c> and is limited to factor enrollment (<c>403 2fa_required</c>).
/// </summary>
public static class AuthClaims
{
    public const string Subject = "sub";
    public const string SessionId = "sid";
    public const string Role = "role";
    public const string Amr = "amr";

    /// <summary>The <c>amr</c> value every full (second-factor-verified) session carries.</summary>
    public const string Mfa = "mfa";

    public const string AccessTokenType = "at+jwt";

    /// <summary>The guest share-session token (08 §8.2). Its own <c>typ</c>, so it is never taken for an access token.</summary>
    public const string GuestTokenType = "nyx-guest+jwt";

    /// <summary>Claims of the guest token: the link share it came through and that share's permission when it was issued.</summary>
    public const string ShareId = "share_id";
    public const string Permission = "perm";

    public static string[] AmrFor(AuthMethod method, bool mfaVerified) => (method, mfaVerified) switch
    {
        (_, false) => ["pwd"],
        (AuthMethod.PasswordTotp or AuthMethod.PasswordEmail or AuthMethod.PasswordBackupCode, true) => ["pwd", "otp", Mfa],
        (AuthMethod.Passkey, true) => ["hwk", "user", Mfa],
        (AuthMethod.Oidc, true) => ["fed", Mfa],
        _ => throw new ArgumentOutOfRangeException(nameof(method)),
    };

    public static Guid UserId(this ClaimsPrincipal principal) =>
        Guid.TryParse(principal.FindFirstValue(Subject), out var id) ? id : throw AuthException.Unauthenticated();

    public static Guid SessionIdOf(this ClaimsPrincipal principal) =>
        Guid.TryParse(principal.FindFirstValue(SessionId), out var id) ? id : throw AuthException.Unauthenticated();

    public static bool HasSecondFactor(this ClaimsPrincipal principal) => principal.HasClaim(Amr, Mfa);

    /// <summary>The link share of a guest principal, or null for an account.</summary>
    public static Guid? GuestShareId(this ClaimsPrincipal principal) =>
        Guid.TryParse(principal.FindFirstValue(ShareId), out var id) ? id : null;
}
