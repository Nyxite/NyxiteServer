using System.Security.Cryptography;
using OtpNet;

namespace Nyxite.Application.Auth;

/// <summary>
/// RFC 6238 TOTP: SHA-1, 6 digits, 30 s steps, ±1 step tolerance for clock drift. This class only checks the math; the
/// one-use-per-step rule of RFC 6238 §5.2 is enforced against <c>users.totp_last_step</c> by <see cref="SecondFactors"/>.
/// </summary>
public sealed class TotpCodes(TimeProvider time)
{
    public const int SecretBytes = 20;

    public static byte[] NewSecret() => RandomNumberGenerator.GetBytes(SecretBytes);

    public static string Base32(byte[] secret) => Base32Encoding.ToString(secret).TrimEnd('=');

    public bool Verify(byte[] secret, string? code) => Verify(secret, code, out _);

    /// <summary>Checks a code and returns the time step it matched.</summary>
    public bool Verify(byte[] secret, string? code, out long step)
    {
        step = 0;
        if (code is null || code.Length != 6 || !code.All(char.IsAsciiDigit)) return false;
        var totp = new Totp(secret);
        return totp.VerifyTotp(time.GetUtcNow().UtcDateTime, code, out step, VerificationWindow.RfcSpecifiedNetworkDelay);
    }

    /// <summary>The current code, for tests and tooling.</summary>
    public string Compute(byte[] secret) => new Totp(secret).ComputeTotp(time.GetUtcNow().UtcDateTime);

    public static string OtpAuthUri(string issuer, string account, byte[] secret) =>
        $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}" +
        $"?secret={Base32(secret)}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits=6&period=30";
}
