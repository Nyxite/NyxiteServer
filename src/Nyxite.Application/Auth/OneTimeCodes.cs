using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Nyxite.Application.Auth;

/// <summary>
/// Generates and hashes the short codes a person types: emailed codes and backup codes. They have little entropy, so
/// only <c>HMAC-SHA256(HKDF-SHA256(pepper_v, info = "nyxite-one-time-code-v1"), purpose ‖ 0x00 ‖ code)</c> is stored.
/// Without the pepper, which lives outside Postgres, a DB-only leak cannot brute-force them. The purpose keeps a hash of
/// one kind of code from verifying another kind.
/// </summary>
public sealed class OneTimeCodes(IOptions<AuthOptions> options)
{
    public const int EmailCodeDigits = 8;

    /// <summary>Crockford base32 without I, L, O and U, so codes survive being read aloud or handwritten.</summary>
    private const string BackupAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    public const int BackupCodeLength = 10;

    private static readonly byte[] Info = "nyxite-one-time-code-v1"u8.ToArray();
    private readonly VersionedSecret _pepper = VersionedSecret.Parse(options.Value.PasswordPepper, "Auth:PasswordPepper");

    public int CurrentVersion => _pepper.CurrentVersion;

    public static string NewEmailCode() =>
        RandomNumberGenerator.GetInt32(0, (int)Math.Pow(10, EmailCodeDigits)).ToString("D" + EmailCodeDigits);

    /// <summary>A backup code as shown to the person, <c>XXXXX-XXXXX</c> (50 bits).</summary>
    public static string NewBackupCode()
    {
        var chars = RandomNumberGenerator.GetString(BackupAlphabet, BackupCodeLength);
        return chars[..5] + "-" + chars[5..];
    }

    /// <summary>Canonical form of a typed backup code: case, spaces and dashes ignored, Crockford look-alikes mapped.</summary>
    public static string? NormalizeBackupCode(string? code)
    {
        if (code is null) return null;
        var sb = new StringBuilder(BackupCodeLength);
        foreach (var c in code.ToUpperInvariant())
        {
            if (c is '-' or ' ') continue;
            var mapped = c switch { 'O' => '0', 'I' or 'L' => '1', _ => c };
            if (!BackupAlphabet.Contains(mapped)) return null;
            sb.Append(mapped);
        }

        return sb.Length == BackupCodeLength ? sb.ToString() : null;
    }

    public static bool IsEmailCode(string? code) => code is { Length: EmailCodeDigits } && code.All(char.IsAsciiDigit);

    public (byte[] Hash, int Version) Hash(string purpose, string code) =>
        (Mac(_pepper.Current, purpose, code), _pepper.CurrentVersion);

    public bool Verify(string purpose, string? code, byte[] hash, int version)
    {
        if (code is null || !_pepper.TryGet(version, out var pepper)) return false;
        return CryptographicOperations.FixedTimeEquals(Mac(pepper, purpose, code), hash);
    }

    private static byte[] Mac(byte[] pepper, string purpose, string code)
    {
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, pepper, 32, info: Info);
        return HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(purpose + "\0" + code));
    }
}
