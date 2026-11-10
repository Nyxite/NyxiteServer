using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Nyxite.Application.Auth;

/// <summary>
/// Encrypts TOTP secrets at rest (<c>users.totp_secret_enc</c>) with AES-256-GCM under a key derived from the versioned
/// password pepper: <c>HKDF-SHA256(pepper_v, info = "nyxite-totp-secret-v1")</c>. No extra secret is needed, and the
/// secret follows pepper rotation. Layout: <c>pepper_version(u32) ‖ nonce(12) ‖ ciphertext ‖ tag(16)</c>,
/// AAD = <c>"NYXTOTP1" ‖ owner_id(16)</c>, so a ciphertext cannot be moved to another account.
/// </summary>
public sealed class TotpSecretProtector(IOptions<AuthOptions> options)
{
    private static readonly byte[] Info = "nyxite-totp-secret-v1"u8.ToArray();
    private readonly VersionedSecret _pepper = VersionedSecret.Parse(options.Value.PasswordPepper, "Auth:PasswordPepper");

    public int CurrentVersion => _pepper.CurrentVersion;

    public byte[] Protect(ReadOnlySpan<byte> secret, Guid ownerId)
    {
        var output = new byte[4 + 12 + secret.Length + 16];
        BinaryPrimitives.WriteUInt32BigEndian(output, (uint)_pepper.CurrentVersion);
        var nonce = output.AsSpan(4, 12);
        RandomNumberGenerator.Fill(nonce);
        using var gcm = new AesGcm(Key(_pepper.Current), 16);
        gcm.Encrypt(nonce, secret, output.AsSpan(16, secret.Length), output.AsSpan(16 + secret.Length), Aad(ownerId));
        return output;
    }

    public byte[] Unprotect(ReadOnlySpan<byte> data, Guid ownerId)
    {
        if (data.Length < 4 + 12 + 16) throw new CryptographicException("TOTP secret ciphertext too short.");
        var version = (int)BinaryPrimitives.ReadUInt32BigEndian(data);
        if (!_pepper.TryGet(version, out var pepper)) throw new CryptographicException($"Pepper version {version} is not configured.");
        var ctLength = data.Length - 32;
        var secret = new byte[ctLength];
        using var gcm = new AesGcm(Key(pepper), 16);
        gcm.Decrypt(data.Slice(4, 12), data.Slice(16, ctLength), data[^16..], secret, Aad(ownerId));
        return secret;
    }

    public static int VersionOf(ReadOnlySpan<byte> data) => (int)BinaryPrimitives.ReadUInt32BigEndian(data);

    private static byte[] Key(byte[] pepper) => HKDF.DeriveKey(HashAlgorithmName.SHA256, pepper, 32, info: Info);

    private static byte[] Aad(Guid ownerId)
    {
        var aad = new byte[8 + 16];
        Encoding.ASCII.GetBytes("NYXTOTP1", aad);
        ownerId.TryWriteBytes(aad.AsSpan(8), bigEndian: true, out _);
        return aad;
    }
}
