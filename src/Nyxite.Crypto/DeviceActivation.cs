using System.Security.Cryptography;

namespace Nyxite.Crypto;

/// <summary>
/// The message a device signs with the user's identity key to activate itself without an approval (first device,
/// recovery-phrase restore; server 04 <c>POST /devices/{id}/activate</c>):
/// <c>"NYXDEV-ACTIVATE-v1" ‖ user_id(16) ‖ device_id(16) ‖ key_id(16) ‖ SHA-256(device pubkey)(32)</c>,
/// UUIDs in RFC 9562 byte order.
/// </summary>
public static class DeviceActivation
{
    public static ReadOnlySpan<byte> Domain => "NYXDEV-ACTIVATE-v1"u8;

    public static byte[] SignedMessage(Guid userId, Guid deviceId, Guid keyId, ReadOnlySpan<byte> devicePubkey)
    {
        var buffer = new byte[Domain.Length + 16 + 16 + 16 + 32];
        var s = buffer.AsSpan();
        var o = 0;
        Domain.CopyTo(s); o += Domain.Length;
        userId.TryWriteBytes(s.Slice(o, 16), bigEndian: true, out _); o += 16;
        deviceId.TryWriteBytes(s.Slice(o, 16), bigEndian: true, out _); o += 16;
        keyId.TryWriteBytes(s.Slice(o, 16), bigEndian: true, out _); o += 16;
        SHA256.HashData(devicePubkey, s[o..]);
        return buffer;
    }
}
