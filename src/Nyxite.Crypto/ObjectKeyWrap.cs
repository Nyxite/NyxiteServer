namespace Nyxite.Crypto;

/// <summary>
/// How a client wraps the key of a file, folder or project to one member with hybrid HPKE (07 §7.3, P2.2-CORE-1):
/// <c>info = "nyxite object key v1"</c>, <c>aad = object_id(16) ‖ key_id(16)</c>, UUIDs in RFC 9562 byte order, and the
/// 32-byte key as plaintext. The AAD binds a wrap to its object and its key generation, so a server cannot hand a member
/// one object's wrap as another's, or an old generation's as the current one. The server stores the result as opaque
/// bytes and never calls this; account shares, the subtree batch and rotation all wrap the same way.
/// </summary>
public static class ObjectKeyWrap
{
    public static ReadOnlySpan<byte> Info => "nyxite object key v1"u8;

    public static byte[] Aad(Guid objectId, Guid keyId)
    {
        var aad = new byte[32];
        objectId.TryWriteBytes(aad, bigEndian: true, out _);
        keyId.TryWriteBytes(aad.AsSpan(16), bigEndian: true, out _);
        return aad;
    }

    public static byte[] Seal(ReadOnlySpan<byte> recipientPublicKey, Guid objectId, Guid keyId, ReadOnlySpan<byte> objectKey) =>
        HybridHpke.Seal(recipientPublicKey, Info, Aad(objectId, keyId), objectKey);

    /// <summary>Deterministic, for conformance vectors only.</summary>
    public static byte[] SealDerand(ReadOnlySpan<byte> recipientPublicKey, ReadOnlySpan<byte> eseed, Guid objectId, Guid keyId, ReadOnlySpan<byte> objectKey) =>
        HybridHpke.SealDerand(recipientPublicKey, eseed, Info, Aad(objectId, keyId), objectKey);

    public static byte[] Open(ReadOnlySpan<byte> recipientSeed, Guid objectId, Guid keyId, ReadOnlySpan<byte> wrapped) =>
        HybridHpke.Open(recipientSeed, Info, Aad(objectId, keyId), wrapped);
}

/// <summary>
/// The link share's URL (09 §9.4, P2.2-CORE-1): <c>{origin}/share/{token}#k={base64url(fileKey)}</c>. The token is 32
/// random bytes as 43 base64url characters; the server stores and compares only <c>SHA-256(ASCII(token))</c>. Everything
/// after <c>#</c> is the fragment, which a browser never sends, so the file key never reaches the server.
/// </summary>
public static class ShareLink
{
    public const int TokenBytes = 32;
    public const string FragmentPrefix = "k=";

    public static string NewToken() => Base64UrlCodec.Encode(System.Security.Cryptography.RandomNumberGenerator.GetBytes(TokenBytes));

    public static byte[] TokenHash(string token) => System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(token));

    public static string Url(string origin, string token, ReadOnlySpan<byte> fileKey) =>
        $"{origin.TrimEnd('/')}/share/{token}#{FragmentPrefix}{Base64UrlCodec.Encode(fileKey)}";

    /// <summary>The path a client requests for a share URL: the fragment cut off, as a browser does.</summary>
    public static string RequestPath(string url) => new Uri(url.Split('#')[0]).AbsolutePath;

    /// <summary>The token and the file key of a share URL, parsed locally; false when it is not one.</summary>
    public static bool TryParse(string url, out string token, out byte[] fileKey)
    {
        token = "";
        fileKey = [];
        var hash = url.IndexOf('#');
        if (hash < 0 || !Uri.TryCreate(url[..hash], UriKind.Absolute, out var uri)) return false;
        var segments = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var fragment = url[(hash + 1)..];
        if (segments is not ["share", var t] || !fragment.StartsWith(FragmentPrefix, StringComparison.Ordinal)) return false;
        if (!Base64UrlCodec.TryDecode(t, out var tokenBytes) || tokenBytes.Length != TokenBytes) return false;
        if (!Base64UrlCodec.TryDecode(fragment[FragmentPrefix.Length..], out var key) || key.Length != 32) return false;
        token = t;
        fileKey = key;
        return true;
    }
}
