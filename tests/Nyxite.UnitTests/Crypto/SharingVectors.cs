using Nyxite.Crypto;

namespace Nyxite.UnitTests.Crypto;

/// <summary>
/// P2.2-CORE-1: the sharing and rotation protocol fixtures in <c>sharing.json</c>. They pin the share-link URL shape and
/// the link-token hash, the HPKE binding of an object-key wrap, and one request of every share call a client makes,
/// with the responses the server gives, so the four codebases build and parse the same bytes. No request carries the
/// URL fragment or the file key in any form. The rotation part pins the 2.3 contract: the new head is staged under the
/// new key first, the commit names it by content hash in <c>newHeadRef</c>, wraps the new key to every member, the owner
/// included, and re-seals the name; it commits only at generation + 1, otherwise <c>409</c>; an update sealed with the
/// old key passes until the commit and is <c>412</c> after it.
/// </summary>
internal static class SharingVectors
{
    public const string Origin = "https://nyxite.example.org";

    public static readonly Guid OwnerId = Guid.Parse("01890a5d-ac96-774b-bcce-b302099a805d");
    public static readonly Guid GranteeId = Guid.Parse("01890a5d-ac96-774b-bcce-b302099a8059");
    public static readonly Guid FileId = Guid.Parse("01890a5d-ac96-774b-bcce-b302099a8058");
    public static readonly Guid FileKeyId = Guid.Parse("01890a5d-ac96-774b-bcce-b302099a8057");
    public static readonly Guid FolderId = Guid.Parse("01890a5d-ac96-774b-bcce-b302099a805c");
    public static readonly Guid FolderKeyId = Guid.Parse("01890a5d-ac96-774b-bcce-b302099a8060");
    public static readonly Guid ShareId = Guid.Parse("01890a5d-ac96-774b-bcce-b302099a805e");
    public static readonly Guid RotatedKeyId = Guid.Parse("01890a5d-ac96-774b-bcce-b302099a805f");
    public const string CreatedAt = "2026-11-15T12:00:00+00:00";
    public const string ExpiresAt = "2026-12-01T00:00:00+00:00";

    private static byte[] Bytes(int length, int start) => Enumerable.Range(start, length).Select(i => (byte)i).ToArray();
    private static string H(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);
    private static string B(ReadOnlySpan<byte> bytes) => Base64UrlCodec.Encode(bytes);

    public static readonly byte[] TokenBytes = Bytes(32, 0x20);
    public static readonly byte[] FileKey = Bytes(32, 0xc0);
    public static readonly byte[] FolderKey = Bytes(32, 0x60);
    public static readonly byte[] RotatedKey = Bytes(32, 0xe0);
    public static readonly byte[] RotatedHeadPlaintext = "head after rotation"u8.ToArray();

    public static object Build(byte[] granteePublicKey)
    {
        var token = Base64UrlCodec.Encode(TokenBytes);
        var tokenHash = ShareLink.TokenHash(token);
        var url = ShareLink.Url(Origin, token, FileKey);
        var fileWrap = ObjectKeyWrap.SealDerand(granteePublicKey, Bytes(64, 0x40), FileId, FileKeyId, FileKey);
        var folderWrap = ObjectKeyWrap.SealDerand(granteePublicKey, Bytes(64, 0x80), FolderId, FolderKeyId, FolderKey);
        var rotatedWrap = ObjectKeyWrap.SealDerand(granteePublicKey, Bytes(64, 0x10), FileId, RotatedKeyId, RotatedKey);
        // The owner is a member too and gets its own wrap of the new key; its key comes from a second fixed seed.
        var ownerPublicKey = XWing.PublicKeyFromSeed(Bytes(32, 0xa0));
        var ownerRotatedWrap = ObjectKeyWrap.SealDerand(ownerPublicKey, Bytes(64, 0x20), FileId, RotatedKeyId, RotatedKey);
        var rotatedName = NyxcFrame.Seal(RotatedKey, RotatedKeyId, Bytes(12, 0xa0), NyxcFrame.BuildAad(RotatedKeyId, FileId, ObjectKind.Name), "plan.md"u8);
        var rotatedHead = NyxcFrame.Seal(RotatedKey, RotatedKeyId, Bytes(12, 0xb0), NyxcFrame.BuildAad(RotatedKeyId, FileId, ObjectKind.Snapshot),
            RotatedHeadPlaintext);
        var newHeadRef = B(Blake3.Hash(RotatedHeadPlaintext));
        object Wrap(Guid keyId, byte[] wrapped, int generation, Guid? memberId = null) =>
            new { keyId, memberId = memberId ?? GranteeId, ciphertext = B(wrapped), generation, algId = CryptoSuite.HpkeAlgId };
        var idempotency = new Dictionary<string, string> { ["Idempotency-Key"] = "01890a5d-ac96-774b-bcce-b302099a8061" };
        var guestBearer = new Dictionary<string, string> { ["Authorization"] = "Bearer <guestToken>" };
        var shareSession = $"/share/{token}";
        object Problem(int status, string code, string title) => new { type = $"urn:nyxite:problem:{code}", title, status, code };

        return new
        {
            origin = Origin,
            linkToken = new { bytes = H(TokenBytes), token, sha256 = H(tokenHash), linkTokenHash = B(tokenHash) },
            fileId = FileId,
            fileKeyId = FileKeyId,
            fileKey = H(FileKey),
            fragment = ShareLink.FragmentPrefix + B(FileKey),
            shareUrl = url,
            requestPath = ShareLink.RequestPath(url),
            objectKeyWrap = new
            {
                info = "nyxite object key v1",
                aadLayout = "object_id(16) || key_id(16)",
                recipientSeed = H(Bytes(32, 0x90)),
                recipientPublicKey = H(granteePublicKey),
                encapsulationSeed = H(Bytes(64, 0x40)),
                objectId = FileId,
                keyId = FileKeyId,
                aad = H(ObjectKeyWrap.Aad(FileId, FileKeyId)),
                objectKey = H(FileKey),
                wrapped = H(fileWrap),
            },
            requests = new object[]
            {
                new
                {
                    name = "createAccountShare", method = "POST", path = "/api/v1/shares", headers = idempotency,
                    body = new
                    {
                        targetType = "file", targetId = FileId, kind = "user_grant", granteeId = GranteeId, permission = "write",
                        wrappedKeys = new[] { Wrap(FileKeyId, fileWrap, 1) }, linkTokenHash = (string?)null, expiresAt = (string?)null,
                    },
                },
                new
                {
                    name = "createFolderShare", method = "POST", path = "/api/v1/shares", headers = idempotency,
                    body = new
                    {
                        targetType = "folder", targetId = FolderId, kind = "user_grant", granteeId = GranteeId, permission = "read",
                        wrappedKeys = new[] { Wrap(FolderKeyId, folderWrap, 1) }, linkTokenHash = (string?)null, expiresAt = (string?)null,
                    },
                },
                new
                {
                    name = "subtreeBatch", method = "POST", path = "/api/v1/files/keys:batch", headers = new Dictionary<string, string>(),
                    body = new
                    {
                        grants = new object[]
                        {
                            new { fileId = (Guid?)FileId, folderId = (Guid?)null, keyId = FileKeyId, memberId = GranteeId, wrappedKey = B(fileWrap), algId = CryptoSuite.HpkeAlgId },
                            new { fileId = (Guid?)null, folderId = (Guid?)FolderId, keyId = FolderKeyId, memberId = GranteeId, wrappedKey = B(folderWrap), algId = CryptoSuite.HpkeAlgId },
                            new { fileId = (Guid?)FileId, folderId = (Guid?)FolderId, keyId = FileKeyId, memberId = GranteeId, wrappedKey = B(fileWrap), algId = CryptoSuite.HpkeAlgId },
                        },
                    },
                },
                new
                {
                    name = "uploadFileKeys", method = "POST", path = $"/api/v1/files/{FileId}/keys", headers = new Dictionary<string, string>(),
                    body = new { wrappedKeys = new[] { Wrap(FileKeyId, fileWrap, 1) } },
                },
                new
                {
                    name = "createLinkShare", method = "POST", path = "/api/v1/shares", headers = idempotency,
                    body = new
                    {
                        targetType = "file", targetId = FileId, kind = "link", granteeId = (Guid?)null, permission = "write",
                        wrappedKeys = (object[]?)null, linkTokenHash = B(tokenHash), expiresAt = ExpiresAt,
                    },
                },
                new { name = "guestBootstrap", method = "GET", path = shareSession, headers = new Dictionary<string, string>(), body = (object?)null },
                new { name = "guestSession", method = "POST", path = shareSession + "/session", headers = new Dictionary<string, string>(), body = (object?)null },
                new { name = "guestBlob", method = "GET", path = shareSession + "/blob", headers = guestBearer, body = (object?)null },
                new { name = "guestSocketTicket", method = "POST", path = shareSession + "/socket-ticket", headers = guestBearer, body = (object?)null },
                new { name = "guestRelay", method = "GET", path = shareSession + "/ws?access_token=<ticket>", headers = new Dictionary<string, string>(), body = (object?)null },
                new
                {
                    name = "stageRotationHead", method = "PUT", path = $"/api/v1/files/{FileId}/keys/rotate/head",
                    headers = new Dictionary<string, string>
                    {
                        ["Nyxite-Key-Id"] = RotatedKeyId.ToString(), ["Nyxite-Content-Hash"] = newHeadRef, ["Nyxite-Snapshot-Seq"] = "7",
                    },
                    body = (object?)null,
                    bodyHex = H(rotatedHead),
                },
                new
                {
                    name = "rotate", method = "POST", path = $"/api/v1/files/{FileId}/keys/rotate", headers = idempotency,
                    body = new
                    {
                        newKeyId = RotatedKeyId, generation = 2,
                        wrappedKeys = new[] { Wrap(RotatedKeyId, rotatedWrap, 2), Wrap(RotatedKeyId, ownerRotatedWrap, 2, OwnerId) },
                        newHeadRef, nameEnc = B(rotatedName), metadataEnc = (string?)null,
                    },
                },
            },
            responses = new object[]
            {
                new
                {
                    name = "linkShareCreated", method = "POST", path = "/api/v1/shares", status = 201,
                    body = new
                    {
                        id = ShareId, targetType = "file", targetId = FileId, kind = "link", granteeId = (Guid?)null, permission = "write",
                        createdBy = OwnerId, expiresAt = ExpiresAt, createdAt = CreatedAt,
                    },
                },
                new
                {
                    name = "subtreeBatchResults", method = "POST", path = "/api/v1/files/keys:batch", status = 200,
                    body = new
                    {
                        results = new object[]
                        {
                            new { fileId = (Guid?)FileId, folderId = (Guid?)null, status = "applied", error = (string?)null },
                            new { fileId = (Guid?)null, folderId = (Guid?)FolderId, status = "applied", error = (string?)null },
                            new { fileId = (Guid?)FileId, folderId = (Guid?)FolderId, status = "rejected", error = (string?)"validation_failed" },
                        },
                    },
                },
                new { name = "unknownLink", method = "GET", path = $"/share/{Base64UrlCodec.Encode(new byte[32])}", status = 404, body = Problem(404, "not_found", "Not found.") },
                new { name = "revokedLink", method = "GET", path = shareSession, status = 410, body = Problem(410, "share_revoked", "This link was revoked.") },
                new { name = "expiredLink", method = "POST", path = shareSession + "/session", status = 410, body = Problem(410, "link_expired", "This link has expired.") },
                new { name = "rotationHeadStaged", method = "PUT", path = $"/api/v1/files/{FileId}/keys/rotate/head", status = 204, body = (object?)null },
                new
                {
                    name = "rotationHeadMoved", method = "POST", path = $"/api/v1/files/{FileId}/keys/rotate", status = 409,
                    body = Problem(409, "version_conflict", "The head changed since the rotated head was based on it; stage it again."),
                },
                new { name = "rotationCommitted", method = "POST", path = $"/api/v1/files/{FileId}/keys/rotate", status = 204, body = (object?)null },
                new
                {
                    name = "rotationLost", method = "POST", path = $"/api/v1/files/{FileId}/keys/rotate", status = 409,
                    body = Problem(409, "conflict", "Another rotation committed first."),
                },
                new
                {
                    name = "staleUpdateAfterCommit", method = "POST", path = $"/api/v1/files/{FileId}/crdt/log", status = 412,
                    body = Problem(412, "key_generation_stale", "The content is sealed with a key that is not the file's current key."),
                },
            },
            rotation = new
            {
                currentGeneration = 1,
                cases = new object[]
                {
                    new { submittedGeneration = 2, status = 204, code = (string?)null },
                    new { submittedGeneration = 1, status = 409, code = (string?)"conflict" },
                    new { submittedGeneration = 3, status = 409, code = (string?)"conflict" },
                },
                oldKeyUpdate = new { beforeCommit = 200, afterCommit = 412, code = "key_generation_stale" },
                order = new[] { "stageRotationHead", "rotate" },
                newHeadRef = "The base64url BLAKE3-256 content hash of the plaintext head staged under newKeyId with PUT /files/{id}/keys/rotate/head "
                             + "(its Nyxite-Content-Hash); null only when the file has no head. The commit makes the staged head the head.",
                ownerRecipientSeed = H(Bytes(32, 0xa0)),
                rotatedKey = H(RotatedKey),
                rotatedHeadPlaintext = H(RotatedHeadPlaintext),
                members = new[] { GranteeId, OwnerId },
            },
            guestToken = new
            {
                typ = "nyx-guest+jwt",
                alg = "HS256",
                claims = new[] { "iss", "aud", "sub", "share_id", "perm", "iat", "exp", "jti" },
                subject = "share:{shareId}",
                lifetimeSeconds = 900,
                socketTicketLifetimeSeconds = 60,
                relayTransports = new[] { "WebSockets" },
            },
        };
    }
}
