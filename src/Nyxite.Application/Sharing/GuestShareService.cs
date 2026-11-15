using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Nyxite.Application.Audit;
using Nyxite.Application.Auth;
using Nyxite.Contracts.Auth;
using Nyxite.Contracts.Sharing;
using Nyxite.Crypto;
using Nyxite.Domain.Identity;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Sharing;

/// <summary>
/// The public side of link shares (server 04 §4.8, 05 §5.8, 08 §8.2): a visitor presents the link token from the URL
/// path and gets a 15-minute guest token for the relay and the ciphertext, never a key, because its key is the URL
/// fragment that never reaches the server. Only the token's SHA-256 is stored and compared. A token that was never
/// issued is <c>404</c>; one that was issued but is revoked or expired is <c>410</c>, since presenting it already shows
/// the holder knew it (13 §13.6a). The guest token is not stored; every renewal and every relay connection re-checks
/// the share row, and the relay's periodic re-check cuts a live guest off once the share ends.
/// </summary>
public sealed class GuestShareService(
    NyxiteDbContext db, GuestTokenService tokens, IEphemeralTokenStore ephemeral, AuditWriter audit, TimeProvider time, IOptions<AuthOptions> options)
{
    /// <summary>A link token is 32 random bytes, base64url without padding: 43 characters (09 §9.8, at least 128 bits).</summary>
    public const int TokenBytes = 32;

    public const int TokenLength = 43;

    /// <summary><c>link_token_hash</c>: SHA-256 of the token's ASCII characters, the hashing of every other token here (03 §3.2).</summary>
    public static byte[] TokenHash(string token) => ShareLink.TokenHash(token);

    public static bool IsWellFormed(string? token) =>
        token is { Length: TokenLength } && Base64UrlCodec.TryDecode(token, out var bytes) && bytes.Length == TokenBytes;

    /// <summary>The live link share a token names.</summary>
    public async Task<ShareEntity> ResolveAsync(string token, CancellationToken ct)
    {
        if (!IsWellFormed(token)) throw AuthException.NotFound();
        var hash = TokenHash(token);
        var share = await db.Shares.AsNoTracking().SingleOrDefaultAsync(s => s.LinkTokenHash == hash && s.Kind == ShareEntity.Link, ct)
                    ?? throw AuthException.NotFound();
        EnsureLive(share);
        return share;
    }

    /// <summary>
    /// Guest bootstrap: what the shared file is, sealed as it is, and a fresh guest token. Audited as a link access. A
    /// link a rotation kept is answered in its frozen generation: the name, metadata, key and head its fragment key opens,
    /// read only, so a kept link never looks live while serving ciphertext it cannot decrypt (09 §9.6).
    /// </summary>
    public async Task<ShareBootstrapDto> BootstrapAsync(string token, RequestInfo request, CancellationToken ct)
    {
        var share = await ResolveAsync(token, ct);
        var file = await FileAsync(share, ct);
        var generation = share.FrozenGeneration ?? file.KeyGeneration;
        var keyId = await db.FileKeys.AsNoTracking().Where(k => k.FileId == file.Id && k.Generation == generation).Select(k => k.KeyId).FirstAsync(ct);
        long? head = share.FrozenGeneration is not null
            ? share.FrozenVersionSeq
            : file.CurrentVersionId is { } versionId
                ? await db.FileVersions.AsNoTracking().Where(v => v.Id == versionId).Select(v => (long?)v.Seq).SingleAsync(ct)
                : null;
        var nameEnc = share.FrozenNameEnc ?? file.NameEnc;
        var metadataEnc = share.FrozenGeneration is not null ? share.FrozenMetadataEnc : file.MetadataEnc;
        var permission = Permission(share);
        var (guestToken, expires) = tokens.Issue(share.Id, permission);
        audit.Add("share.link_access", null, request, ActorKind.Guest, "share", share.Id, new { via = "bootstrap" });
        await db.SaveChangesAsync(ct);
        return new ShareBootstrapDto(guestToken, expires, permission, StructureTypes.File, file.Id, share.ExpiresAt,
            new GuestFileDto(file.Id, file.ContentType, Base64UrlCodec.Encode(nameEnc), metadataEnc is null ? null : Base64UrlCodec.Encode(metadataEnc),
                keyId, generation, head, file.CrdtDocId, share.FrozenGeneration is not null));
    }

    /// <summary>The permission a guest of the share gets: a frozen link is read only, whatever it was created with.</summary>
    public static string Permission(ShareEntity share) => share.FrozenGeneration is not null ? ShareEntity.Read : share.Permission;

    /// <summary>Issues or renews the guest token. A revoked or expired share stops renewals at once (<c>410</c>).</summary>
    public async Task<GuestSessionDto> SessionAsync(string token, RequestInfo request, CancellationToken ct)
    {
        var share = await ResolveAsync(token, ct);
        var file = await FileAsync(share, ct);
        var permission = Permission(share);
        var (guestToken, expires) = tokens.Issue(share.Id, permission);
        audit.Add("auth.guest_session", null, request, ActorKind.Guest, "share", share.Id);
        await db.SaveChangesAsync(ct);
        return new GuestSessionDto(guestToken, expires, permission, StructureTypes.File, file.Id);
    }

    /// <summary>Records a guest's ciphertext fetch: the share and the request, never a key (09 §9.7).</summary>
    public async Task RecordBlobAccessAsync(Guid shareId, RequestInfo request, CancellationToken ct)
    {
        audit.Add("share.link_access", null, request, ActorKind.Guest, "share", shareId, new { via = "blob" });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// True when <paramref name="token"/> from the request path names the share of the guest token, so a guest token is
    /// only ever good on its own link's paths.
    /// </summary>
    public async Task<bool> PathMatchesAsync(string? token, Guid shareId, CancellationToken ct)
    {
        if (!IsWellFormed(token)) return false;
        var hash = TokenHash(token!);
        return await db.Shares.AsNoTracking().AnyAsync(s => s.Id == shareId && s.LinkTokenHash == hash, ct);
    }

    /// <summary>The share of a guest principal, which must still be live: <c>410</c> otherwise.</summary>
    public async Task<ShareEntity> LiveShareAsync(Guid shareId, CancellationToken ct)
    {
        var share = await db.Shares.AsNoTracking().SingleOrDefaultAsync(s => s.Id == shareId && s.Kind == ShareEntity.Link, ct) ?? throw AuthException.NotFound();
        EnsureLive(share);
        return share;
    }

    /// <summary>
    /// The shares whose guests have no business in a relay room any more, each with the code that ends the connection:
    /// <c>share_revoked</c>, <c>link_expired</c> (purged shares count as revoked), or <c>link_frozen</c> for a link a
    /// rotation kept, because nothing in the room opens with its key. Live shares are left out.
    /// </summary>
    public async Task<Dictionary<Guid, string>> EndedAsync(IReadOnlyCollection<Guid> shareIds, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var rows = await db.Shares.AsNoTracking().Where(s => shareIds.Contains(s.Id))
            .Select(s => new { s.Id, s.RevokedAt, s.ExpiresAt, s.FrozenGeneration }).ToListAsync(ct);
        var ended = shareIds.ToDictionary(id => id, _ => SharesRevoked);
        foreach (var row in rows)
        {
            if (row.RevokedAt is not null) continue;
            if (row.ExpiresAt is { } e && e <= now) ended[row.Id] = LinkExpired;
            else if (row.FrozenGeneration is not null) ended[row.Id] = LinkFrozen;
            else ended.Remove(row.Id);
        }

        return ended;
    }

    public const string SharesRevoked = "share_revoked";
    public const string LinkExpired = "link_expired";
    public const string LinkFrozen = "link_frozen";

    /// <summary>A frozen link has no relay room: what the room carries is sealed with keys its fragment does not hold.</summary>
    public static AuthException Frozen() => new(409, LinkFrozen, "This link was kept through a key rotation; it opens its frozen content only.");

    /// <summary>
    /// The version a guest's blob request reads: the frozen head for a link a rotation kept, otherwise null for the
    /// file's current head. A frozen link of a file that had no head, or whose head was purged since, has nothing.
    /// </summary>
    public static long? FrozenHead(ShareEntity share) => share.FrozenGeneration is null ? null : share.FrozenVersionSeq ?? 0;

    /// <summary>
    /// A single-use 60-second relay socket ticket for a guest (08 §8.4), so a browser puts no reusable credential into
    /// the upgrade URL. Bound to the share instead of a session; only its hash is stored.
    /// </summary>
    public async Task<SocketTicketDto> IssueTicketAsync(Guid shareId, CancellationToken ct)
    {
        if ((await LiveShareAsync(shareId, ct)).FrozenGeneration is not null) throw Frozen();
        var lifetime = options.Value.Lifetimes.SocketTicket;
        var expires = time.GetUtcNow() + lifetime;
        var ticket = await ephemeral.IssueAsync(EphemeralTokenKind.GuestSocketTicket, null, null, lifetime,
            JsonSerializer.Serialize(new { shareId }), ct);
        return new SocketTicketDto(ticket, expires);
    }

    /// <summary>
    /// Turns a guest socket ticket into a guest token for the connection, or null when it is unknown, used, expired or
    /// its share ended. <paramref name="consume"/> false only checks it, for SignalR's negotiate request.
    /// </summary>
    public async Task<string?> RedeemTicketAsync(string ticket, bool consume, CancellationToken ct)
    {
        var hash = IEphemeralTokenStore.Hash(ticket);
        var row = consume
            ? await ephemeral.ConsumeAsync(EphemeralTokenKind.GuestSocketTicket, hash, ct)
            : await ephemeral.FindLiveAsync(EphemeralTokenKind.GuestSocketTicket, hash, ct);
        if (row?.Detail is not { } detail) return null;
        using var json = JsonDocument.Parse(detail);
        if (!json.RootElement.TryGetProperty("shareId", out var id) || !id.TryGetGuid(out var shareId)) return null;
        var now = time.GetUtcNow();
        var share = await db.Shares.AsNoTracking()
            .SingleOrDefaultAsync(s => s.Id == shareId && s.RevokedAt == null && (s.ExpiresAt == null || s.ExpiresAt > now), ct);
        return share is null || share.FrozenGeneration is not null ? null : tokens.Issue(share.Id, share.Permission).Token;
    }

    private void EnsureLive(ShareEntity share)
    {
        if (share.RevokedAt is not null) throw new AuthException(410, SharesRevoked, "This link was revoked.");
        if (share.ExpiresAt is { } expires && expires <= time.GetUtcNow()) throw new AuthException(410, LinkExpired, "This link has expired.");
    }

    /// <summary>The shared file, live and in a live project; a file in Trash is gone for the guest (<c>404</c>).</summary>
    private async Task<FileEntity> FileAsync(ShareEntity share, CancellationToken ct) =>
        await db.Files.AsNoTracking().SingleOrDefaultAsync(f => f.Id == share.FileId && f.DeletedAt == null
                                                                && db.Projects.Any(p => p.Id == f.ProjectId && p.DeletedAt == null), ct)
        ?? throw AuthException.NotFound();
}
