using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Nyxite.Application.Audit;
using Nyxite.Crypto;
using Nyxite.Domain.Identity;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Auth;

public sealed record TokenPair(string AccessToken, string RefreshToken, DateTimeOffset AccessTokenExpiresAt);

/// <summary>
/// The one internal token every identity provider resolves to (08 §8.1 IdP seam): creates <c>sessions</c>, issues the
/// access token and the rotating refresh-token chain, and revokes sessions (03 §3.2, 08 §8.7).
/// </summary>
public sealed class SessionService(
    NyxiteDbContext db, AccessTokenService tokens, AuditWriter audit, IEphemeralTokenStore ephemeral, TimeProvider time,
    IOptions<AuthOptions> options)
{
    private readonly AuthOptions _options = options.Value;

    /// <summary>
    /// Starts a session. <paramref name="mfaVerified"/> false yields an enrollment-limited session. A blocked account is
    /// download-only and gets no web session (12 §12.6), checked here because every sign-in path ends here.
    /// </summary>
    public async Task<TokenPair> StartAsync(UserEntity user, ClientKind clientKind, AuthMethod method, bool mfaVerified,
        RequestInfo request, CancellationToken ct)
    {
        if (IsBlockedFor(user, clientKind))
        {
            audit.Add("auth.login_failed", user.Id, request, detail: new { reason = "account_blocked" });
            await db.SaveChangesAsync(ct);
            throw AuthException.AccountBlocked();
        }

        var now = time.GetUtcNow();
        var session = new SessionEntity
        {
            Id = Guid.CreateVersion7(now),
            UserId = user.Id,
            ClientKind = clientKind,
            AuthMethod = method,
            MfaVerifiedAt = mfaVerified ? now : null,
            CreatedAt = now,
            LastSeenAt = now,
            ExpiresAt = now + _options.SessionAbsoluteLifetime,
            LastIp = request.Ip,
            UserAgent = AuditWriter.Truncate(request.UserAgent),
        };
        db.Sessions.Add(session);
        var refresh = NewRefreshToken(session, parentId: null, now);
        audit.Add("auth.login", user.Id, request, targetType: "session", targetId: session.Id,
            detail: new { method = AuthDbValue.Of(method), client = AuthDbValue.Of(clientKind), limited = !mfaVerified });
        await db.SaveChangesAsync(ct);
        var (access, expires) = tokens.Issue(user.Id, session.Id, user.Role, method, mfaVerified);
        return new TokenPair(access, refresh, expires);
    }

    /// <summary>Rotates a refresh token (03 §3.2). Re-presenting a used token revokes the whole session.</summary>
    public async Task<TokenPair> RefreshAsync(string refreshToken, RequestInfo request, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var hash = HashToken(refreshToken);
        var row = await db.RefreshTokens.SingleOrDefaultAsync(r => r.TokenHash == hash, ct) ?? throw AuthException.Unauthenticated();
        var session = await db.Sessions.SingleAsync(s => s.Id == row.SessionId, ct);

        if (row.UsedAt is not null)
        {
            if (session.RevokedAt is null)
            {
                session.RevokedAt = now;
                session.RevokeReason = RevokeReason.ReuseDetected;
                audit.Add("auth.refresh_reuse", session.UserId, request, targetType: "session", targetId: session.Id);
                await db.SaveChangesAsync(ct);
            }

            throw AuthException.Unauthenticated();
        }

        if (row.ExpiresAt <= now || session.RevokedAt is not null || session.ExpiresAt <= now) throw AuthException.Unauthenticated();
        var user = await db.Users.AsNoTracking().SingleAsync(u => u.Id == session.UserId, ct);
        if (IsBlockedFor(user, session.ClientKind))
        {
            session.RevokedAt = now;
            session.RevokeReason = RevokeReason.UserBlocked;
            await db.SaveChangesAsync(ct);
            throw AuthException.AccountBlocked();
        }

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        // Conditional update: of two concurrent refreshes of the same token exactly one wins; the loser gets 401.
        var won = await db.RefreshTokens.Where(r => r.Id == row.Id && r.UsedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.UsedAt, now), ct);
        if (won != 1) throw AuthException.Unauthenticated();
        session.LastSeenAt = now;
        session.LastIp = request.Ip;
        var next = NewRefreshToken(session, row.Id, now);
        try
        {
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
        }
        catch (DbUpdateException)
        {
            throw AuthException.Unauthenticated();
        }

        var (access, expires) = tokens.Issue(user.Id, session.Id, user.Role, session.AuthMethod, session.MfaVerifiedAt is not null);
        return new TokenPair(access, next, expires);
    }

    /// <summary>
    /// Mints a relay socket ticket from a session (08 §8.4). A browser must put its credential into the WebSocket URL,
    /// where proxies and browser history can see it, so it sends this single-use 60 s value instead of its access token.
    /// </summary>
    public async Task<(string Ticket, DateTimeOffset ExpiresAt)> IssueSocketTicketAsync(Guid userId, Guid sessionId, CancellationToken ct)
    {
        var lifetime = _options.Lifetimes.SocketTicket;
        var expires = time.GetUtcNow() + lifetime;
        var ticket = await ephemeral.IssueAsync(EphemeralTokenKind.SocketTicket, userId, sessionId, lifetime, null, ct);
        return (ticket, expires);
    }

    /// <summary>
    /// Turns a socket ticket into a short access token for the relay connection, or null when the ticket is unknown,
    /// used, expired, or its session ended. <paramref name="consume"/> false only checks it: SignalR's negotiate request
    /// carries the ticket ahead of the upgrade, and the upgrade is the one use.
    /// </summary>
    public async Task<string?> RedeemSocketTicketAsync(string ticket, bool consume, CancellationToken ct)
    {
        var hash = IEphemeralTokenStore.Hash(ticket);
        var row = consume
            ? await ephemeral.ConsumeAsync(EphemeralTokenKind.SocketTicket, hash, ct)
            : await ephemeral.FindLiveAsync(EphemeralTokenKind.SocketTicket, hash, ct);
        if (row?.SessionId is not { } sessionId) return null;
        var now = time.GetUtcNow();
        var session = await db.Sessions.AsNoTracking()
            .SingleOrDefaultAsync(s => s.Id == sessionId && s.RevokedAt == null && s.ExpiresAt > now, ct);
        if (session is null) return null;
        var user = await db.Users.AsNoTracking().SingleAsync(u => u.Id == session.UserId, ct);
        if (IsBlockedFor(user, session.ClientKind)) return null;
        return tokens.Issue(user.Id, session.Id, user.Role, session.AuthMethod, session.MfaVerifiedAt is not null).Token;
    }

    public async Task RevokeAsync(Guid sessionId, Guid userId, RevokeReason reason, RequestInfo request, CancellationToken ct)
    {
        var session = await db.Sessions.SingleOrDefaultAsync(s => s.Id == sessionId && s.UserId == userId, ct);
        if (session is null || session.RevokedAt is not null) return;
        session.RevokedAt = time.GetUtcNow();
        session.RevokeReason = reason;
        if (reason == RevokeReason.Logout) audit.Add("auth.logout", userId, request, targetType: "session", targetId: sessionId);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Revokes every live session of a user except <paramref name="keep"/> (credential change, 03 §3.2).</summary>
    public Task RevokeOthersAsync(Guid userId, Guid keep, RevokeReason reason, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        return db.Sessions.Where(s => s.UserId == userId && s.Id != keep && s.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, now).SetProperty(x => x.RevokeReason, reason), ct);
    }

    private static bool IsBlockedFor(UserEntity user, ClientKind clientKind) =>
        user.Status == UserStatus.Blocked && clientKind == ClientKind.Web;

    public static byte[] HashToken(string token) => SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(token));

    private string NewRefreshToken(SessionEntity session, Guid? parentId, DateTimeOffset now)
    {
        var token = Base64UrlCodec.Encode(RandomNumberGenerator.GetBytes(32));
        var idle = now + _options.RefreshTokenIdleLifetime;
        db.RefreshTokens.Add(new RefreshTokenEntity
        {
            Id = Guid.CreateVersion7(now),
            SessionId = session.Id,
            ParentId = parentId,
            TokenHash = HashToken(token),
            IssuedAt = now,
            ExpiresAt = idle < session.ExpiresAt ? idle : session.ExpiresAt,
        });
        return token;
    }
}
