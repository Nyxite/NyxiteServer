using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Nyxite.Crypto;
using Nyxite.Domain.Identity;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Auth;

/// <summary>Single-use short-lived tokens (03 §3.2 <c>ephemeral_tokens</c>); only SHA-256 hashes are stored.</summary>
public interface IEphemeralTokenStore
{
    /// <summary>Creates a random 256-bit token and returns it base64url-encoded; only its hash is stored.</summary>
    Task<string> IssueAsync(EphemeralTokenKind kind, Guid? userId, Guid? sessionId, TimeSpan lifetime, string? detail, CancellationToken ct);

    /// <summary>Stores a row under a caller-chosen hash (passkey challenge, per-session TOTP enrollment), replacing any old one.</summary>
    Task PutAsync(byte[] tokenHash, EphemeralTokenKind kind, Guid? userId, Guid? sessionId, TimeSpan lifetime, string? detail, CancellationToken ct);

    /// <summary>Atomically marks a live row used and returns it; exactly one caller can win.</summary>
    Task<EphemeralTokenEntity?> ConsumeAsync(EphemeralTokenKind kind, byte[] tokenHash, CancellationToken ct);

    /// <summary>Returns a live (unused, unexpired) row without changing it.</summary>
    Task<EphemeralTokenEntity?> FindLiveAsync(EphemeralTokenKind kind, byte[] tokenHash, CancellationToken ct);

    /// <summary>Atomically counts one attempt against a live row and returns it, or null once <paramref name="maxAttempts"/> is reached.</summary>
    Task<EphemeralTokenEntity?> RegisterAttemptAsync(EphemeralTokenKind kind, byte[] tokenHash, int maxAttempts, CancellationToken ct);

    static byte[] Hash(string token) => SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(token));
}

public sealed class PostgresEphemeralTokenStore(NyxiteDbContext db, TimeProvider time) : IEphemeralTokenStore
{
    public async Task<string> IssueAsync(EphemeralTokenKind kind, Guid? userId, Guid? sessionId, TimeSpan lifetime, string? detail, CancellationToken ct)
    {
        var token = Base64UrlCodec.Encode(RandomNumberGenerator.GetBytes(32));
        await PutAsync(IEphemeralTokenStore.Hash(token), kind, userId, sessionId, lifetime, detail, ct);
        return token;
    }

    public async Task PutAsync(byte[] tokenHash, EphemeralTokenKind kind, Guid? userId, Guid? sessionId, TimeSpan lifetime, string? detail, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var k = AuthDbValue.Of(kind);
        var expires = now + lifetime;
        // One statement, so two requests replacing the same row (a double "resend") cannot collide on the primary key.
        await db.Database.ExecuteSqlAsync($"""
            INSERT INTO ephemeral_tokens (token_hash, kind, user_id, session_id, attempts, detail, issued_at, expires_at, used_at)
            VALUES ({tokenHash}, {k}, {userId}, {sessionId}, 0, {detail}::jsonb, {now}, {expires}, NULL)
            ON CONFLICT (token_hash) DO UPDATE SET kind = EXCLUDED.kind, user_id = EXCLUDED.user_id,
                session_id = EXCLUDED.session_id, attempts = 0, detail = EXCLUDED.detail, issued_at = EXCLUDED.issued_at,
                expires_at = EXCLUDED.expires_at, used_at = NULL
            """, ct);
        // Callers rely on their pending changes (audit rows, queued mail) being saved with the token.
        await db.SaveChangesAsync(ct);
    }

    public async Task<EphemeralTokenEntity?> ConsumeAsync(EphemeralTokenKind kind, byte[] tokenHash, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var k = AuthDbValue.Of(kind);
        var rows = await db.EphemeralTokens
            .FromSql($"""
                UPDATE ephemeral_tokens SET used_at = {now}
                WHERE token_hash = {tokenHash} AND kind = {k} AND used_at IS NULL AND expires_at > {now}
                RETURNING *
                """)
            .AsNoTracking().ToListAsync(ct);
        return rows.SingleOrDefault();
    }

    public Task<EphemeralTokenEntity?> FindLiveAsync(EphemeralTokenKind kind, byte[] tokenHash, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        return db.EphemeralTokens.AsNoTracking()
            .SingleOrDefaultAsync(t => t.TokenHash == tokenHash && t.Kind == kind && t.UsedAt == null && t.ExpiresAt > now, ct);
    }

    public async Task<EphemeralTokenEntity?> RegisterAttemptAsync(EphemeralTokenKind kind, byte[] tokenHash, int maxAttempts, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var k = AuthDbValue.Of(kind);
        var rows = await db.EphemeralTokens
            .FromSql($"""
                UPDATE ephemeral_tokens SET attempts = attempts + 1
                WHERE token_hash = {tokenHash} AND kind = {k} AND used_at IS NULL AND expires_at > {now} AND attempts < {maxAttempts}
                RETURNING *
                """)
            .AsNoTracking().ToListAsync(ct);
        return rows.SingleOrDefault();
    }
}
