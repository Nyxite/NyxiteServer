using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Nyxite.Application.Auth;
using Nyxite.Application.Diagnostics;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Email;

/// <summary>
/// Encrypts outbox payloads with AES-256-GCM under <c>HKDF-SHA256(pepper_v, info = "nyxite-email-outbox-v1")</c>, like
/// <see cref="TotpSecretProtector"/>. The pepper lives outside Postgres, so a database-only leak shows no code or reset
/// token of an unsent mail. Layout: <c>pepper_version(u32) ‖ nonce(12) ‖ ciphertext ‖ tag(16)</c>,
/// AAD = <c>"NYXMAIL1" ‖ row_id(16)</c>, so a payload cannot be moved to another row.
/// </summary>
public sealed class EmailOutboxProtector(IOptions<AuthOptions> options)
{
    private static readonly byte[] Info = "nyxite-email-outbox-v1"u8.ToArray();
    private readonly VersionedSecret _pepper = VersionedSecret.Parse(options.Value.PasswordPepper, "Auth:PasswordPepper");

    public byte[] Protect(ReadOnlySpan<byte> payload, Guid rowId)
    {
        var output = new byte[4 + 12 + payload.Length + 16];
        BinaryPrimitives.WriteUInt32BigEndian(output, (uint)_pepper.CurrentVersion);
        var nonce = output.AsSpan(4, 12);
        RandomNumberGenerator.Fill(nonce);
        using var gcm = new AesGcm(Key(_pepper.Current), 16);
        gcm.Encrypt(nonce, payload, output.AsSpan(16, payload.Length), output.AsSpan(16 + payload.Length), Aad(rowId));
        return output;
    }

    public byte[] Unprotect(ReadOnlySpan<byte> data, Guid rowId)
    {
        if (data.Length < 4 + 12 + 16) throw new CryptographicException("Outbox payload too short.");
        var version = (int)BinaryPrimitives.ReadUInt32BigEndian(data);
        if (!_pepper.TryGet(version, out var pepper)) throw new CryptographicException($"Pepper version {version} is not configured.");
        var payload = new byte[data.Length - 32];
        using var gcm = new AesGcm(Key(pepper), 16);
        gcm.Decrypt(data.Slice(4, 12), data.Slice(16, payload.Length), data[^16..], payload, Aad(rowId));
        return payload;
    }

    private static byte[] Key(byte[] pepper) => HKDF.DeriveKey(HashAlgorithmName.SHA256, pepper, 32, info: Info);

    private static byte[] Aad(Guid rowId)
    {
        var aad = new byte[8 + 16];
        Encoding.ASCII.GetBytes("NYXMAIL1", aad);
        rowId.TryWriteBytes(aad.AsSpan(8), bigEndian: true, out _);
        return aad;
    }
}

/// <summary>Wakes the outbox worker as soon as a mail was queued, so it does not wait for its next poll.</summary>
public sealed class EmailOutboxSignal
{
    private readonly SemaphoreSlim _pending = new(0, 1);

    public void Notify()
    {
        try { _pending.Release(); }
        catch (SemaphoreFullException) { /* a wake-up is already pending */ }
    }

    public Task WaitAsync(TimeSpan timeout, CancellationToken ct) => _pending.WaitAsync(timeout, ct);
}

/// <summary>
/// Queues account email (08 §8.1). The row joins the caller's unit of work, so a mail is queued exactly when the change
/// it belongs to commits, and the request never waits for the mail relay: it answers the same and equally fast whether
/// or not a mail goes out.
/// </summary>
public sealed class EmailOutbox(NyxiteDbContext db, EmailOutboxProtector protector, EmailOutboxSignal signal, TimeProvider time)
{
    internal sealed record Payload(string To, string Subject, string Body);

    /// <summary>Adds the mail to the unit of work. Call <see cref="Notify"/> after it was saved.</summary>
    public void Enqueue(string to, string subject, string body, TimeSpan validFor)
    {
        var now = time.GetUtcNow();
        var id = Guid.CreateVersion7(now);
        db.EmailOutbox.Add(new EmailOutboxEntity
        {
            Id = id,
            PayloadEnc = protector.Protect(JsonSerializer.SerializeToUtf8Bytes(new Payload(to, subject, body)), id),
            CreatedAt = now,
            NextAttemptAt = now,
            ExpiresAt = now + validFor,
        });
    }

    public void Notify() => signal.Notify();
}

/// <summary>
/// Sends due outbox mail. Each mail is claimed with <c>FOR UPDATE SKIP LOCKED</c>, so several server nodes never send
/// the same one, and deleted in the same transaction once the relay accepted it. A failed attempt is retried with a
/// growing delay, and a mail is dropped when its code expired or after <see cref="EmailOptions.OutboxMaxAttempts"/>.
/// </summary>
public sealed class EmailOutboxDispatcher(
    NyxiteDbContext db, EmailOutboxProtector protector, IEmailSender sender, TimeProvider time,
    IOptions<EmailOptions> options, ILogger<EmailOutboxDispatcher> logger)
{
    private readonly EmailOptions _options = options.Value;

    /// <summary>Works through every mail that is due now and returns how many were sent.</summary>
    public async Task<int> DispatchDueAsync(CancellationToken ct)
    {
        var sent = 0;
        while (!ct.IsCancellationRequested)
        {
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            var now = time.GetUtcNow();
            var row = (await db.EmailOutbox
                .FromSql($"SELECT * FROM email_outbox WHERE next_attempt_at <= {now} ORDER BY next_attempt_at LIMIT 1 FOR UPDATE SKIP LOCKED")
                .ToListAsync(ct)).SingleOrDefault();
            if (row is null) return sent;

            if (row.ExpiresAt <= now)
            {
                db.EmailOutbox.Remove(row);
                logger.LogWarning("Dropped outbox mail {MailId}: it expired before it could be sent.", row.Id);
            }
            else if (await TrySendAsync(row, ct))
            {
                db.EmailOutbox.Remove(row);
                sent++;
                NyxiteMetrics.EmailsSent.Add(1);
            }
            else
            {
                NyxiteMetrics.EmailsFailed.Add(1);
                row.Attempts++;
                if (row.Attempts >= _options.OutboxMaxAttempts)
                {
                    db.EmailOutbox.Remove(row);
                    logger.LogError("Gave up on outbox mail {MailId} after {Attempts} attempts.", row.Id, row.Attempts);
                }
                else
                {
                    // 10 s, 20 s, 40 s, ... capped at 5 min.
                    row.NextAttemptAt = now + TimeSpan.FromSeconds(Math.Min(300, 10 * Math.Pow(2, row.Attempts - 1)));
                }
            }

            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
        }

        return sent;
    }

    private async Task<bool> TrySendAsync(EmailOutboxEntity row, CancellationToken ct)
    {
        EmailOutbox.Payload mail;
        try
        {
            mail = JsonSerializer.Deserialize<EmailOutbox.Payload>(protector.Unprotect(row.PayloadEnc, row.Id))!;
        }
        catch (Exception e) when (e is CryptographicException or JsonException)
        {
            // Its pepper version is gone: no retry can ever succeed.
            logger.LogError(e, "Outbox mail {MailId} cannot be decrypted and is dropped.", row.Id);
            row.Attempts = int.MaxValue - 1;
            return false;
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(_options.SendTimeout);
        try
        {
            await sender.SendAsync(mail.To, mail.Subject, mail.Body, timeout.Token);
            return true;
        }
        catch (Exception e) when (!ct.IsCancellationRequested)
        {
            // Never log the recipient or the body.
            logger.LogWarning(e, "Sending outbox mail {MailId} failed (attempt {Attempt}).", row.Id, row.Attempts + 1);
            return false;
        }
    }
}

/// <summary>Background worker that sends queued mail: woken by <see cref="EmailOutboxSignal"/>, and polling as a fallback.</summary>
public sealed class EmailOutboxWorker(
    IServiceScopeFactory scopes, EmailOutboxSignal signal, IOptions<EmailOptions> options, ILogger<EmailOutboxWorker> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using (var scope = scopes.CreateAsyncScope())
                    await scope.ServiceProvider.GetRequiredService<EmailOutboxDispatcher>().DispatchDueAsync(stoppingToken);
                await signal.WaitAsync(options.Value.OutboxPollInterval, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception e)
            {
                logger.LogWarning(e, "The email outbox run failed.");
                try { await Task.Delay(options.Value.OutboxPollInterval, stoppingToken); }
                catch (OperationCanceledException) { return; }
            }
        }
    }
}
