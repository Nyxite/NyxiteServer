namespace Nyxite.Persistence.Entities;

/// <summary>
/// <c>email_outbox</c> — account email waiting to be sent (03 §3.2). The payload (recipient, subject, body) is
/// AES-256-GCM ciphertext under a key that lives outside Postgres, because the body carries a usable one-time code.
/// A row is deleted as soon as it was sent, expired or given up on.
/// </summary>
public sealed class EmailOutboxEntity
{
    public Guid Id { get; set; }
    public required byte[] PayloadEnc { get; set; }
    public int Attempts { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset NextAttemptAt { get; set; }

    /// <summary>When the code in the mail stops working; an unsent mail is dropped then instead of delivered late.</summary>
    public DateTimeOffset ExpiresAt { get; set; }
}
