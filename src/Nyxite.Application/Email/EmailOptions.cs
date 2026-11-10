namespace Nyxite.Application.Email;

/// <summary>Configuration section <c>Email</c> (<c>NYXITE__Email__*</c>, 14): the SMTP relay for account email.</summary>
public sealed class EmailOptions
{
    public const string Section = "Email";

    public string? Host { get; set; }
    public int Port { get; set; } = 587;

    /// <summary>STARTTLS on the submission port. Implicit TLS (port 465) is not supported by the sender.</summary>
    public bool EnableSsl { get; set; } = true;

    public string? Username { get; set; }
    public string? Password { get; set; }

    /// <summary>How long one delivery attempt may take before it counts as failed and is retried.</summary>
    public TimeSpan SendTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>How often the outbox worker looks for due mail when nothing woke it earlier.</summary>
    public TimeSpan OutboxPollInterval { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>Delivery attempts per mail before it is given up on.</summary>
    public int OutboxMaxAttempts { get; set; } = 5;

    /// <summary>Sender address, for example <c>Nyxite &lt;no-reply@example.org&gt;</c>.</summary>
    public string? From { get; set; }
}
