namespace Nyxite.Application.Email;

/// <summary>Sends account email (verification and one-time codes). Never used for content, which the server cannot read.</summary>
public interface IEmailSender
{
    Task SendAsync(string to, string subject, string body, CancellationToken ct);
}
