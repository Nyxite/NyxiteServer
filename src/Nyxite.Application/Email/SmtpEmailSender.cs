using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Options;

namespace Nyxite.Application.Email;

/// <summary>
/// SMTP submission with <see cref="SmtpClient"/>. Email verification is mandatory, so a server without a mail relay
/// cannot onboard anyone: the constructor fails at startup when <c>Email:Host</c> or <c>Email:From</c> is missing.
/// </summary>
public sealed class SmtpEmailSender : IEmailSender
{
    private readonly EmailOptions _options;
    private readonly MailAddress _from;

    public SmtpEmailSender(IOptions<EmailOptions> options)
    {
        _options = options.Value;
        if (string.IsNullOrWhiteSpace(_options.Host)) throw new InvalidOperationException("Email:Host is not configured.");
        if (!MailAddress.TryCreate(_options.From, out var from)) throw new InvalidOperationException("Email:From is not a valid address.");
        _from = from;
    }

    public async Task SendAsync(string to, string subject, string body, CancellationToken ct)
    {
        using var message = new MailMessage(_from, new MailAddress(to)) { Subject = subject, Body = body, IsBodyHtml = false };
        using var client = new SmtpClient(_options.Host, _options.Port) { EnableSsl = _options.EnableSsl };
        if (!string.IsNullOrEmpty(_options.Username)) client.Credentials = new NetworkCredential(_options.Username, _options.Password);
        await client.SendMailAsync(message, ct);
    }
}
