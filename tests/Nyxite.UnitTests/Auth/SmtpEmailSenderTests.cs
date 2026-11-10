using Microsoft.Extensions.Options;
using Nyxite.Application.Email;

namespace Nyxite.UnitTests.Auth;

public sealed class SmtpEmailSenderTests
{
    [Theory]
    [InlineData(null, "no-reply@example.org")]
    [InlineData("", "no-reply@example.org")]
    [InlineData("smtp.example.org", null)]
    [InlineData("smtp.example.org", "not an address")]
    public void Missing_relay_or_sender_fails_at_construction(string? host, string? from) =>
        Assert.Throws<InvalidOperationException>(() => new SmtpEmailSender(Options.Create(new EmailOptions { Host = host, From = from })));

    [Fact]
    public void Configured_relay_constructs() =>
        Assert.NotNull(new SmtpEmailSender(Options.Create(new EmailOptions { Host = "smtp.example.org", From = "Nyxite <no-reply@example.org>" })));
}
