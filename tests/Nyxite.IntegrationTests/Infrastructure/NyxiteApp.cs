using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Nyxite.Application.Email;

namespace Nyxite.IntegrationTests.Infrastructure;

/// <summary>A clock the tests move by hand; the server and the test TOTP generator share it.</summary>
public sealed class ManualTimeProvider(DateTimeOffset start) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = start;
    public override DateTimeOffset GetUtcNow() => Now;
    public void Advance(TimeSpan by) => Now += by;
}

/// <summary>Captures account email instead of sending it, so tests read the codes a person would receive.</summary>
public sealed class CapturingEmailSender : IEmailSender
{
    public sealed record Message(string To, string Subject, string Body);

    public ConcurrentQueue<Message> Sent { get; } = new();

    /// <summary>Makes the next send fail like an unreachable relay.</summary>
    public bool FailNext { get; set; }

    public Task SendAsync(string to, string subject, string body, CancellationToken ct)
    {
        if (FailNext)
        {
            FailNext = false;
            throw new System.Net.Mail.SmtpException("relay unreachable");
        }

        Sent.Enqueue(new Message(to, subject, body));
        return Task.CompletedTask;
    }

    /// <summary>Sends what is queued in the outbox; set by <see cref="NyxiteApp"/>, which runs no background worker.</summary>
    public Func<Task>? Flush { get; set; }

    public List<Message> To(string address)
    {
        if (Flush is { } flush) Task.Run(flush).GetAwaiter().GetResult();
        return Sent.Where(m => string.Equals(m.To, address, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    /// <summary>The 8-digit code of the latest message to <paramref name="address"/>.</summary>
    public string LastCode(string address)
    {
        var last = To(address).LastOrDefault() ?? throw new InvalidOperationException($"No email was sent to {address}.");
        return System.Text.RegularExpressions.Regex.Match(last.Body, @"\b\d{8}\b").Value;
    }
}

/// <summary>The real server against a per-test Postgres database, with test secrets and cheap Argon2id parameters.</summary>
public sealed class NyxiteApp : WebApplicationFactory<Program>
{
    public const string Origin = "https://nyxite.test";
    public const string RpId = "nyxite.test";

    public static string Key(byte fill) => Convert.ToBase64String(Enumerable.Repeat(fill, 32).ToArray());

    private readonly Dictionary<string, string?> _settings;

    private readonly Action<IServiceCollection>? _configureServices;

    public NyxiteApp(string connectionString, ManualTimeProvider? clock = null, IDictionary<string, string?>? overrides = null,
        Action<IServiceCollection>? configureServices = null)
    {
        _configureServices = configureServices;
        Clock = clock ?? new ManualTimeProvider(DateTimeOffset.UtcNow);
        ConnectionString = connectionString;
        _settings = new Dictionary<string, string?>
        {
            ["Database:ConnectionString"] = connectionString,
            ["Auth:Issuer"] = Origin,
            ["Auth:Audience"] = "nyxite-test",
            ["Auth:TokenSigningKey"] = $"1:{Key(9)}",
            ["Auth:PasswordPepper"] = $"1:{Key(1)}",
            ["Auth:PasswordHashing:MemoryKiB"] = "1024",
            ["Auth:PasswordHashing:Iterations"] = "1",
            ["Auth:PasswordHashing:Parallelism"] = "1",
            ["Auth:WebAuthn:RelyingPartyId"] = RpId,
            ["Auth:WebAuthn:Origins:0"] = Origin,
            // Tests drive many sign-ins from one test host; the limiter itself is tested with its real value.
            ["RateLimiting:Auth:PermitLimit"] = "100000",
            ["RateLimiting:Directory:PermitLimit"] = "100000",
            ["RateLimiting:DeviceEnrollment:PermitLimit"] = "100000",
        };
        foreach (var (k, v) in overrides ?? new Dictionary<string, string?>()) _settings[k] = v;
        Email.Flush = FlushOutboxAsync;
    }

    /// <summary>Runs the outbox dispatcher once, like the background worker would.</summary>
    public async Task<int> FlushOutboxAsync()
    {
        await using var scope = Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<EmailOutboxDispatcher>().DispatchDueAsync(CancellationToken.None);
    }

    public ManualTimeProvider Clock { get; }
    public CapturingEmailSender Email { get; } = new();
    public string ConnectionString { get; }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        foreach (var (k, v) in _settings) builder.UseSetting(k, v);
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(Clock);
            services.RemoveAll<IEmailSender>();
            services.AddSingleton<IEmailSender>(Email);
            // Tests send queued mail themselves (Flush), so a mail is never in flight when a test looks for it.
            var worker = services.Single(d => d.ImplementationType == typeof(EmailOutboxWorker));
            services.Remove(worker);
            _configureServices?.Invoke(services);
        });
    }
}

public static class HttpTestExtensions
{
    public static HttpClient WithBearer(this HttpClient client, string token)
    {
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    public static async Task<JsonElement> JsonAsync(this HttpResponseMessage response)
    {
        var text = await response.Content.ReadAsStringAsync();
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    public static async Task<string> ProblemCodeAsync(this HttpResponseMessage response)
    {
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        return (await response.JsonAsync()).GetProperty("code").GetString()!;
    }

    public static Task<HttpResponseMessage> PostJsonAsync(this HttpClient client, string url, object? body = null) =>
        body is null ? client.PostAsync(url, null) : client.PostAsJsonAsync(url, body);
}
