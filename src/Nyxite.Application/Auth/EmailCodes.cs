using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Nyxite.Application.Email;
using Nyxite.Crypto;
using Nyxite.Domain.Identity;

namespace Nyxite.Application.Auth;

/// <summary>Why a code is emailed. Each purpose has its own text and its own hash domain.</summary>
public enum EmailCodePurpose { Verification, Enrollment, Login, StepUp }

/// <summary>
/// Emailed one-time codes (email verification, the email second factor and email step-up). A code lives in one
/// <c>ephemeral_tokens</c> row under a caller-chosen key; issuing again replaces it. Only the HMAC of the code is stored
/// (<see cref="OneTimeCodes"/>), and wrong guesses count against the row's attempt cap.
/// </summary>
public sealed class EmailCodes(IEphemeralTokenStore ephemeral, OneTimeCodes codes, EmailOutbox outbox, IOptions<AuthOptions> options)
{
    private readonly AuthOptions _options = options.Value;

    public static byte[] Key(EmailCodePurpose purpose, string scope) =>
        SHA256.HashData(Encoding.ASCII.GetBytes($"email_code:{Name(purpose)}:{scope}"));

    public async Task IssueAsync(EmailCodePurpose purpose, byte[] key, Guid userId, Guid? sessionId, string email, CancellationToken ct)
    {
        var code = OneTimeCodes.NewEmailCode();
        var (hash, version) = codes.Hash(Name(purpose), code);
        var kind = purpose == EmailCodePurpose.Verification ? EphemeralTokenKind.EmailVerify : EphemeralTokenKind.EmailCode;
        var detail = JsonSerializer.Serialize(new { h = Base64UrlCodec.Encode(hash), v = version });
        var (subject, body) = Text(purpose, code, _options.EmailCodeLifetime);
        // Queued first, so the save inside PutAsync stores the code and its mail together.
        outbox.Enqueue(email, subject, body, _options.EmailCodeLifetime);
        await ephemeral.PutAsync(key, kind, userId, sessionId, _options.EmailCodeLifetime, detail, ct);
        outbox.Notify();
    }

    /// <summary>Checks a code; a match consumes it. False for a wrong, expired, used or capped code.</summary>
    public async Task<bool> VerifyAsync(EmailCodePurpose purpose, byte[] key, Guid userId, string? code, CancellationToken ct)
    {
        var kind = purpose == EmailCodePurpose.Verification ? EphemeralTokenKind.EmailVerify : EphemeralTokenKind.EmailCode;
        var row = await ephemeral.RegisterAttemptAsync(kind, key, _options.MfaMaxAttempts, ct);
        if (row is null || row.UserId != userId || !OneTimeCodes.IsEmailCode(code)) return false;
        var detail = JsonDocument.Parse(row.Detail!).RootElement;
        var hash = Base64UrlCodec.Decode(detail.GetProperty("h").GetString()!);
        if (!codes.Verify(Name(purpose), code, hash, detail.GetProperty("v").GetInt32())) return false;
        return await ephemeral.ConsumeAsync(kind, key, ct) is not null;
    }

    private static string Name(EmailCodePurpose purpose) => purpose switch
    {
        EmailCodePurpose.Verification => "email_verify",
        EmailCodePurpose.Enrollment => "email_enroll",
        EmailCodePurpose.Login => "email_login",
        EmailCodePurpose.StepUp => "email_step_up",
        _ => throw new ArgumentOutOfRangeException(nameof(purpose)),
    };

    private static (string Subject, string Body) Text(EmailCodePurpose purpose, string code, TimeSpan lifetime)
    {
        var minutes = (int)Math.Ceiling(lifetime.TotalMinutes);
        return purpose switch
        {
            EmailCodePurpose.Verification => ("Verify your Nyxite email address",
                $"Your verification code is {code}.\n\nIt expires in {minutes} minutes. " +
                "If you did not create a Nyxite account, ignore this email and the account is deleted automatically."),
            EmailCodePurpose.Enrollment => ("Turn on Nyxite sign-in codes by email",
                $"Your confirmation code is {code}.\n\nIt expires in {minutes} minutes. " +
                "If you did not ask for sign-in codes by email, someone knows your password: change it."),
            EmailCodePurpose.Login => ("Your Nyxite sign-in code",
                $"Your sign-in code is {code}.\n\nIt expires in {minutes} minutes. " +
                "If you did not try to sign in, someone knows your password: change it."),
            EmailCodePurpose.StepUp => ("Confirm a change to your Nyxite sign-in methods",
                $"Your confirmation code is {code}.\n\nIt expires in {minutes} minutes. " +
                "If you did not ask to change how you sign in, do not share this code and change your password."),
            _ => throw new ArgumentOutOfRangeException(nameof(purpose)),
        };
    }
}
