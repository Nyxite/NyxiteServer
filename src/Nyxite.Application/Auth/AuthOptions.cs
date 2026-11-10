using Nyxite.Crypto;

namespace Nyxite.Application.Auth;

/// <summary>Configuration section <c>Auth</c> (<c>NYXITE__Auth__*</c>, 14).</summary>
public sealed class AuthOptions
{
    public const string Section = "Auth";

    /// <summary><c>iss</c> of issued access tokens: the instance base URL.</summary>
    public string Issuer { get; set; } = "nyxite";

    /// <summary><c>NYXITE__Auth__Audience</c>.</summary>
    public string Audience { get; set; } = "nyxite-api";

    /// <summary><c>NYXITE__Auth__TokenSigningKey</c>: versioned HMAC keys, <c>{version}:{base64 key};...</c>, highest version signs.</summary>
    public string TokenSigningKey { get; set; } = "";

    /// <summary><c>NYXITE__Auth__PasswordPepper</c> (deploy secret <c>PASSWORD_PEPPER</c>): <c>{version}:{base64 key};...</c>.</summary>
    public string PasswordPepper { get; set; } = "";

    /// <summary>Argon2id parameters for new verifiers. The pinned v1 values (07 §7.3); tests may lower them.</summary>
    public Argon2idParameters PasswordHashing { get; set; } = Argon2id.Default;

    /// <summary>
    /// <c>NYXITE__Auth__MaxConcurrentPasswordHashes</c>: how many Argon2id derivations may run at once. Each one holds the
    /// configured memory (64 MiB by default), so this bounds the memory and CPU that sign-ins can take. 0 = one per CPU core.
    /// </summary>
    public int MaxConcurrentPasswordHashes { get; set; }

    /// <summary>How long a sign-in waits for a free hashing slot before it is answered <c>429 rate_limited</c>.</summary>
    public TimeSpan PasswordHashQueueTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Password-reset emails allowed per account within <see cref="PasswordResetEmailWindow"/>. Further requests are
    /// dropped silently, so the endpoint cannot be used to flood someone's mailbox.
    /// </summary>
    public int PasswordResetEmailLimit { get; set; } = 3;

    public TimeSpan PasswordResetEmailWindow { get; set; } = TimeSpan.FromHours(1);

    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(5);
    public TimeSpan RefreshTokenIdleLifetime { get; set; } = TimeSpan.FromDays(14);
    public TimeSpan SessionAbsoluteLifetime { get; set; } = TimeSpan.FromDays(90);
    public TimeSpan MfaTokenLifetime { get; set; } = TimeSpan.FromMinutes(5);
    public int MfaMaxAttempts { get; set; } = 5;

    /// <summary>Lifetime of a passkey challenge and of a pending TOTP enrollment.</summary>
    public TimeSpan WebAuthnChallengeLifetime { get; set; } = TimeSpan.FromMinutes(5);
    public TimeSpan TotpEnrollLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Lifetime of an emailed one-time code (email verification, email second factor, email step-up).</summary>
    public TimeSpan EmailCodeLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>How long an account may stay unverified before it is purged and its email address is free again.</summary>
    public TimeSpan UnverifiedAccountLifetime { get; set; } = TimeSpan.FromHours(24);

    /// <summary>How often the background job purges expired unverified accounts.</summary>
    public TimeSpan UnverifiedAccountSweepInterval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Lifetime of a single-use step-up token that authorizes one factor change (08 §8.2).</summary>
    public TimeSpan StepUpLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary><c>NYXITE__Auth__PairingCodeLifetime</c>: how long a pending device's <c>pairingCode</c> is valid (14).</summary>
    public TimeSpan PairingCodeLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary><c>NYXITE__Auth__PairingCodeMaxAttempts</c>: wrong entries before the code is void (14).</summary>
    public int PairingCodeMaxAttempts { get; set; } = 5;

    /// <summary><c>NYXITE__Auth__PairingCodeDigits</c>: length of the pairing code, 6 to 8 (14).</summary>
    public int PairingCodeDigits { get; set; } = 8;

    /// <summary>How long a POST create's response is replayed for its <c>Idempotency-Key</c> (04 §4.1).</summary>
    public TimeSpan IdempotencyLifetime { get; set; } = TimeSpan.FromHours(24);

    /// <summary>Number of backup codes per generated set.</summary>
    public int BackupCodeCount { get; set; } = 10;

    /// <summary>
    /// Wrong second-factor codes allowed per account within <see cref="SecondFactorFailureWindow"/>, across all
    /// <c>mfaToken</c>s, step-ups and email verification; further attempts get <c>429 rate_limited</c>.
    /// </summary>
    public int SecondFactorFailureLimit { get; set; } = 10;

    public TimeSpan SecondFactorFailureWindow { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>Lifetimes of the single-use <c>ephemeral_tokens</c> kinds (<c>NYXITE__Auth__Lifetimes__*</c>, 14).</summary>
    public TokenLifetimes Lifetimes { get; set; } = new();

    /// <summary>
    /// Optional link template for the password-reset email, for example <c>https://notes.example.org/reset?token={token}</c>.
    /// Unset, the email carries the token alone for the client to accept.
    /// </summary>
    public string? PasswordResetUrl { get; set; }

    /// <summary>Issuer shown in authenticator apps (<c>otpauth://</c> label and <c>issuer</c> parameter).</summary>
    public string TotpIssuer { get; set; } = "Nyxite";

    public WebAuthnOptions WebAuthn { get; set; } = new();
    public EnterpriseOptions Enterprise { get; set; } = new();
}

public sealed class TokenLifetimes
{
    public TimeSpan PasswordReset { get; set; } = TimeSpan.FromMinutes(30);
}

/// <summary><c>NYXITE__Auth__WebAuthn__*</c>. Passkey flows answer <c>503</c> until <see cref="RelyingPartyId"/> is set.</summary>
public sealed class WebAuthnOptions
{
    public string? RelyingPartyId { get; set; }
    public string RelyingPartyName { get; set; } = "Nyxite";
    public List<string> Origins { get; set; } = [];
}

/// <summary><c>NYXITE__Auth__Enterprise__*</c> — the optional enterprise OIDC IdP (08 §8.1).</summary>
public sealed class EnterpriseOptions
{
    public bool Enabled { get; set; }
    public string? Authority { get; set; }
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }
    public List<string> RedirectUris { get; set; } = [];
}
