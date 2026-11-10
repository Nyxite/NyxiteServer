using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Nyxite.Application.Audit;
using Nyxite.Crypto;
using Nyxite.Domain.Identity;
using Nyxite.Persistence;
using Nyxite.Persistence.Entities;

namespace Nyxite.Application.Auth;

/// <summary>
/// Passkeys (WebAuthn), co-equal to password + TOTP and sufficient alone (08 §8.1(b)). Only the public credential and
/// its signature counter are stored. Challenges live in <c>ephemeral_tokens</c> (kind <c>webauthn_challenge</c>) keyed
/// by SHA-256 of the challenge, so they are single-use and work across server nodes. Credentials are discoverable
/// (resident), so login never needs the email: <c>assert/options</c> ignores it and reveals nothing about accounts.
/// </summary>
public sealed class PasskeyService(
    NyxiteDbContext db,
    FactorChangeGuard guard,
    IEphemeralTokenStore ephemeral,
    SessionService sessions,
    AuditWriter audit,
    TimeProvider time,
    IOptions<AuthOptions> options)
{
    private const string CreateType = "create";
    private const string AssertType = "get";
    private const string StepUpType = "step_up";
    public const int LabelMaxLength = 100;

    private readonly AuthOptions _options = options.Value;
    private IFido2? _fido2;

    public async Task<string> BeginRegistrationAsync(ClaimsPrincipal principal, string? stepUpToken, CancellationToken ct)
    {
        var fido2 = Fido2();
        var (user, _) = await guard.AuthorizeChangeAsync(principal, stepUpToken, ct);
        var existing = await db.WebAuthnCredentials.Where(c => c.UserId == user.Id).Select(c => c.CredentialId).ToListAsync(ct);
        var createOptions = fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = new Fido2User { Id = UserHandle(user.Id), Name = user.Email, DisplayName = user.DisplayName },
            ExcludeCredentials = existing.Select(id => new PublicKeyCredentialDescriptor(id)).ToList(),
            AuthenticatorSelection = new AuthenticatorSelection
            {
                ResidentKey = ResidentKeyRequirement.Required,
                UserVerification = UserVerificationRequirement.Required,
            },
            AttestationPreference = AttestationConveyancePreference.None,
        });
        var json = createOptions.ToJson();
        await ephemeral.PutAsync(SHA256.HashData(createOptions.Challenge), EphemeralTokenKind.WebauthnChallenge, user.Id,
            principal.SessionIdOf(), _options.WebAuthnChallengeLifetime, Detail(CreateType, json), ct);
        return json;
    }

    public async Task FinishRegistrationAsync(ClaimsPrincipal principal, JsonElement credential, string? label,
        RequestInfo request, CancellationToken ct)
    {
        var fido2 = Fido2();
        if (label is { Length: > LabelMaxLength }) throw AuthException.Validation($"label must be at most {LabelMaxLength} characters.");
        var (user, hadFactor) = await guard.RequireEnrollmentRightAsync(principal, ct);
        var response = Deserialize<AuthenticatorAttestationRawResponse>(credential);
        var row = await ConsumeChallengeAsync(response.Response?.ClientDataJson, CreateType, ct);
        if (row.Entity.UserId != user.Id || row.Entity.SessionId != principal.SessionIdOf())
            throw AuthException.Validation("The passkey challenge does not belong to this session.");

        RegisteredPublicKeyCredential result;
        try
        {
            result = await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = response,
                OriginalOptions = CredentialCreateOptions.FromJson(row.OptionsJson),
                IsCredentialIdUniqueToUserCallback = async (args, token) =>
                    !await db.WebAuthnCredentials.AnyAsync(c => c.CredentialId == args.CredentialId, token),
            }, ct);
        }
        catch (Fido2VerificationException e)
        {
            throw AuthException.Validation("The passkey registration could not be verified: " + e.Message);
        }

        var now = time.GetUtcNow();
        db.WebAuthnCredentials.Add(new WebAuthnCredentialEntity
        {
            Id = Guid.CreateVersion7(now),
            UserId = user.Id,
            CredentialId = result.Id,
            PublicKey = result.PublicKey,
            SignCount = result.SignCount,
            Label = label,
            CreatedAt = now,
        });
        var session = await db.Sessions.SingleAsync(s => s.Id == principal.SessionIdOf(), ct);
        session.MfaVerifiedAt ??= now;
        audit.Add("auth.passkey_registered", user.Id, request, targetType: "user", targetId: user.Id);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException e) when (e.InnerException is Npgsql.PostgresException { SqlState: Npgsql.PostgresErrorCodes.UniqueViolation })
        {
            throw AuthException.Conflict("This passkey is already registered.");
        }

        // A new passkey signs in on its own, so adding one is a credential change (03 §3.2), in the same transaction.
        if (hadFactor) await sessions.RevokeOthersAsync(user.Id, session.Id, RevokeReason.CredentialChange, ct);
        await tx.CommitAsync(ct);
    }

    /// <summary>Step-up challenge (08 §8.2): an assertion limited to the caller's own passkeys, bound to this session.</summary>
    public async Task<string> BeginStepUpAsync(ClaimsPrincipal principal, CancellationToken ct)
    {
        var fido2 = Fido2();
        var userId = principal.UserId();
        var existing = await db.WebAuthnCredentials.Where(c => c.UserId == userId).Select(c => c.CredentialId).ToListAsync(ct);
        if (existing.Count == 0) throw AuthException.Validation("This account has no passkey.");
        var assertionOptions = fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = existing.Select(id => new PublicKeyCredentialDescriptor(id)).ToList(),
            UserVerification = UserVerificationRequirement.Required,
        });
        var json = assertionOptions.ToJson();
        await ephemeral.PutAsync(SHA256.HashData(assertionOptions.Challenge), EphemeralTokenKind.WebauthnChallenge, userId,
            principal.SessionIdOf(), _options.WebAuthnChallengeLifetime, Detail(StepUpType, json), ct);
        return json;
    }

    /// <summary>Verifies a step-up assertion against a challenge of this session and one of the caller's passkeys.</summary>
    public async Task<bool> VerifyStepUpAsync(ClaimsPrincipal principal, JsonElement? credential, CancellationToken ct)
    {
        var fido2 = Fido2();
        if (credential is null) return false;
        var userId = principal.UserId();
        AuthenticatorAssertionRawResponse response;
        (EphemeralTokenEntity Entity, string OptionsJson) row;
        try
        {
            response = Deserialize<AuthenticatorAssertionRawResponse>(credential.Value);
            row = await ConsumeChallengeAsync(response.Response?.ClientDataJson, StepUpType, ct);
        }
        catch (AuthException)
        {
            return false;
        }

        if (row.Entity.UserId != userId || row.Entity.SessionId != principal.SessionIdOf() || response.RawId is null) return false;
        var rawId = response.RawId;
        var stored = await db.WebAuthnCredentials.SingleOrDefaultAsync(c => c.CredentialId == rawId && c.UserId == userId, ct);
        if (stored is null) return false;
        try
        {
            var result = await fido2.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = response,
                OriginalOptions = AssertionOptions.FromJson(row.OptionsJson),
                StoredPublicKey = stored.PublicKey,
                StoredSignatureCounter = (uint)stored.SignCount,
                IsUserHandleOwnerOfCredentialIdCallback = (args, _) =>
                    Task.FromResult(args.UserHandle.AsSpan().SequenceEqual(UserHandle(stored.UserId))),
            }, ct);
            stored.SignCount = result.SignCount;
            return true;
        }
        catch (Fido2VerificationException)
        {
            return false;
        }
    }

    public async Task<string> BeginAssertionAsync(CancellationToken ct)
    {
        var fido2 = Fido2();
        var assertionOptions = fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = [],
            UserVerification = UserVerificationRequirement.Required,
        });
        var json = assertionOptions.ToJson();
        await ephemeral.PutAsync(SHA256.HashData(assertionOptions.Challenge), EphemeralTokenKind.WebauthnChallenge, null, null,
            _options.WebAuthnChallengeLifetime, Detail(AssertType, json), ct);
        return json;
    }

    public async Task<TokenPair> FinishAssertionAsync(JsonElement credential, ClientKind clientKind, RequestInfo request, CancellationToken ct)
    {
        var fido2 = Fido2();
        var response = Deserialize<AuthenticatorAssertionRawResponse>(credential, unauthenticated: true);
        var row = await ConsumeChallengeAsync(response.Response?.ClientDataJson, AssertType, ct, unauthenticated: true);
        var rawId = response.RawId ?? throw AuthException.Unauthenticated();
        var stored = await db.WebAuthnCredentials.SingleOrDefaultAsync(c => c.CredentialId == rawId, ct);
        if (stored is null)
        {
            audit.Add("auth.login_failed", null, request, detail: new { reason = "unknown_passkey" });
            await db.SaveChangesAsync(ct);
            throw AuthException.Unauthenticated();
        }

        VerifyAssertionResult result;
        try
        {
            result = await fido2.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = response,
                OriginalOptions = AssertionOptions.FromJson(row.OptionsJson),
                StoredPublicKey = stored.PublicKey,
                StoredSignatureCounter = (uint)stored.SignCount,
                IsUserHandleOwnerOfCredentialIdCallback = (args, _) =>
                    Task.FromResult(args.UserHandle.AsSpan().SequenceEqual(UserHandle(stored.UserId))),
            }, ct);
        }
        catch (Fido2VerificationException)
        {
            audit.Add("auth.login_failed", stored.UserId, request, detail: new { reason = "bad_passkey_assertion" });
            await db.SaveChangesAsync(ct);
            throw AuthException.Unauthenticated();
        }

        stored.SignCount = result.SignCount;
        var user = await db.Users.SingleAsync(u => u.Id == stored.UserId, ct);
        return await sessions.StartAsync(user, clientKind, AuthMethod.Passkey, mfaVerified: true, request, ct);
    }

    /// <summary>The WebAuthn user handle: the account id in RFC 9562 byte order (no email or name).</summary>
    public static byte[] UserHandle(Guid userId)
    {
        var bytes = new byte[16];
        userId.TryWriteBytes(bytes, bigEndian: true, out _);
        return bytes;
    }

    private IFido2 Fido2()
    {
        if (_fido2 is not null) return _fido2;
        var w = _options.WebAuthn;
        if (string.IsNullOrWhiteSpace(w.RelyingPartyId) || w.Origins.Count == 0)
            throw AuthException.Unavailable("Passkeys are not configured on this instance (Auth:WebAuthn).");
        return _fido2 = new Fido2(new Fido2Configuration
        {
            RPID = w.RelyingPartyId,
            RPName = w.RelyingPartyName,
            Origins = w.Origins.ToHashSet(),
        });
    }

    private static string Detail(string type, string optionsJson) =>
        JsonSerializer.Serialize(new { type, options = optionsJson });

    private async Task<(EphemeralTokenEntity Entity, string OptionsJson)> ConsumeChallengeAsync(
        byte[]? clientDataJson, string type, CancellationToken ct, bool unauthenticated = false)
    {
        var fail = () => unauthenticated ? AuthException.Unauthenticated() : AuthException.Validation("Unknown or expired passkey challenge.");
        if (clientDataJson is null) throw fail();
        string? challenge;
        try { challenge = JsonDocument.Parse(clientDataJson).RootElement.GetProperty("challenge").GetString(); }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException) { throw fail(); }
        if (!Base64UrlCodec.TryDecode(challenge, out var challengeBytes)) throw fail();

        var row = await ephemeral.ConsumeAsync(EphemeralTokenKind.WebauthnChallenge, SHA256.HashData(challengeBytes), ct) ?? throw fail();
        var detail = JsonDocument.Parse(row.Detail!).RootElement;
        if (detail.GetProperty("type").GetString() != type) throw fail();
        return (row, detail.GetProperty("options").GetString()!);
    }

    private static T Deserialize<T>(JsonElement element, bool unauthenticated = false)
    {
        try
        {
            if (element.ValueKind != JsonValueKind.Object) throw new JsonException();
            return element.Deserialize<T>() ?? throw new JsonException();
        }
        catch (Exception e) when (e is JsonException or NotSupportedException or InvalidOperationException)
        {
            throw unauthenticated ? AuthException.Unauthenticated() : AuthException.Validation("Malformed WebAuthn credential.");
        }
    }
}
