using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Nyxite.Crypto;

namespace Nyxite.IntegrationTests.Infrastructure;

/// <summary>Drives the key directory, device enrollment and recovery endpoints the way a client does (server 04, 08 §8.3).</summary>
public sealed class KeyDriver(AuthDriver auth)
{
    /// <summary>A client-side identity: the hybrid signing key and a stand-in hybrid KEM public key (the server only checks its size).</summary>
    public sealed record Identity(Guid KeyId, int Generation, HybridSigningKey Signing, byte[] KemPub);

    public sealed record Registered(Guid DeviceId, string PairingCode, byte[] Pubkey, string Fingerprint);

    public static Identity NewIdentity(int generation = 1) =>
        new(Guid.CreateVersion7(), generation, HybridSigningKey.Generate(), RandomNumberGenerator.GetBytes(CryptoSuite.HybridKemPublicKeySize));

    public static byte[] DevicePubkey() => RandomNumberGenerator.GetBytes(CryptoSuite.HybridKemPublicKeySize);

    public async Task<Guid> UserIdAsync(string accessToken) =>
        (await (await auth.Client().WithBearer(accessToken).GetAsync("/api/v1/me")).JsonAsync()).GetProperty("id").GetGuid();

    public static object PublishBody(Guid userId, Identity id, byte[]? selfSig = null, string algId = CryptoSuite.DirectoryAlgId)
    {
        var message = DirectoryEntry.SignedMessage(DirectoryEntryType.UserKeyPublish, userId, id.KeyId, (uint)id.Generation, CryptoSuite.DirectoryAlgId,
            id.KemPub, id.Signing.PublicKey);
        return new
        {
            keyId = id.KeyId,
            generation = id.Generation,
            algId,
            kemPub = Base64UrlCodec.Encode(id.KemPub),
            sigPub = Base64UrlCodec.Encode(id.Signing.PublicKey),
            selfSig = Base64UrlCodec.Encode(selfSig ?? id.Signing.Sign(message)),
        };
    }

    public Task<HttpResponseMessage> PublishAsync(string accessToken, Guid userId, Identity id) =>
        auth.Client().WithBearer(accessToken).PutAsJsonAsync("/api/v1/keys", PublishBody(userId, id));

    public async Task<HttpResponseMessage> RegisterRawAsync(string accessToken, object body, string? idempotencyKey)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1/devices") { Content = JsonContent.Create(body) };
        if (idempotencyKey is not null) request.Headers.Add("Idempotency-Key", idempotencyKey);
        return await auth.Client().WithBearer(accessToken).SendAsync(request);
    }

    public async Task<Registered> RegisterAsync(string accessToken, string label = "laptop")
    {
        var pubkey = DevicePubkey();
        var response = await RegisterRawAsync(accessToken, new { label, pubkey = Base64UrlCodec.Encode(pubkey) }, Guid.NewGuid().ToString());
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var json = await response.JsonAsync();
        return new Registered(json.GetProperty("deviceId").GetGuid(), json.GetProperty("pairingCode").GetString()!, pubkey,
            json.GetProperty("qrPayload").GetProperty("pubkeyFingerprint").GetString()!);
    }

    public static object ActivateBody(Guid userId, Registered device, Identity id, HybridSigningKey? signer = null) => new
    {
        keyId = id.KeyId,
        sig = Base64UrlCodec.Encode((signer ?? id.Signing).Sign(DeviceActivation.SignedMessage(userId, device.DeviceId, id.KeyId, device.Pubkey))),
    };

    public Task<HttpResponseMessage> ActivateAsync(string accessToken, Guid userId, Registered device, Identity id, HybridSigningKey? signer = null) =>
        auth.Client().WithBearer(accessToken).PostAsJsonAsync($"/api/v1/devices/{device.DeviceId}/activate", ActivateBody(userId, device, id, signer));

    /// <summary>A full account whose first device is registered, its identity published and the device activated.</summary>
    public async Task<(AuthDriver.Account Account, Guid UserId, Identity Identity, Registered Device)> AccountWithActiveDeviceAsync()
    {
        var account = await auth.RegisterWithTotpAsync();
        var token = account.Tokens.AccessToken;
        var userId = await UserIdAsync(token);
        var device = await RegisterAsync(token);
        var identity = NewIdentity();
        Assert.Equal(HttpStatusCode.OK, (await PublishAsync(token, userId, identity)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await ActivateAsync(token, userId, device, identity)).StatusCode);
        return (account, userId, identity, device);
    }

    public Task<HttpResponseMessage> ApproveAsync(string accessToken, Guid deviceId, string pairingCode, byte[]? wrapped = null) =>
        auth.Client().WithBearer(accessToken).PostAsJsonAsync($"/api/v1/devices/{deviceId}/approve",
            new { pairingCode, wrappedIdentityKey = Base64UrlCodec.Encode(wrapped ?? RandomNumberGenerator.GetBytes(4000)) });

    public static object RecoveryBody(int version = 1, int saltSize = 16) => new
    {
        version,
        kdf = new { alg = "argon2id", m = 65536, t = 3, p = 1, salt = Base64UrlCodec.Encode(RandomNumberGenerator.GetBytes(saltSize)) },
        nonce = Base64UrlCodec.Encode(RandomNumberGenerator.GetBytes(12)),
        ciphertext = Base64UrlCodec.Encode(RandomNumberGenerator.GetBytes(5000)),
        tag = Base64UrlCodec.Encode(RandomNumberGenerator.GetBytes(16)),
    };
}
