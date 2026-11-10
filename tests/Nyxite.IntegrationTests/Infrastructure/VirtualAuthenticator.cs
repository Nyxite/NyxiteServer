using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Nyxite.Crypto;

namespace Nyxite.IntegrationTests.Infrastructure;

/// <summary>
/// A software WebAuthn authenticator (ES256, attestation "none", user verification set): builds the
/// RegistrationResponseJSON / AuthenticationResponseJSON a browser would send, from the server's options JSON.
/// </summary>
public sealed class VirtualAuthenticator : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private uint _counter;

    public VirtualAuthenticator(string rpId = NyxiteApp.RpId, string origin = NyxiteApp.Origin)
    {
        RpId = rpId;
        Origin = origin;
    }

    public string RpId { get; }
    public string Origin { get; }
    public byte[] CredentialId { get; } = RandomNumberGenerator.GetBytes(16);
    public byte[]? UserHandle { get; private set; }

    public JsonObject Create(JsonElement options)
    {
        var challenge = options.GetProperty("challenge").GetString()!;
        UserHandle = Base64UrlCodec.Decode(options.GetProperty("user").GetProperty("id").GetString()!);
        var clientData = ClientData("webauthn.create", challenge);
        var authData = AuthData(attested: true);

        var cbor = new CborWriter(CborConformanceMode.Ctap2Canonical);
        cbor.WriteStartMap(3);
        cbor.WriteTextString("fmt"); cbor.WriteTextString("none");
        cbor.WriteTextString("attStmt"); cbor.WriteStartMap(0); cbor.WriteEndMap();
        cbor.WriteTextString("authData"); cbor.WriteByteString(authData);
        cbor.WriteEndMap();

        var id = Base64UrlCodec.Encode(CredentialId);
        return new JsonObject
        {
            ["id"] = id,
            ["rawId"] = id,
            ["type"] = "public-key",
            ["response"] = new JsonObject
            {
                ["clientDataJSON"] = Base64UrlCodec.Encode(clientData),
                ["attestationObject"] = Base64UrlCodec.Encode(cbor.Encode()),
                ["transports"] = new JsonArray("internal"),
            },
            ["clientExtensionResults"] = new JsonObject(),
        };
    }

    public JsonObject Get(JsonElement options, bool corruptSignature = false)
    {
        var challenge = options.GetProperty("challenge").GetString()!;
        var clientData = ClientData("webauthn.get", challenge);
        var authData = AuthData(attested: false);
        var signature = _key.SignData([.. authData, .. SHA256.HashData(clientData)], HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        if (corruptSignature) signature[^1] ^= 1;

        var id = Base64UrlCodec.Encode(CredentialId);
        return new JsonObject
        {
            ["id"] = id,
            ["rawId"] = id,
            ["type"] = "public-key",
            ["response"] = new JsonObject
            {
                ["clientDataJSON"] = Base64UrlCodec.Encode(clientData),
                ["authenticatorData"] = Base64UrlCodec.Encode(authData),
                ["signature"] = Base64UrlCodec.Encode(signature),
                ["userHandle"] = UserHandle is null ? null : Base64UrlCodec.Encode(UserHandle),
            },
            ["clientExtensionResults"] = new JsonObject(),
        };
    }

    private byte[] ClientData(string type, string challenge) => Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
    {
        type, challenge, origin = Origin, crossOrigin = false,
    }));

    private byte[] AuthData(bool attested)
    {
        var data = new List<byte>(SHA256.HashData(Encoding.UTF8.GetBytes(RpId)));
        const byte up = 0x01, uv = 0x04, at = 0x40;
        data.Add((byte)(up | uv | (attested ? at : 0)));
        var counter = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(counter, ++_counter);
        data.AddRange(counter);
        if (!attested) return [.. data];

        data.AddRange(new byte[16]); // AAGUID
        var len = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(len, (ushort)CredentialId.Length);
        data.AddRange(len);
        data.AddRange(CredentialId);

        var p = _key.ExportParameters(false);
        var cose = new CborWriter(CborConformanceMode.Ctap2Canonical);
        cose.WriteStartMap(5);
        cose.WriteInt32(1); cose.WriteInt32(2);    // kty: EC2
        cose.WriteInt32(3); cose.WriteInt32(-7);   // alg: ES256
        cose.WriteInt32(-1); cose.WriteInt32(1);   // crv: P-256
        cose.WriteInt32(-2); cose.WriteByteString(p.Q.X!);
        cose.WriteInt32(-3); cose.WriteByteString(p.Q.Y!);
        cose.WriteEndMap();
        data.AddRange(cose.Encode());
        return [.. data];
    }

    public void Dispose() => _key.Dispose();
}
