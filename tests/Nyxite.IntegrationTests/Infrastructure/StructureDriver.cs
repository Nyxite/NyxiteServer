using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Nyxite.Crypto;

namespace Nyxite.IntegrationTests.Infrastructure;

/// <summary>
/// Drives the structure endpoints the way a client does (server 04 "structure"): it allocates the id, makes the
/// object's key, seals the name with it and wraps the key to its own X-Wing key, so tests can also open what comes back.
/// </summary>
public sealed class StructureDriver(HttpClient client)
{
    /// <summary>The client's key-wrapping seed. The server never sees it.</summary>
    private readonly byte[] _kemSeed = RandomNumberGenerator.GetBytes(XWing.SeedSize);

    public sealed record Sealed(Guid Id, Guid KeyId, byte[] Key);

    public HttpClient Client => client;

    public static string Name(Sealed s, string plaintext) =>
        Base64UrlCodec.Encode(NyxcFrame.Seal(s.Key, s.KeyId, s.Id, ObjectKind.Name, Encoding.UTF8.GetBytes(plaintext)));

    public static string Metadata(Sealed s, string plaintext) =>
        Base64UrlCodec.Encode(NyxcFrame.Seal(s.Key, s.KeyId, s.Id, ObjectKind.Metadata, Encoding.UTF8.GetBytes(plaintext)));

    public static Sealed NewObject() => new(Guid.CreateVersion7(), Guid.CreateVersion7(), RandomNumberGenerator.GetBytes(32));

    public object Wrap(Sealed s) => new
    {
        keyId = s.KeyId,
        ciphertext = Base64UrlCodec.Encode(HybridHpke.Seal(XWing.PublicKeyFromSeed(_kemSeed), "nyxite object key"u8, s.Id.ToByteArray(bigEndian: true), s.Key)),
        generation = 1,
    };

    public async Task<HttpResponseMessage> PostAsync(string path, object body, string? idempotencyKey = "auto")
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/v1" + path) { Content = JsonContent.Create(body) };
        if (idempotencyKey is not null) request.Headers.Add("Idempotency-Key", idempotencyKey == "auto" ? Guid.NewGuid().ToString() : idempotencyKey);
        return await client.SendAsync(request);
    }

    public Task<HttpResponseMessage> PatchAsync(string path, object body) => client.PatchAsJsonAsync("/api/v1" + path, body);

    public Task<HttpResponseMessage> GetAsync(string path) => client.GetAsync("/api/v1" + path);

    public Task<HttpResponseMessage> DeleteAsync(string path) => client.DeleteAsync("/api/v1" + path);

    public async Task<Sealed> ProjectAsync(string name)
    {
        var s = NewObject();
        var response = await PostAsync("/projects", new { id = s.Id, nameEnc = Name(s, name), ownerWrappedKey = Wrap(s) });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return s;
    }

    public async Task<Sealed> FolderAsync(Sealed project, string name, Sealed? parent = null)
    {
        var s = NewObject();
        var response = await PostAsync("/folders",
            new { id = s.Id, projectId = project.Id, parentFolderId = parent?.Id, nameEnc = Name(s, name), ownerWrappedKey = Wrap(s) });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return s;
    }

    public async Task<Sealed> FileAsync(Sealed project, string name, Sealed? folder = null, string contentType = "markdown")
    {
        var s = NewObject();
        var response = await PostAsync("/files", FileBody(s, project, name, folder, contentType));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return s;
    }

    public object FileBody(Sealed s, Sealed project, string name, Sealed? folder = null, string contentType = "markdown") => new
    {
        id = s.Id,
        projectId = project.Id,
        folderId = folder?.Id,
        nameEnc = Name(s, name),
        contentType,
        crdtDocId = contentType is "markdown" or "plaintext" or "sourcecode" ? Guid.CreateVersion7() : (Guid?)null,
        ownerWrappedKey = Wrap(s),
    };

    /// <summary>What a second device does: fetch the wrapped key, unwrap it, open the name.</summary>
    public async Task<string> ReadNameAsync(string kind, Guid id)
    {
        var item = await (await GetAsync($"/{kind}/{id}")).JsonAsync();
        var wrapped = (await (await GetAsync($"/{kind}/{id}/keys")).JsonAsync()).GetProperty("items")[0];
        var key = HybridHpke.Open(_kemSeed, "nyxite object key"u8, id.ToByteArray(bigEndian: true), Base64UrlCodec.Decode(wrapped.GetProperty("ciphertext").GetString()!));
        var aad = NyxcFrame.BuildAad(wrapped.GetProperty("keyId").GetGuid(), id, ObjectKind.Name);
        return Encoding.UTF8.GetString(NyxcFrame.Open(key, Base64UrlCodec.Decode(item.GetProperty("nameEnc").GetString()!), aad));
    }

    /// <summary>Opens the name of a returned object with the wrapped key it carries.</summary>
    public string NameOf(JsonElement item)
    {
        var id = item.GetProperty("id").GetGuid();
        var wrapped = item.GetProperty("wrappedKey");
        var key = HybridHpke.Open(_kemSeed, "nyxite object key"u8, id.ToByteArray(bigEndian: true), Base64UrlCodec.Decode(wrapped.GetProperty("ciphertext").GetString()!));
        var aad = NyxcFrame.BuildAad(wrapped.GetProperty("keyId").GetGuid(), id, ObjectKind.Name);
        return Encoding.UTF8.GetString(NyxcFrame.Open(key, Base64UrlCodec.Decode(item.GetProperty("nameEnc").GetString()!), aad));
    }

    public async Task<List<JsonElement>> ItemsAsync(string path)
    {
        var items = new List<JsonElement>();
        string? cursor = null;
        do
        {
            var page = await (await GetAsync(path + (cursor is null ? "" : (path.Contains('?') ? "&" : "?") + "cursor=" + cursor))).JsonAsync();
            items.AddRange(page.GetProperty("items").EnumerateArray());
            cursor = page.GetProperty("nextCursor").ValueKind == JsonValueKind.Null ? null : page.GetProperty("nextCursor").GetString();
        } while (cursor is not null);

        return items;
    }

    public async Task<List<Guid>> IdsAsync(string path)
    {
        var ids = new List<Guid>();
        string? cursor = null;
        do
        {
            var page = await (await GetAsync(path + (cursor is null ? "" : (path.Contains('?') ? "&" : "?") + "cursor=" + cursor))).JsonAsync();
            ids.AddRange(page.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("id").GetGuid()));
            cursor = page.GetProperty("nextCursor").ValueKind == JsonValueKind.Null ? null : page.GetProperty("nextCursor").GetString();
        } while (cursor is not null);

        return ids;
    }
}
