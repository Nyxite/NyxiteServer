using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Nyxite.Crypto;
using Nyxite.IntegrationTests.Infrastructure;
using Nyxite.IntegrationTests.Sharing;
using static Nyxite.IntegrationTests.Sharing.SharingTests;

namespace Nyxite.IntegrationTests.Content;

/// <summary>
/// Phase 2.4 server (P2.4-SRV-1): version history as records and ciphertext only. A client lists versions, fetches two
/// of them, decrypts, checks the BLAKE3 address and diffs them itself (P2.4-TC-1), and restores an older version by
/// recording the restore and writing a new head through the normal write path, which leaves every prior version as it
/// was (P2.4-TC-2). The client work is done here the way a client does it: keys stay local and the server only sees
/// frames, hashes and sequence numbers.
/// </summary>
public sealed class VersionHistoryTests(PostgresFixture pg)
{
    private static string Hash(string text) => Base64UrlCodec.Encode(Blake3.Hash(Encoding.UTF8.GetBytes(text)));

    private static byte[] Seal(StructureDriver.Sealed file, ObjectKind kind, string text) =>
        NyxcFrame.Seal(file.Key, file.KeyId, file.Id, kind, Encoding.UTF8.GetBytes(text));

    private static Task<HttpResponseMessage> PutAsync(StructureDriver s, StructureDriver.Sealed file, string path, ObjectKind kind, string text,
        Action<HttpRequestMessage> headers)
    {
        var request = new HttpRequestMessage(HttpMethod.Put, $"/api/v1/files/{file.Id}/{path}")
        {
            Content = new ByteArrayContent(Seal(file, kind, text)) { Headers = { ContentType = new("application/octet-stream") } },
        };
        request.Headers.Add("Nyxite-Content-Hash", Hash(text));
        request.Headers.Add("Nyxite-Key-Id", file.KeyId.ToString());
        headers(request);
        return s.Client.SendAsync(request);
    }

    private static Task<HttpResponseMessage> BlobAsync(StructureDriver s, StructureDriver.Sealed file, long parentSeq, string text) =>
        PutAsync(s, file, "blob", ObjectKind.Blob, text, r => r.Headers.TryAddWithoutValidation("If-Match", parentSeq.ToString()));

    private static Task<HttpResponseMessage> SnapshotAsync(StructureDriver s, StructureDriver.Sealed file, long crdtSeq, string text) =>
        PutAsync(s, file, "snapshot", ObjectKind.Snapshot, text, r => r.Headers.Add("Nyxite-Snapshot-Seq", crdtSeq.ToString()));

    private static async Task<long> SubmitAsync(StructureDriver s, StructureDriver.Sealed file, string text)
    {
        var response = await s.PostAsync($"/files/{file.Id}/crdt/log", new
        {
            updates = new[] { new { clientUpdateId = Guid.CreateVersion7(), keyId = file.KeyId, updateEnc = Base64UrlCodec.Encode(Seal(file, ObjectKind.Crdt, text)) } },
        }, null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.JsonAsync()).GetProperty("acks")[0].GetProperty("seq").GetInt64();
    }

    private static Task<HttpResponseMessage> RestoreAsync(StructureDriver s, StructureDriver.Sealed file, long seq, string? idempotencyKey = "auto") =>
        s.PostAsync($"/files/{file.Id}/restore", new { seq }, idempotencyKey);

    /// <summary>
    /// What a client does to open a version: fetch the ciphertext, unwrap nothing new (the key is local), open the frame
    /// and check that the plaintext hashes to the content address the version names. A mismatch is rejected.
    /// </summary>
    private static async Task<string> OpenVersionAsync(StructureDriver s, StructureDriver.Sealed file, byte[] key, long seq, ObjectKind kind)
    {
        var meta = await (await s.GetAsync($"/files/{file.Id}/versions/{seq}")).JsonAsync();
        var response = await s.GetAsync($"/files/{file.Id}/versions/{seq}/blob");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(meta.GetProperty("keyId").GetGuid(), Guid.Parse(response.Headers.GetValues("Nyxite-Key-Id").Single()));
        Assert.Equal($"\"{meta.GetProperty("contentHash").GetString()}\"", response.Headers.ETag!.Tag);
        var frame = await response.Content.ReadAsByteArrayAsync();
        var plaintext = NyxcFrame.Open(key, frame, NyxcFrame.BuildAad(file.KeyId, file.Id, kind));
        Assert.Equal(meta.GetProperty("contentHash").GetString(), Base64UrlCodec.Encode(Blake3.Hash(plaintext)));
        return Encoding.UTF8.GetString(plaintext);
    }

    /// <summary>A client-side line diff (longest common subsequence), as each client computes it after decrypting.</summary>
    private static List<string> Diff(string before, string after)
    {
        var a = before.Split('\n');
        var b = after.Split('\n');
        var lcs = new int[a.Length + 1, b.Length + 1];
        for (var i = a.Length - 1; i >= 0; i--)
        for (var j = b.Length - 1; j >= 0; j--)
            lcs[i, j] = a[i] == b[j] ? lcs[i + 1, j + 1] + 1 : Math.Max(lcs[i + 1, j], lcs[i, j + 1]);
        var result = new List<string>();
        int x = 0, y = 0;
        while (x < a.Length && y < b.Length)
        {
            if (a[x] == b[y]) { result.Add("  " + a[x]); x++; y++; }
            else if (lcs[x + 1, y] >= lcs[x, y + 1]) result.Add("- " + a[x++]);
            else result.Add("+ " + b[y++]);
        }

        result.AddRange(a[x..].Select(l => "- " + l));
        result.AddRange(b[y..].Select(l => "+ " + l));
        return result;
    }

    /// <summary>Every version row and the bytes the server serves for it, to prove a restore changed none of them.</summary>
    private static async Task<List<string>> HistoryAsync(NyxiteApp app, StructureDriver s, StructureDriver.Sealed file)
    {
        var rows = await Sql.ListAsync<string>(app.ConnectionString,
            "SELECT seq || ':' || encode(content_hash, 'hex') || ':' || blob_ref || ':' || size_cipher || ':' || coalesce(restored_from_seq::text, '-') FROM file_versions WHERE file_id = @f ORDER BY seq",
            ("f", file.Id));
        var history = new List<string>();
        foreach (var row in rows)
        {
            var seq = row.Split(':')[0];
            var bytes = await (await s.GetAsync($"/files/{file.Id}/versions/{seq}/blob")).Content.ReadAsByteArrayAsync();
            history.Add(row + ":" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)));
        }

        return history;
    }

    private static async Task<Guid> ShareAsync(Member owner, StructureDriver.Sealed file, Member grantee, string permission)
    {
        var publicKey = await DirectoryKeyAsync(owner, grantee.Id);
        var created = await owner.S.PostAsync("/shares", new
        {
            targetType = "file", targetId = file.Id, kind = "user_grant", granteeId = grantee.Id, permission,
            wrappedKeys = new[]
            {
                new
                {
                    keyId = file.KeyId, memberId = grantee.Id, ciphertext = Base64UrlCodec.Encode(ObjectKeyWrap.Seal(publicKey, file.Id, file.KeyId, file.Key)),
                    generation = 1, algId = CryptoSuite.HpkeAlgId,
                },
            },
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        return (await created.JsonAsync()).GetProperty("id").GetGuid();
    }

    private static async Task<byte[]> UnwrapAsync(Member member, Guid fileId)
    {
        var wrap = (await (await member.S.GetAsync($"/files/{fileId}/keys")).JsonAsync()).GetProperty("items").EnumerateArray().Single();
        return ObjectKeyWrap.Open(member.Seed, fileId, wrap.GetProperty("keyId").GetGuid(), Base64UrlCodec.Decode(wrap.GetProperty("ciphertext").GetString()!));
    }

    // ---------------------------------------------------------------- P2.4-TC-1: client-side diff

    /// <summary>
    /// P2.4-TC-1, server side: a note with several snapshot versions. Owner and a read-only grantee each fetch two
    /// versions, decrypt them with their own key, check the BLAKE3 address and diff them locally. The server has no diff
    /// route in its route table or its contract, and nothing it stores or serves is plaintext.
    /// </summary>
    [Fact]
    public async Task Two_versions_are_fetched_decrypted_verified_and_diffed_on_the_client()
    {
        var logs = new CapturingLoggerProvider();
        await using var app = App(await pg.CreateDatabaseAsync(), logs);
        var owner = await MemberAsync(app, "Owner");
        var reader = await MemberAsync(app, "Reader");
        var file = await owner.S.FileAsync(await owner.S.ProjectAsync("p"), "note.md");

        const string first = "# Plan\nbuy milk\ncall Ada";
        const string second = "# Plan\nbuy oat milk\ncall Ada\nwrite report";
        var seq = await SubmitAsync(owner.S, file, "update 1");
        Assert.Equal(HttpStatusCode.Created, (await SnapshotAsync(owner.S, file, seq, first)).StatusCode);
        seq = await SubmitAsync(owner.S, file, "update 2");
        Assert.Equal(HttpStatusCode.Created, (await SnapshotAsync(owner.S, file, seq, second)).StatusCode);
        await ShareAsync(owner, file, reader, "read");

        var expected = new List<string> { "  # Plan", "- buy milk", "+ buy oat milk", "  call Ada", "+ write report" };
        foreach (var (member, key) in new[] { (owner, file.Key), (reader, await UnwrapAsync(reader, file.Id)) })
        {
            var versions = await member.S.ItemsAsync($"/files/{file.Id}/versions");
            Assert.Equal([2L, 1L], versions.Select(v => v.GetProperty("seq").GetInt64()));
            Assert.Equal([true, false], versions.Select(v => v.GetProperty("isHead").GetBoolean()));
            Assert.All(versions, v => Assert.Equal(owner.Id, v.GetProperty("authorId").GetGuid()));
            Assert.All(versions, v => Assert.Equal(JsonValueKind.Null, v.GetProperty("restoredFromSeq").ValueKind));

            var older = await OpenVersionAsync(member.S, file, key, 1, ObjectKind.Snapshot);
            var newer = await OpenVersionAsync(member.S, file, key, 2, ObjectKind.Snapshot);
            Assert.Equal(expected, Diff(older, newer));
        }

        // A reader sees the history but cannot record a restore.
        Assert.Equal("acl_denied", await (await RestoreAsync(reader.S, file, 1)).ProblemCodeAsync());

        // No diff anywhere: not as a request, not as a route, not in the contract.
        foreach (var path in new[] { $"/files/{file.Id}/diff?from=1&to=2", $"/files/{file.Id}/versions/diff?from=1&to=2", $"/files/{file.Id}/versions/1/diff/2" })
            Assert.Equal(HttpStatusCode.NotFound, (await owner.S.GetAsync(path)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await owner.S.Client.PostAsJsonAsync($"/api/v1/files/{file.Id}/diff", new { from = 1, to = 2 })).StatusCode);
        var routes = app.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>().Select(e => e.RoutePattern.RawText ?? "").ToList();
        Assert.Contains(routes, r => r.EndsWith("/versions/{seq:long}/blob", StringComparison.Ordinal));
        Assert.DoesNotContain(routes, r => r.Contains("diff", StringComparison.OrdinalIgnoreCase));
        var paths = Nyxite.Server.Http.OpenApiDocument.Load()["paths"]!.AsObject().Select(p => p.Key).ToList();
        Assert.Contains("/files/{id}/versions/{seq}/blob", paths);
        Assert.DoesNotContain(paths, p => p.Contains("diff", StringComparison.OrdinalIgnoreCase));

        await AssertNothingLeaksAsync(app, logs, Encoding.UTF8.GetBytes("buy oat milk"), Encoding.UTF8.GetBytes("write report"), file.Key);
    }

    // ---------------------------------------------------------------- P2.4-TC-2: non-destructive restore

    /// <summary>
    /// P2.4-TC-2 for a binary file: the restore call carries only <c>seq</c> and records an audit event, the restored
    /// bytes arrive as a new head through <c>PUT /blob</c>, which carries the link, and every prior version is unchanged.
    /// The restore is idempotent under its key and checked for key, reach and policy.
    /// </summary>
    [Fact]
    public async Task Restoring_a_binary_version_writes_a_new_head_through_put_blob_and_keeps_every_version()
    {
        var logs = new CapturingLoggerProvider();
        await using var app = App(await pg.CreateDatabaseAsync(), logs);
        var owner = await MemberAsync(app, "Owner");
        var file = await owner.S.FileAsync(await owner.S.ProjectAsync("p"), "scan.bin", contentType: "binary");
        await BlobAsync(owner.S, file, 0, "scan one");
        await BlobAsync(owner.S, file, 1, "scan two");
        await BlobAsync(owner.S, file, 2, "scan three");
        var before = await HistoryAsync(app, owner.S, file);

        // The restore call takes no content and changes no version.
        Assert.Equal(HttpStatusCode.BadRequest, (await RestoreAsync(owner.S, file, 1, idempotencyKey: null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await RestoreAsync(owner.S, file, 9)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await RestoreAsync(owner.S, file, 0)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await RestoreAsync(owner.S, file, 1, "restore-key-1")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await RestoreAsync(owner.S, file, 1, "restore-key-1")).StatusCode);
        Assert.Equal("idempotency_conflict", await (await RestoreAsync(owner.S, file, 2, "restore-key-1")).ProblemCodeAsync());
        Assert.Equal(before, await HistoryAsync(app, owner.S, file));
        Assert.Equal(3, (await (await owner.S.GetAsync($"/files/{file.Id}")).JsonAsync()).GetProperty("currentVersionSeq").GetInt64());

        // The client opens version 1, seals it again and writes it as the new head.
        var restoredText = await OpenVersionAsync(owner.S, file, file.Key, 1, ObjectKind.Blob);
        var written = await BlobAsync(owner.S, file, 3, restoredText);
        Assert.Equal(HttpStatusCode.Created, written.StatusCode);
        var head = await written.JsonAsync();
        Assert.Equal(4, head.GetProperty("seq").GetInt64());
        Assert.True(head.GetProperty("isHead").GetBoolean());
        Assert.Equal(1, head.GetProperty("restoredFromSeq").GetInt64());
        Assert.Equal("scan one", await OpenVersionAsync(owner.S, file, file.Key, 4, ObjectKind.Blob));

        // All prior versions are intact, and the history lists the restore as a version of its own.
        Assert.Equal(before, (await HistoryAsync(app, owner.S, file)).Take(3));
        var versions = await owner.S.ItemsAsync($"/files/{file.Id}/versions");
        Assert.Equal([4L, 3L, 2L, 1L], versions.Select(v => v.GetProperty("seq").GetInt64()));
        Assert.Equal(1, versions[0].GetProperty("restoredFromSeq").GetInt64());

        // The next write is no restore.
        var next = await (await BlobAsync(owner.S, file, 4, "scan five")).JsonAsync();
        Assert.Equal(JsonValueKind.Null, next.GetProperty("restoredFromSeq").ValueKind);

        // One audit event for the replayed restore, naming the file and the source seq only.
        var audit = await Sql.ListAsync<string>(app.ConnectionString,
            "SELECT target_type || ':' || target_id || ':' || detail::text FROM audit_log WHERE action = 'version.restore'");
        Assert.Equal([$"file:{file.Id}:{{\"seq\": 1}}"], audit);

        // A file excluded from sync takes no content, so no restore can complete for it.
        Assert.Equal(HttpStatusCode.OK, (await owner.S.PatchAsync($"/files/{file.Id}", new { syncPolicy = "excluded" })).StatusCode);
        Assert.Equal("excluded_content", await (await RestoreAsync(owner.S, file, 2)).ProblemCodeAsync());

        await AssertNothingLeaksAsync(app, logs, Encoding.UTF8.GetBytes("scan one"), Encoding.UTF8.GetBytes("scan three"), file.Key);
    }

    /// <summary>
    /// P2.4-TC-2 for a text file: the client turns the current document into the restored one with a CRDT update on the
    /// normal update path and then snapshots. The snapshot is the new head and carries the link; the update log and the
    /// earlier snapshots stay.
    /// </summary>
    [Fact]
    public async Task Restoring_a_text_version_arrives_as_a_crdt_update_and_snapshot_and_keeps_every_version()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Owner");
        var file = await owner.S.FileAsync(await owner.S.ProjectAsync("p"), "note.md");
        var seq = await SubmitAsync(owner.S, file, "insert draft");
        await SnapshotAsync(owner.S, file, seq, "draft");
        seq = await SubmitAsync(owner.S, file, "insert more");
        await SnapshotAsync(owner.S, file, seq, "draft and more");
        var before = await HistoryAsync(app, owner.S, file);
        var logBefore = (await (await owner.S.GetAsync($"/files/{file.Id}/crdt/log?since=0")).JsonAsync()).GetProperty("items").GetArrayLength();

        Assert.Equal(HttpStatusCode.NoContent, (await RestoreAsync(owner.S, file, 1)).StatusCode);
        var restoredText = await OpenVersionAsync(owner.S, file, file.Key, 1, ObjectKind.Snapshot);
        var restoreUpdate = await SubmitAsync(owner.S, file, "delete ' and more'");
        var snapshot = await SnapshotAsync(owner.S, file, restoreUpdate, restoredText);
        Assert.Equal(HttpStatusCode.Created, snapshot.StatusCode);
        var head = await snapshot.JsonAsync();
        Assert.Equal(3, head.GetProperty("seq").GetInt64());
        Assert.Equal(1, head.GetProperty("restoredFromSeq").GetInt64());
        Assert.Equal(restoreUpdate, head.GetProperty("crdtSeq").GetInt64());

        var current = await (await owner.S.GetAsync($"/files/{file.Id}/snapshot")).Content.ReadAsByteArrayAsync();
        Assert.Equal("draft", Encoding.UTF8.GetString(NyxcFrame.Open(file.Key, current,
            NyxcFrame.BuildAad(file.KeyId, file.Id, ObjectKind.Snapshot))));
        Assert.Equal(before, (await HistoryAsync(app, owner.S, file)).Take(2));
        Assert.Equal(logBefore + 1, (await (await owner.S.GetAsync($"/files/{file.Id}/crdt/log?since=0")).JsonAsync()).GetProperty("items").GetArrayLength());
    }

    /// <summary>
    /// The link belongs to the account that recorded the restore: a collaborator's write in between is no restore and
    /// leaves the link pending, and the restorer's own upload carries it even when it lost LWW and is kept as a sibling.
    /// </summary>
    [Fact]
    public async Task Only_the_restoring_accounts_next_version_carries_the_link_even_as_a_kept_lww_loser()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Owner");
        var writer = await MemberAsync(app, "Writer");
        var file = await owner.S.FileAsync(await owner.S.ProjectAsync("p"), "drawing.ink", contentType: "ink");
        await ShareAsync(owner, file, writer, "write");
        await BlobAsync(owner.S, file, 0, "strokes one");
        await BlobAsync(owner.S, file, 1, "strokes two");

        Assert.Equal(HttpStatusCode.NoContent, (await RestoreAsync(owner.S, file, 1)).StatusCode);
        // The collaborator writes first: its version is the head and is not a restore.
        var other = await (await BlobAsync(writer.S, file, 2, "collaborator strokes")).JsonAsync();
        Assert.Equal(3, other.GetProperty("seq").GetInt64());
        Assert.Equal(JsonValueKind.Null, other.GetProperty("restoredFromSeq").ValueKind);

        // The restorer's upload was based on version 2, so it loses LWW, is kept, and carries the link.
        var lost = await BlobAsync(owner.S, file, 2, "strokes one");
        Assert.Equal(HttpStatusCode.Conflict, lost.StatusCode);
        var sibling = (await lost.JsonAsync()).GetProperty("sibling");
        Assert.Equal(4, sibling.GetProperty("seq").GetInt64());
        Assert.False(sibling.GetProperty("isHead").GetBoolean());
        Assert.Equal(1, sibling.GetProperty("restoredFromSeq").GetInt64());

        // The link was taken: the restorer's retry on top of the head is a plain write.
        var retry = await (await BlobAsync(owner.S, file, 3, "strokes one")).JsonAsync();
        Assert.Equal(JsonValueKind.Null, retry.GetProperty("restoredFromSeq").ValueKind);
        Assert.Equal((long?)null, await Sql.ScalarAsync<long?>(app.ConnectionString, "SELECT pending_restore_seq FROM files WHERE id = @f", ("f", file.Id)));
    }

    /// <summary>
    /// Every version records the seq it was based on (<c>parentSeq</c>), so any member, a grantee included, flags kept
    /// LWW losers from the history alone: replaying the list in seq order, a version whose parent was not the head of its
    /// moment lost.
    /// </summary>
    [Fact]
    public async Task Every_version_records_its_parent_so_a_grantee_flags_lww_losers_from_the_history()
    {
        await using var app = App(await pg.CreateDatabaseAsync());
        var owner = await MemberAsync(app, "Owner");
        var writer = await MemberAsync(app, "Writer");
        var reader = await MemberAsync(app, "Reader");
        var file = await owner.S.FileAsync(await owner.S.ProjectAsync("p"), "drawing.ink", contentType: "ink");
        await ShareAsync(owner, file, writer, "write");
        await ShareAsync(owner, file, reader, "read");
        await BlobAsync(owner.S, file, 0, "strokes one");
        await BlobAsync(writer.S, file, 1, "writer strokes");
        Assert.Equal(HttpStatusCode.Conflict, (await BlobAsync(owner.S, file, 1, "owner strokes")).StatusCode);
        await BlobAsync(owner.S, file, 2, "strokes merged");

        var versions = (await (await reader.S.GetAsync($"/files/{file.Id}/versions")).JsonAsync()).GetProperty("items").EnumerateArray()
            .OrderBy(v => v.GetProperty("seq").GetInt64()).ToList();
        Assert.Equal([0L, 1L, 1L, 2L], versions.Select(v => v.GetProperty("parentSeq").GetInt64()));
        long head = 0;
        var losers = new List<long>();
        foreach (var v in versions)
        {
            if (v.GetProperty("parentSeq").GetInt64() == head) head = v.GetProperty("seq").GetInt64();
            else losers.Add(v.GetProperty("seq").GetInt64());
        }

        Assert.Equal([3L], losers);
        Assert.Equal(4, head);
    }

    /// <summary>
    /// A recorded restore that no version of the restoring account follows within <c>Limits:RestoreMarkLifetime</c>
    /// (10 minutes by default, 2 minutes here) lapses, so a later unrelated write is not labelled a restore.
    /// </summary>
    [Fact]
    public async Task A_restore_mark_that_no_save_follows_in_time_lapses()
    {
        await using var app = App(await pg.CreateDatabaseAsync(), overrides: new Dictionary<string, string?>
        {
            ["Relay:AccessRecheckInterval"] = "01:00:00", ["Limits:RestoreMarkLifetime"] = "00:02:00",
        });
        var owner = await MemberAsync(app, "Owner");
        var file = await owner.S.FileAsync(await owner.S.ProjectAsync("p"), "drawing.ink", contentType: "ink");
        await BlobAsync(owner.S, file, 0, "strokes one");
        await BlobAsync(owner.S, file, 1, "strokes two");

        Assert.Equal(HttpStatusCode.NoContent, (await RestoreAsync(owner.S, file, 1)).StatusCode);
        app.Clock.Advance(TimeSpan.FromMinutes(1));
        var inTime = await (await BlobAsync(owner.S, file, 2, "strokes one")).JsonAsync();
        Assert.Equal(1, inTime.GetProperty("restoredFromSeq").GetInt64());

        Assert.Equal(HttpStatusCode.NoContent, (await RestoreAsync(owner.S, file, 2)).StatusCode);
        app.Clock.Advance(TimeSpan.FromMinutes(3));
        var late = await (await BlobAsync(owner.S, file, 3, "unrelated strokes")).JsonAsync();
        Assert.Equal(JsonValueKind.Null, late.GetProperty("restoredFromSeq").ValueKind);
        Assert.Equal((long?)null, await Sql.ScalarAsync<long?>(app.ConnectionString, "SELECT pending_restore_seq FROM files WHERE id = @f", ("f", file.Id)));
    }
}
