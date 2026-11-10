using System.Text.Json;
using Nyxite.Contracts.Structure;
using Nyxite.Domain.Structure;

namespace Nyxite.UnitTests.Contracts;

public sealed class PatchTests
{
    private static UpdateFolderRequest Read(string json) => JsonSerializer.Deserialize<UpdateFolderRequest>(json, JsonSerializerOptions.Web)!;

    [Fact]
    public void A_field_that_was_not_sent_differs_from_one_sent_as_null()
    {
        var absent = Read("{}");
        Assert.False(absent.ParentFolderId.IsSet);
        Assert.False(absent.SyncPolicy.IsSet);
        Assert.Null(absent.NameEnc);

        var cleared = Read("""{"parentFolderId":null,"syncPolicy":null,"metadataEnc":null}""");
        Assert.True(cleared.ParentFolderId.IsSet);
        Assert.Null(cleared.ParentFolderId.Value);
        Assert.True(cleared.SyncPolicy.IsSet);
        Assert.True(cleared.MetadataEnc.IsSet);

        var id = Guid.CreateVersion7();
        var set = Read($$"""{"parentFolderId":"{{id}}","syncPolicy":"excluded"}""");
        Assert.Equal(id, set.ParentFolderId.Value);
        Assert.Equal("excluded", set.SyncPolicy.Value);
        Assert.False(set.MetadataEnc.IsSet);
    }

    [Fact]
    public void A_patch_serializes_as_its_value()
    {
        var json = JsonSerializer.Serialize(new UpdateFileRequest("n", null, new Patch<Guid?>(null), default), JsonSerializerOptions.Web);
        Assert.Equal("""{"nameEnc":"n","syncPolicy":null,"parentFolderId":null,"metadataEnc":null}""", json);
    }

    [Fact]
    public void Text_types_are_the_crdt_types_and_a_folder_is_never_its_own_ancestor()
    {
        Assert.Equal(["markdown", "plaintext", "sourcecode"], ContentTypes.All.Where(ContentTypes.IsCrdt).Order());
        Assert.True(SyncPolicies.IsValid("excluded"));
        Assert.False(SyncPolicies.IsValid("pinned-local"));
        var (a, b, c) = (Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid());
        Assert.True(FolderRules.WouldCycle(a, [c, b, a]));
        Assert.True(FolderRules.WouldCycle(a, [a]));
        Assert.False(FolderRules.WouldCycle(a, [c, b]));
    }
}
