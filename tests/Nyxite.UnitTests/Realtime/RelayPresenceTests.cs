using System.Collections;
using System.Reflection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Nyxite.Application;
using Nyxite.Application.Content;
using Nyxite.Server.Realtime;

namespace Nyxite.UnitTests.Realtime;

public sealed class RelayPresenceTests
{
    private static RelayMember Member(Guid userId) => new(PresenceDto.ForUser(userId, "Ada"), userId, Guid.NewGuid());

    private static int RoomCount(RelayPresence presence) =>
        ((ICollection)typeof(RelayPresence).GetField("_rooms", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(presence)!).Count;

    /// <summary>05 §5.9: a room is forgotten once its last member leaves, and a later join opens a fresh one.</summary>
    [Fact]
    public void A_room_is_forgotten_when_its_last_member_leaves_and_opens_again_on_the_next_join()
    {
        var presence = new RelayPresence();
        var fileId = Guid.NewGuid();
        var userId = Guid.NewGuid();

        presence.Join(fileId, "a", Member(userId));
        presence.Join(fileId, "b", Member(userId));
        Assert.True(presence.Leave(fileId, "a"));
        Assert.Equal(1, RoomCount(presence));
        Assert.True(presence.Leave(fileId, "b"));
        Assert.Equal(0, RoomCount(presence));
        Assert.False(presence.Leave(fileId, "b"));
        Assert.Empty(presence.Roster(fileId));

        presence.Join(fileId, "c", Member(userId));
        Assert.True(presence.IsIn(fileId, "c"));
        Assert.Single(presence.Roster(fileId));
    }

    /// <summary>
    /// F3: forgetting an empty room must not lose a join that races the last leave. Each round one connection leaves
    /// the room it alone was in while another joins it; the joiner must always end up in the room that the map holds.
    /// </summary>
    [Fact]
    public async Task A_join_that_races_the_last_leave_is_never_lost()
    {
        var presence = new RelayPresence();
        var userId = Guid.NewGuid();
        for (var round = 0; round < 2000; round++)
        {
            var fileId = Guid.NewGuid();
            presence.Join(fileId, "leaver", Member(userId));
            using var start = new Barrier(2);
            var leave = Task.Run(() =>
            {
                start.SignalAndWait();
                presence.Leave(fileId, "leaver");
            }, TestContext.Current.CancellationToken);
            var join = Task.Run(() =>
            {
                start.SignalAndWait();
                presence.Join(fileId, "joiner", Member(userId));
            }, TestContext.Current.CancellationToken);
            await Task.WhenAll(leave, join);

            Assert.True(presence.IsIn(fileId, "joiner"), $"The join of round {round} was lost.");
            Assert.Contains(presence.Members(), m => m.FileId == fileId && m.ConnectionId == "joiner");
            Assert.True(presence.Leave(fileId, "joiner"));
        }

        Assert.Equal(0, RoomCount(presence));
    }

    /// <summary>F6, 14 §14.4: a re-check interval that is zero or negative fails the options instead of spinning the worker.</summary>
    [Theory]
    [InlineData("00:00:00")]
    [InlineData("-00:00:01")]
    public void A_non_positive_recheck_interval_is_refused(string interval)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Relay:AccessRecheckInterval"] = interval })
            .Build();
        using var services = new ServiceCollection().AddNyxiteAuth(configuration).BuildServiceProvider();

        var refused = Assert.Throws<OptionsValidationException>(() => services.GetRequiredService<IOptions<RelayOptions>>().Value);
        Assert.Contains("Relay:AccessRecheckInterval must be positive.", refused.Failures);
    }
}
