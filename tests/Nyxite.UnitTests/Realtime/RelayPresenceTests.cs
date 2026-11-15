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

    /// <summary>R2: a full room refuses a new connection, also when joins race for the last slot, but keeps one already in it.</summary>
    [Fact]
    public async Task A_room_never_holds_more_connections_than_its_cap()
    {
        var presence = new RelayPresence();
        var fileId = Guid.NewGuid();
        var userId = Guid.NewGuid();
        var joined = await Task.WhenAll(Enumerable.Range(0, 64).Select(i =>
            Task.Run(() => presence.TryJoin(fileId, $"c{i}", Member(userId), 10), TestContext.Current.CancellationToken)));

        Assert.Equal(10, joined.Count(j => j));
        Assert.Equal(10, presence.ConnectionCount(fileId));
        var member = presence.Members().First().ConnectionId;
        Assert.True(presence.TryJoin(fileId, member, Member(userId), 10));
        Assert.False(presence.TryJoin(fileId, "late", Member(userId), 10));
        Assert.Equal(1, presence.RoomCount(member));
    }

    /// <summary>R2: the awareness budget holds one second's worth and refills with time, never above that.</summary>
    [Fact]
    public void The_awareness_budget_holds_one_second_and_refills()
    {
        var time = new SteppedTime();
        var budget = new AwarenessBudget(60, time.GetTimestamp());
        Assert.Equal(60, Enumerable.Range(0, 100).Count(_ => budget.TryTake(time)));
        time.Step(TimeSpan.FromMilliseconds(500));
        Assert.Equal(30, Enumerable.Range(0, 100).Count(_ => budget.TryTake(time)));
        time.Step(TimeSpan.FromMinutes(5));
        Assert.Equal(60, Enumerable.Range(0, 100).Count(_ => budget.TryTake(time)));
    }

    private sealed class SteppedTime : TimeProvider
    {
        private long _ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _ticks;
        public void Step(TimeSpan by) => _ticks += by.Ticks;
    }

    /// <summary>R2, 14 §14.4: a relay limit that is zero or negative fails the options at startup.</summary>
    [Theory]
    [InlineData("Relay:AwarenessPerSecond")]
    [InlineData("Relay:MaxConnectionsPerRoom")]
    [InlineData("Relay:MaxRoomsPerConnection")]
    public void A_non_positive_relay_limit_is_refused(string setting)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { [setting] = "0" }).Build();
        using var services = new ServiceCollection().AddNyxiteAuth(configuration).BuildServiceProvider();

        var refused = Assert.Throws<OptionsValidationException>(() => services.GetRequiredService<IOptions<RelayOptions>>().Value);
        Assert.Contains($"{setting} must be positive.", refused.Failures);
    }

    /// <summary>R5: a targeted re-check matches a member by its account, its link share or the file of its room.</summary>
    [Fact]
    public void An_access_scope_matches_members_by_account_share_or_file()
    {
        var user = Guid.NewGuid();
        var share = Guid.NewGuid();
        var file = Guid.NewGuid();
        var merged = RelayAccessScope.Merge([RelayAccessScope.ForUser(user), RelayAccessScope.ForShare(share), RelayAccessScope.ForFiles([file])]);

        Assert.True(merged.Matches(Guid.NewGuid(), user, null));
        Assert.True(merged.Matches(Guid.NewGuid(), null, share));
        Assert.True(merged.Matches(file, Guid.NewGuid(), null));
        Assert.False(merged.Matches(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid()));
        Assert.True(RelayAccessScope.ForFiles([]).IsEmpty);
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
