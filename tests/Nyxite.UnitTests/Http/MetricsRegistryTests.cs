using Nyxite.Application.Diagnostics;
using Nyxite.Server.Http;

namespace Nyxite.UnitTests.Http;

public sealed class MetricsRegistryTests
{
    [Fact]
    public void Counters_are_rendered_in_the_prometheus_text_format()
    {
        using var registry = new MetricsRegistry();

        NyxiteMetrics.AuditEvents.Add(2, new KeyValuePair<string, object?>("action", "test.metrics_event"));

        Assert.Contains("# TYPE nyxite_audit_events_total counter\n", registry.Render());
        Assert.Contains("nyxite_audit_events_total{action=\"test.metrics_event\"} 2\n", registry.Render());
    }

    [Fact]
    public async Task Rendering_while_new_series_are_recorded_does_not_throw()
    {
        using var registry = new MetricsRegistry();

        var writer = Task.Run(() =>
        {
            for (var i = 0; i < 3000; i++)
                NyxiteMetrics.AuditEvents.Add(1, new KeyValuePair<string, object?>("action", $"test.race_{i}"));
        }, TestContext.Current.CancellationToken);

        while (!writer.IsCompleted) registry.Render();
        await writer;
    }
}
