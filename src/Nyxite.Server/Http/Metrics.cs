using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Nyxite.Application.Diagnostics;

namespace Nyxite.Server.Http;

/// <summary>
/// Collects the server's metrics and renders them in the Prometheus text format (14 §14.5). It listens to the request
/// metrics ASP.NET Core publishes and to <see cref="NyxiteMetrics"/>. Written in-house on <see cref="MeterListener"/>,
/// because the OpenTelemetry Prometheus exporter is only published as a pre-release package.
/// </summary>
public sealed class MetricsRegistry : IDisposable
{
    private static readonly string[] Meters = [NyxiteMetrics.MeterName, "Microsoft.AspNetCore.Hosting"];

    /// <summary>Only these request tags are kept, so the number of series stays bounded and no URL value is exported.</summary>
    private static readonly HashSet<string> RequestTags = ["http.request.method", "http.route", "http.response.status_code"];

    private static readonly double[] Buckets = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

    private readonly MeterListener _listener = new();
    private readonly ConcurrentDictionary<(string Name, string Labels), Series> _series = new();

    private sealed class Series(bool histogram, bool monotonic)
    {
        public readonly bool Histogram = histogram;
        public readonly bool Monotonic = monotonic;
        public readonly long[] BucketCounts = new long[Buckets.Length];
        public double Sum;
        public long Count;
    }

    public MetricsRegistry()
    {
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (Meters.Contains(instrument.Meter.Name)) listener.EnableMeasurementEvents(instrument);
        };
        _listener.SetMeasurementEventCallback<long>((i, value, tags, _) => Record(i, value, tags));
        _listener.SetMeasurementEventCallback<int>((i, value, tags, _) => Record(i, value, tags));
        _listener.SetMeasurementEventCallback<double>((i, value, tags, _) => Record(i, value, tags));
        _listener.Start();
    }

    private void Record(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        var own = instrument.Meter.Name == NyxiteMetrics.MeterName;
        var labels = new List<string>(tags.Length);
        foreach (var tag in tags)
        {
            if (own || RequestTags.Contains(tag.Key)) labels.Add($"{Name(tag.Key)}=\"{Escape(tag.Value?.ToString() ?? "")}\"");
        }

        labels.Sort(StringComparer.Ordinal);
        var type = instrument.GetType();
        var histogram = type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Histogram<>);
        var monotonic = type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Counter<>);
        var series = _series.GetOrAdd((Name(instrument.Name), string.Join(",", labels)), _ => new Series(histogram, monotonic));
        lock (series)
        {
            series.Sum += value;
            series.Count++;
            if (!histogram) return;
            for (var b = 0; b < Buckets.Length; b++)
            {
                if (value <= Buckets[b]) series.BucketCounts[b]++;
            }
        }
    }

    public string Render()
    {
        var text = new StringBuilder();
        // ToArray() on the dictionary itself is an atomic snapshot. LINQ would copy through ICollection.CopyTo, which
        // throws when a request adds a series between its Count read and the copy.
        foreach (var group in _series.ToArray().OrderBy(s => s.Key.Name, StringComparer.Ordinal).GroupBy(s => s.Key.Name))
        {
            var first = group.First().Value;
            var name = first.Monotonic ? group.Key + "_total" : group.Key;
            text.Append("# TYPE ").Append(name).Append(first.Histogram ? " histogram" : first.Monotonic ? " counter" : " gauge").Append('\n');
            foreach (var ((_, labels), series) in group)
            {
                lock (series)
                {
                    if (!series.Histogram)
                    {
                        Line(text, name, labels, null, series.Sum);
                        continue;
                    }

                    for (var b = 0; b < Buckets.Length; b++)
                        Line(text, name + "_bucket", labels, Buckets[b].ToString(CultureInfo.InvariantCulture), series.BucketCounts[b]);
                    Line(text, name + "_bucket", labels, "+Inf", series.Count);
                    Line(text, name + "_sum", labels, null, series.Sum);
                    Line(text, name + "_count", labels, null, series.Count);
                }
            }
        }

        return text.ToString();
    }

    private static void Line(StringBuilder text, string name, string labels, string? le, double value)
    {
        text.Append(name);
        var all = le is null ? labels : labels.Length == 0 ? $"le=\"{le}\"" : $"{labels},le=\"{le}\"";
        if (all.Length > 0) text.Append('{').Append(all).Append('}');
        text.Append(' ').Append(value.ToString("R", CultureInfo.InvariantCulture)).Append('\n');
    }

    private static string Name(string name) => new(name.Select(c => char.IsAsciiLetterOrDigit(c) ? c : '_').ToArray());

    private static string Escape(string value) => value.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n");

    public void Dispose() => _listener.Dispose();
}

/// <summary>
/// Serves <c>GET /metrics</c> on its own port (<c>NYXITE__Metrics__Port</c>, off when unset). It is a separate listener
/// with nothing but this one route, so the reverse proxy, which only forwards the API port, never exposes it and the
/// endpoint needs no authentication: only the operator's monitoring inside the deployment network reaches it.
/// </summary>
public sealed class MetricsServer(MetricsRegistry registry, IConfiguration configuration, ILogger<MetricsServer> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var port = configuration.GetValue<int?>("Metrics:Port");
        if (port is null) return;

        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());
        builder.WebHost.UseKestrelCore().ConfigureKestrel((KestrelServerOptions o) => o.ListenAnyIP(port.Value));
        builder.Services.AddRoutingCore();
        await using var app = builder.Build();
        app.MapGet("/metrics", () => Results.Text(registry.Render(), "text/plain; version=0.0.4"));
        logger.LogInformation("Metrics are served on port {Port}.", port.Value);
        await app.RunAsync(stoppingToken);
    }
}
