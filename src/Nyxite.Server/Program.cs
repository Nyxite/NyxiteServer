using Microsoft.EntityFrameworkCore;
using Nyxite.Application;
using Nyxite.Persistence;
using Nyxite.Server;
using Nyxite.Server.Endpoints;
using Nyxite.Server.Http;
using Nyxite.Server.Realtime;

if (args is [MigrateCommand.Name, ..])
    return await MigrateCommand.RunAsync(args[1..]);

var builder = WebApplication.CreateBuilder(args);
// NYXITE__Section__Key environment variables (14) map to Section:Key.
builder.Configuration.AddEnvironmentVariables(prefix: "NYXITE__");

// Structured logs (01 §1.5): one JSON object per line with the request's trace id, except in development.
if (!builder.Environment.IsDevelopment())
{
    builder.Logging.ClearProviders();
    builder.Logging.AddJsonConsole(o =>
    {
        o.IncludeScopes = true;
        o.UseUtcTimestamp = true;
        o.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";
    });
    builder.Logging.Configure(o => o.ActivityTrackingOptions =
        ActivityTrackingOptions.TraceId | ActivityTrackingOptions.SpanId);
}

builder.Services.AddDbContext<NyxiteDbContext>((sp, options) =>
    options.UseNpgsql(sp.GetRequiredService<IConfiguration>()["Database:ConnectionString"]
                      ?? throw new InvalidOperationException("Database:ConnectionString is not configured.")));
builder.Services.AddNyxiteAuth(builder.Configuration);
builder.Services.AddNyxiteBearer();
builder.Services.AddNyxiteRateLimiting(builder.Configuration);
builder.Services.AddNyxiteHealth();
builder.Services.AddNyxiteBlobStore();
builder.Services.AddNyxiteRelay();
builder.Services.AddNyxiteCors(builder.Configuration);
builder.Services.AddSingleton<MetricsRegistry>();
builder.Services.AddHostedService<MetricsServer>();
// Malformed bodies throw, so the exception handler answers with a 400 validation_failed problem.
builder.Services.Configure<RouteHandlerOptions>(o => o.ThrowOnBadRequest = true);

var app = builder.Build();

app.Services.ValidateNyxiteAuthSecrets();
app.Services.ValidateNyxiteBlobStore();

app.UseNyxiteForwardedHeaders(app.Configuration);
// Created now, so it listens before the first request is measured.
_ = app.Services.GetRequiredService<MetricsRegistry>();
app.UseNyxiteHardening();
app.UseExceptionHandler(new ExceptionHandlerOptions
{
    ExceptionHandler = Problems.HandleExceptionAsync,
    // not_found is a regular problem answer (existence-hiding, 04 §4.4). Without this the middleware accepts a 404
    // only when the body write has already started the response, and turns it into a 500 otherwise.
    AllowStatusCode404Response = true,
    // A wrong code or a 401 is a normal answer; logging it as an unhandled error would bury real failures.
    SuppressDiagnosticsCallback = context => Hardening.IsExpected(context.Exception),
});
app.UseStatusCodePages(context =>
    context.HttpContext.Response.StatusCode == 404 && !context.HttpContext.Response.HasStarted
        ? Problems.WriteAsync(context.HttpContext, 404, "not_found", "Not found.")
        : Task.CompletedTask);
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.MapNyxiteHealth();
app.MapOpenApiDocument();

var api = app.MapGroup("/api/v1");
api.MapAuthEndpoints();
api.MapAccountSecurityEndpoints();
api.MapMeEndpoints();
api.MapKeyEndpoints();
api.MapStructureEndpoints();
api.MapContentEndpoints();
app.MapHub<Nyxite.Server.Realtime.RelayHub>(Nyxite.Server.Realtime.RelayHub.Path).RequireAuthorization();

await app.RunAsync();
return 0;

/// <summary>Entry point, exposed for <c>WebApplicationFactory</c> in the integration tests.</summary>
public partial class Program;
