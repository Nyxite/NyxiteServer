using Microsoft.AspNetCore.Diagnostics;
using Nyxite.Application.Auth;

namespace Nyxite.Server.Http;

/// <summary>RFC 9457 <c>application/problem+json</c> with the stable <c>code</c> of 04 §4.4.</summary>
public static class Problems
{
    public const string ContentType = "application/problem+json";

    public sealed record Body(string Type, string Title, int Status, string Code);

    public static IResult Result(int status, string code, string title) =>
        Results.Json(new Body($"urn:nyxite:problem:{code}", title, status, code), contentType: ContentType, statusCode: status);

    public static Task WriteAsync(HttpContext context, int status, string code, string title)
    {
        context.Response.StatusCode = status;
        return context.Response.WriteAsJsonAsync(new Body($"urn:nyxite:problem:{code}", title, status, code), (System.Text.Json.JsonSerializerOptions?)null, ContentType);
    }

    /// <summary>Maps expected failures to problems; anything else becomes a bare <c>500 internal</c> without details.</summary>
    public static async Task HandleExceptionAsync(HttpContext context)
    {
        var error = context.Features.Get<IExceptionHandlerFeature>()?.Error;
        if (error is AuthException { RetryAfter: { } retry })
            context.Response.Headers.RetryAfter = ((int)Math.Ceiling(retry.TotalSeconds)).ToString(System.Globalization.CultureInfo.InvariantCulture);
        var (status, code, title) = error switch
        {
            AuthException a => (a.Status, a.Code, a.Message),
            // The client went away; nobody reads the answer. 499 keeps it out of the server-error rate.
            OperationCanceledException when context.RequestAborted.IsCancellationRequested => (499, "client_closed", "Client closed the request."),
            BadHttpRequestException b => (b.StatusCode == 413 ? 413 : 400, b.StatusCode == 413 ? "payload_too_large" : "validation_failed", "The request is malformed."),
            _ => (500, "internal", "Internal server error."),
        };
        await WriteAsync(context, status, code, title);
    }
}
