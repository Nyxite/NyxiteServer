using Nyxite.Application.Audit;

namespace Nyxite.Server.Http;

public static class RequestInfoExtensions
{
    public static RequestInfo Info(this HttpContext context) =>
        new(context.Connection.RemoteIpAddress, context.Request.Headers.UserAgent.ToString() is { Length: > 0 } ua ? ua : null);
}
