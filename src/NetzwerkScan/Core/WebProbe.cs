using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace NetzwerkScan.Core;

public sealed record WebInfo(string Scheme, string? Title, string? Server);

public sealed record RedirectTarget(bool UseTls, int Port, string Path);

/// <summary>Finds out whether an open port serves a website, and whether over HTTP or HTTPS.</summary>
public static partial class WebProbe
{
    private const int AttemptTimeoutMs = 2500;
    private const int MaxResponseBytes = 64 * 1024;
    private const int MaxRedirects = 3;
    private static readonly byte[] TitleEnd = Encoding.ASCII.GetBytes("</title>");

    public static async Task<WebInfo?> ProbeAsync(IPAddress address, int port, CancellationToken ct)
    {
        // HTTPS first: a plain request on a TLS port is often answered with an HTTP 400, which would
        // look like a working HTTP service. Port 8006 on Proxmox is an example.
        return await AttemptAsync(address, port, useTls: true, ct)
            ?? await AttemptAsync(address, port, useTls: false, ct);
    }

    private static async Task<WebInfo?> AttemptAsync(IPAddress address, int port, bool useTls, CancellationToken ct)
    {
        var response = await FetchAsync(address, port, useTls, "/", ct);
        if (response is null || ParseResponse(response, useTls ? "https" : "http") is not { } info) return null;

        return RedirectLocation(response) is { } location
            ? await FollowRedirectsAsync(info, location, address, port, useTls, ct)
            : info;
    }

    /// <summary>Only the title comes from where the redirect leads. The port being probed stays the one to open.</summary>
    private static async Task<WebInfo> FollowRedirectsAsync(WebInfo first, string location, IPAddress address, int port, bool useTls, CancellationToken ct)
    {
        var path = "/";
        for (var hop = 0; hop < MaxRedirects; hop++)
        {
            if (ResolveRedirect(location, address, port, useTls, path) is not { } target) break;
            (useTls, port, path) = (target.UseTls, target.Port, target.Path);

            var response = await FetchAsync(address, port, useTls, path, ct);
            if (response is null || ParseResponse(response, first.Scheme) is not { } page) break;

            if (RedirectLocation(response) is { } next)
            {
                location = next;
                continue;
            }
            return first with { Title = page.Title, Server = first.Server ?? page.Server };
        }
        return first;
    }

    /// <summary>
    /// Where a redirect leads, as long as that is the same device. Everything else is left alone: a scan of
    /// the local network should not start talking to other machines because a device on it says so.
    /// </summary>
    public static RedirectTarget? ResolveRedirect(string location, IPAddress address, int port, bool useTls, string path = "/")
    {
        var current = new Uri($"{(useTls ? "https" : "http")}://{address}:{port}{path}");
        if (!Uri.TryCreate(current, location, out var target)) return null;
        if (target.Scheme != Uri.UriSchemeHttp && target.Scheme != Uri.UriSchemeHttps) return null;
        if (target.Host != address.ToString() || !ServiceCatalog.MayProbeWeb(target.Port)) return null;

        return new RedirectTarget(target.Scheme == Uri.UriSchemeHttps, target.Port, target.PathAndQuery);
    }

    private static async Task<string?> FetchAsync(IPAddress address, int port, bool useTls, string path, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(AttemptTimeoutMs);

        try
        {
            using var client = new TcpClient(AddressFamily.InterNetwork);
            await client.ConnectAsync(address, port, timeout.Token);

            Stream stream = client.GetStream();
            if (useTls)
            {
                var tls = new SslStream(stream, leaveInnerStreamOpen: false);
                stream = tls;
                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = address.ToString(),
                    // Devices on a LAN nearly always use self-signed certificates. The only thing this
                    // connection does is read the page title; no credentials or user data are sent.
                    RemoteCertificateValidationCallback = (_, _, _, _) => true,
                }, timeout.Token);
            }

            await using (stream)
            {
                var request = $"GET {path} HTTP/1.1\r\nHost: {address}:{port}\r\nUser-Agent: NetzwerkScan/1.0\r\n" +
                              "Accept: text/html,*/*\r\nConnection: close\r\n\r\n";
                await stream.WriteAsync(Encoding.ASCII.GetBytes(request), timeout.Token);

                return await ReadResponseAsync(stream, timeout.Token);
            }
        }
        catch (Exception e) when (e is SocketException or IOException or System.Security.Authentication.AuthenticationException
                                  || (e is OperationCanceledException && !ct.IsCancellationRequested))
        {
            return null;
        }
    }

    private static async Task<string> ReadResponseAsync(Stream stream, CancellationToken token)
    {
        var buffer = new byte[MaxResponseBytes];
        var total = 0;
        try
        {
            while (total < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(total), token);
                if (read == 0) break;
                total += read;
                if (buffer.AsSpan(0, total).IndexOf(TitleEnd) >= 0) break;
            }
        }
        catch (Exception e) when (e is IOException or OperationCanceledException)
        {
            // Slow or stalling server: whatever arrived so far may already identify it.
        }
        return Encoding.UTF8.GetString(buffer, 0, total);
    }

    /// <summary>Returns null when the text is not an HTTP response.</summary>
    public static WebInfo? ParseResponse(string response, string scheme)
    {
        if (!response.StartsWith("HTTP/", StringComparison.Ordinal)) return null;

        var headers = HeadersOf(response);
        var server = ServerHeader().Match(headers) is { Success: true } s ? s.Groups[1].Value.Trim() : null;

        // The page of a redirect only says "301 Moved Permanently", which tells nothing about the device.
        string? title = null;
        if (!RedirectStatus().IsMatch(headers) && TitleTag().Match(response) is { Success: true } t)
        {
            title = Whitespace().Replace(WebUtility.HtmlDecode(t.Groups[1].Value), " ").Trim();
            if (title.Length > 100) title = title[..100] + "…";
            if (title.Length == 0) title = null;
        }
        return new WebInfo(scheme, title, string.IsNullOrEmpty(server) ? null : server);
    }

    /// <summary>The target of a redirect response, otherwise null.</summary>
    public static string? RedirectLocation(string response)
    {
        var headers = HeadersOf(response);
        if (!RedirectStatus().IsMatch(headers)) return null;

        var location = LocationHeader().Match(headers) is { Success: true } l ? l.Groups[1].Value.Trim() : "";
        return location.Length > 0 ? location : null;
    }

    private static string HeadersOf(string response)
    {
        var end = response.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        return end >= 0 ? response[..end] : response;
    }

    [GeneratedRegex(@"\AHTTP/\d(?:\.\d)? 30[12378]\b")]
    private static partial Regex RedirectStatus();

    [GeneratedRegex(@"^Location:[ \t]*(.+?)\r?$", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex LocationHeader();

    [GeneratedRegex(@"^Server:[ \t]*(.+?)\r?$", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex ServerHeader();

    [GeneratedRegex(@"<title[^>]*>(.*?)</title>", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex TitleTag();

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();
}
