using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace NetzwerkScan.Core;

public sealed record WebInfo(string Scheme, string? Title, string? Server);

/// <summary>Finds out whether an open port serves a website, and whether over HTTP or HTTPS.</summary>
public static partial class WebProbe
{
    private const int AttemptTimeoutMs = 2500;
    private const int MaxResponseBytes = 64 * 1024;
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
                var request = $"GET / HTTP/1.1\r\nHost: {address}:{port}\r\nUser-Agent: NetzwerkScan/1.0\r\n" +
                              "Accept: text/html,*/*\r\nConnection: close\r\n\r\n";
                await stream.WriteAsync(Encoding.ASCII.GetBytes(request), timeout.Token);

                var response = await ReadResponseAsync(stream, timeout.Token);
                return ParseResponse(response, useTls ? "https" : "http");
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

        var server = ServerHeader().Match(response) is { Success: true } s ? s.Groups[1].Value.Trim() : null;

        string? title = null;
        if (TitleTag().Match(response) is { Success: true } t)
        {
            title = Whitespace().Replace(WebUtility.HtmlDecode(t.Groups[1].Value), " ").Trim();
            if (title.Length > 100) title = title[..100] + "…";
            if (title.Length == 0) title = null;
        }
        return new WebInfo(scheme, title, string.IsNullOrEmpty(server) ? null : server);
    }

    [GeneratedRegex(@"^Server:[ \t]*(.+?)\r?$", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex ServerHeader();

    [GeneratedRegex(@"<title[^>]*>(.*?)</title>", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex TitleTag();

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();
}
