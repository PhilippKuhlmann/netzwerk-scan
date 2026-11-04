using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NetzwerkScan.Core;
using Xunit;

namespace NetzwerkScan.Tests;

/// <summary>Runs the real probes against servers on the loopback address. Nothing leaves this machine.</summary>
public class LiveProbeTests
{
    private const string PageResponse =
        "HTTP/1.1 200 OK\r\nServer: test-server\r\nConnection: close\r\n\r\n<html><title>Testseite</title></html>";

    [Fact]
    public async Task DetectsPlainHttp()
    {
        using var listener = StartListener(out var port);
        var server = ServeAsync(listener, stream => stream, connections: 2);

        var info = await WebProbe.ProbeAsync(IPAddress.Loopback, port, CancellationToken.None);

        Assert.NotNull(info);
        Assert.Equal("http", info!.Scheme);
        Assert.Equal("Testseite", info.Title);
        Assert.Equal("test-server", info.Server);
        await server;
    }

    [Fact]
    public async Task DetectsHttpsWithSelfSignedCertificate()
    {
        using var certificate = CreateCertificate();
        using var listener = StartListener(out var port);
        var server = ServeTlsAsync(listener, certificate);

        var info = await WebProbe.ProbeAsync(IPAddress.Loopback, port, CancellationToken.None);

        Assert.NotNull(info);
        Assert.Equal("https", info!.Scheme);
        Assert.Equal("Testseite", info.Title);
        await server;
    }

    [Fact]
    public async Task NonWebServiceIsNotReportedAsWeb()
    {
        using var listener = StartListener(out var port);
        var server = Task.Run(async () =>
        {
            for (var i = 0; i < 2; i++)
            {
                using var client = await listener.AcceptTcpClientAsync();
                try { await client.GetStream().WriteAsync(Encoding.ASCII.GetBytes("SSH-2.0-OpenSSH_9.6\r\n")); }
                catch (IOException) { }
            }
        });

        Assert.Null(await WebProbe.ProbeAsync(IPAddress.Loopback, port, CancellationToken.None));
        await server;
    }

    [Fact]
    public async Task FullScanFindsOpenPortAndWebsiteOnLoopback()
    {
        using var listener = StartListener(out var port);
        using var stop = new CancellationTokenSource();
        var server = Task.Run(async () =>
        {
            try
            {
                while (true)
                {
                    using var client = await listener.AcceptTcpClientAsync(stop.Token);
                    await AnswerAsync(client.GetStream());
                }
            }
            catch (OperationCanceledException) { }
        });

        var events = new List<ScanEvent>();
        var recorder = new SynchronousProgress(events);
        var ip = Ipv4.ToUInt(IPAddress.Loopback);
        var closedPort = FindClosedPort();
        var scanner = new NetworkScanner();

        await scanner.RunAsync(
            new ScanOptions(new IpRange(ip, ip), new[] { port, closedPort }, FindShares: false, TimeoutMs: 1000),
            recorder, CancellationToken.None);

        stop.Cancel();
        await server;

        Assert.Single(events.OfType<HostFoundEvent>());
        var open = events.OfType<PortOpenEvent>().Select(e => e.Port).ToList();
        Assert.Contains(port, open);
        Assert.DoesNotContain(closedPort, open);

        var web = Assert.Single(events.OfType<PortWebEvent>());
        Assert.Equal(port, web.Port);
        Assert.Equal("Testseite", web.Info.Title);
        Assert.Single(events.OfType<HostFinishedEvent>());

        var progress = scanner.Progress;
        Assert.Equal(1, progress.Checked);
        Assert.Equal(1, progress.Found);
        Assert.Equal(1, progress.Finished);
    }

    [Fact]
    public async Task ScanCanBeCancelled()
    {
        using var cancel = new CancellationTokenSource();
        cancel.Cancel();
        var ip = Ipv4.ToUInt(IPAddress.Loopback);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new NetworkScanner().RunAsync(
            new ScanOptions(new IpRange(ip, ip), new[] { 80 }, false, 500),
            new SynchronousProgress(new List<ScanEvent>()), cancel.Token));
    }

    [Fact]
    public void ArpTableParsesIntoPlausibleEntries()
    {
        foreach (var entry in NeighborTable.Read())
        {
            Assert.True(Enum.IsDefined(entry.State), $"Unknown state {entry.State}");
            Assert.True(entry.Mac.Length is 0 or 17, $"Unexpected MAC format '{entry.Mac}'");
        }
    }

    private sealed class SynchronousProgress : IProgress<ScanEvent>
    {
        private readonly List<ScanEvent> _events;
        public SynchronousProgress(List<ScanEvent> events) => _events = events;
        public void Report(ScanEvent value) { lock (_events) _events.Add(value); }
    }

    private static TcpListener StartListener(out int port)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        port = ((IPEndPoint)listener.LocalEndpoint).Port;
        return listener;
    }

    private static int FindClosedPort()
    {
        using var listener = StartListener(out var port);
        return port;
    }

    private static Task ServeAsync(TcpListener listener, Func<Stream, Stream> wrap, int connections) => Task.Run(async () =>
    {
        for (var i = 0; i < connections; i++)
        {
            using var client = await listener.AcceptTcpClientAsync();
            await AnswerAsync(wrap(client.GetStream()));
        }
    });

    private static Task ServeTlsAsync(TcpListener listener, X509Certificate2 certificate) => Task.Run(async () =>
    {
        using var client = await listener.AcceptTcpClientAsync();
        await using var tls = new SslStream(client.GetStream());
        await tls.AuthenticateAsServerAsync(certificate);
        await AnswerAsync(tls);
    });

    /// <summary>Answers an HTTP request. Connections that don't send one, such as a TLS hello on a plain port, get dropped.</summary>
    private static async Task AnswerAsync(Stream stream)
    {
        var buffer = new byte[4096];
        try
        {
            var read = await stream.ReadAsync(buffer);
            if (Encoding.ASCII.GetString(buffer, 0, read).StartsWith("GET "))
            {
                await stream.WriteAsync(Encoding.ASCII.GetBytes(PageResponse));
                await stream.FlushAsync();
            }
        }
        catch (IOException) { }
    }

    private static X509Certificate2 CreateCertificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        // SChannel can't use an ephemeral key for a server certificate, so it goes through a PFX round trip.
        return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pfx), null);
    }
}
