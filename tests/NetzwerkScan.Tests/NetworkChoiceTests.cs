using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NetzwerkScan.Core;
using NetzwerkScan.ViewModels;
using Xunit;

namespace NetzwerkScan.Tests;

public class IpRangeSetTests
{
    [Fact]
    public void ParsesSeveralRanges()
    {
        Assert.True(IpRangeSet.TryParse("192.0.2.0/24, 198.51.100.10-12", out var set, out _));

        Assert.Equal(2, set.Ranges.Count);
        Assert.Equal(257, set.Count);
        Assert.Equal(257, set.Addresses().Count());
        Assert.True(set.Contains(0xC633640B));
        Assert.False(set.Contains(0xC6336409));
    }

    [Theory]
    [InlineData("192.0.2.1-5;192.0.2.3-8", 8)]
    [InlineData("192.0.2.1-5, 192.0.2.6-8", 8)]
    [InlineData("192.0.2.1-8, 192.0.2.3", 8)]
    [InlineData("192.0.2.1, 192.0.2.1", 1)]
    [InlineData("255.255.255.250-255, 255.255.255.255", 6)]
    public void OverlapsCountOnce(string text, int count)
    {
        Assert.True(IpRangeSet.TryParse(text, out var set, out _));
        Assert.Single(set.Ranges);
        Assert.Equal(count, set.Count);
        Assert.Equal(count, set.Addresses().Distinct().Count());
    }

    [Theory]
    [InlineData("192.0.2.1-5,")]
    [InlineData(" , 192.0.2.1-5 ; ")]
    public void EmptyEntriesAreIgnored(string text)
    {
        Assert.True(IpRangeSet.TryParse(text, out var set, out _));
        Assert.Equal(5, set.Count);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" , ")]
    [InlineData("abc")]
    public void RejectsWhatHoldsNoRange(string text)
    {
        Assert.False(IpRangeSet.TryParse(text, out _, out var error));
        Assert.NotEmpty(error);
    }

    [Fact]
    public void ErrorNamesTheEntryThatIsWrong()
    {
        Assert.False(IpRangeSet.TryParse("192.0.2.0/24, 198.51.100.0/99", out _, out var error));
        Assert.StartsWith("198.51.100.0/99: ", error);
    }

    [Fact]
    public void LimitAppliesToAllRangesTogether()
    {
        Assert.False(IpRangeSet.TryParse("10.0.0.0/16, 10.2.0.0/16", out _, out var error));
        Assert.Contains("zusammen", error);
    }

    [Fact]
    public void SingleRangeReadsTheSameAsBefore()
    {
        Assert.True(IpRangeSet.TryParse("192.0.2.10-20", out var set, out _));
        Assert.Equal(new IpRange(0xC000020A, 0xC0000214).ToString(), set.ToString());
    }
}

public class SeveralRangesInventoryTests
{
    private const uint A = 0xC0000201, B = 0xC6336401;
    private const string MacA = "AA:00:00:00:00:01", MacB = "AA:00:00:00:00:02", MacC = "AA:00:00:00:00:03";
    private static readonly DateTime T1 = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly IpRangeSet Both = new(new[] { new IpRange(A, A + 9), new IpRange(B, B + 9) });

    private static SeenDevice Seen(uint ip, string mac) => new(ip, mac, "", "");

    [Fact]
    public void ComparesEveryRange()
    {
        var inventory = new DeviceInventory();
        inventory.Record(Both, new[] { Seen(A, MacA), Seen(B, MacB) }, T1);

        var result = inventory.Compare(Both, new[] { Seen(A, MacA), Seen(B + 1, MacC) });

        Assert.True(result.HadHistory);
        Assert.Equal(new uint[] { B + 1 }, result.NewIps);
        Assert.Equal(MacB, Assert.Single(result.Missing).Mac);
    }

    [Fact]
    public void ScanningOneOfTheRangesKeepsTheOtherOutOfIt()
    {
        var inventory = new DeviceInventory();
        inventory.Record(Both, new[] { Seen(A, MacA), Seen(B, MacB) }, T1);

        Assert.Empty(inventory.Compare(new IpRange(A, A + 9), new[] { Seen(A, MacA) }).Missing);
    }

    [Fact]
    public void RepeatedScansDoNotPileUpRanges()
    {
        var inventory = new DeviceInventory();
        inventory.Record(Both, Array.Empty<SeenDevice>(), T1);
        inventory.Record(Both, Array.Empty<SeenDevice>(), T1.AddDays(1));

        Assert.Equal(2, inventory.Ranges.Count);
    }
}

public class CustomNameTests
{
    private const uint Ip = 0xC0000201;
    private const string Mac = "AA:00:00:00:00:01";

    [Fact]
    public void NameFollowsTheMacToAnotherAddress()
    {
        var inventory = new DeviceInventory();
        inventory.SetCustomName(Mac, Ip, "  Proxmox 1 ");

        Assert.Equal("Proxmox 1", inventory.CustomNameFor(Mac, Ip + 5));
        Assert.Equal("", inventory.CustomNameFor("AA:00:00:00:00:02", Ip));
    }

    [Fact]
    public void WithoutMacTheAddressIdentifiesTheDevice()
    {
        var inventory = new DeviceInventory();
        inventory.SetCustomName("", Ip, "Hinter dem Router");

        Assert.Equal("Hinter dem Router", inventory.CustomNameFor("", Ip));
        Assert.Equal("", inventory.CustomNameFor("", Ip + 1));
    }

    [Fact]
    public void NameGivenBeforeTheMacArrivedIsStillFoundAndMovesWithTheNextEdit()
    {
        var inventory = new DeviceInventory();
        inventory.SetCustomName("", Ip, "Früh");
        Assert.Equal("Früh", inventory.CustomNameFor(Mac, Ip));

        inventory.SetCustomName(Mac, Ip, "Später");

        Assert.Equal("Später", inventory.CustomNameFor(Mac, Ip));
        Assert.Equal(new[] { Mac }, inventory.CustomNames.Keys);
    }

    [Fact]
    public void EmptyNameRemovesIt()
    {
        var inventory = new DeviceInventory();
        inventory.SetCustomName("", Ip, "A");
        inventory.SetCustomName(Mac, Ip, "B");

        inventory.SetCustomName(Mac, Ip, "   ");

        Assert.Empty(inventory.CustomNames);
    }

    [Fact]
    public void NamesSurviveSavingAndOutlastTheScanHistory()
    {
        var inventory = new DeviceInventory();
        var start = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        var range = new IpRange(Ip, Ip);
        inventory.Record(range, new[] { new SeenDevice(Ip, Mac, "", "") }, start);
        inventory.SetCustomName(Mac, Ip, "NAS");

        inventory.Record(range, Array.Empty<SeenDevice>(), start.AddDays(400));
        var loaded = DeviceInventory.Parse(inventory.ToJson());

        Assert.Empty(loaded.Devices);
        Assert.Equal("NAS", loaded.CustomNameFor(Mac, Ip));
    }

    [Theory]
    [InlineData("""{"Devices":[],"Ranges":[]}""")]
    [InlineData("""{"CustomNames":null}""")]
    [InlineData("""{"CustomNames":{"AA:00:00:00:00:01":null,"AA:00:00:00:00:02":"  "}}""")]
    public void FilesWithoutUsableNamesLoadEmpty(string json) =>
        Assert.Empty(DeviceInventory.Parse(json).CustomNames);

    [Fact]
    public void ListShowsTheOwnNameFirst()
    {
        var host = new HostViewModel(Ip, null, isThisPc: true, () => "") { Name = "srv.example.org" };
        Assert.Equal("srv", host.DisplayName);
        Assert.Equal("srv.example.org", host.ExportName);

        host.CustomName = "Mein Server ";

        Assert.Equal("Mein Server", host.DisplayName);
        Assert.Equal("Mein Server", host.ExportName);
        Assert.True(host.Matches("mein"));

        host.CustomName = "";
        Assert.Equal("srv", host.DisplayName);
    }

    [Fact]
    public void OnlyTheUsersOwnInputCountsAsAChange()
    {
        var changes = 0;
        var host = new HostViewModel(Ip, null, false, () => "", _ => changes++);

        host.LoadCustomName("Gespeichert");
        Assert.Equal(0, changes);
        Assert.Equal("Gespeichert", host.DisplayName);

        host.CustomName = "Neu";
        Assert.Equal(1, changes);
    }

    [Fact]
    public void MissingDeviceShowsTheOwnName()
    {
        var device = new KnownDevice(Mac, Ip, Mac, "nas.example.org", "", DateTime.UtcNow, DateTime.UtcNow);

        Assert.Equal("192.0.2.1 · nas", new MissingDeviceViewModel(device).Text);

        var named = new MissingDeviceViewModel(device, "Mein NAS");
        Assert.Equal("192.0.2.1 · Mein NAS", named.Text);
        Assert.Equal("Mein NAS", named.Name);
    }
}

public class RememberedNetworkTests
{
    [Fact]
    public void RoundTripKeepsTheNetwork()
    {
        var loaded = AppSettings.Parse(new AppSettings { LastAdapter = "Ethernet 2", LastRange = "192.0.2.0/24, 198.51.100.1" }.ToJson());

        Assert.Equal("Ethernet 2", loaded.LastAdapter);
        Assert.Equal("192.0.2.0/24, 198.51.100.1", loaded.LastRange);
    }

    [Theory]
    [InlineData("""{"LastRange":"quatsch"}""")]
    [InlineData("""{"LastRange":null,"LastAdapter":null}""")]
    [InlineData("""{}""")]
    public void AnythingUnusableMeansNothingIsRemembered(string json)
    {
        var loaded = AppSettings.Parse(json);

        Assert.Equal("", loaded.LastAdapter);
        Assert.Equal("", loaded.LastRange);
    }
}

public class WebRedirectTests
{
    private static readonly IPAddress Device = IPAddress.Parse("192.0.2.1");

    [Fact]
    public void RedirectPageTitleIsNotTheDevicesTitle()
    {
        var info = WebProbe.ParseResponse(
            "HTTP/1.1 301 Moved Permanently\r\nServer: nginx\r\nLocation: https://192.0.2.1/\r\n\r\n<title>301 Moved Permanently</title>", "http");

        Assert.Null(info!.Title);
        Assert.Equal("nginx", info.Server);
    }

    [Fact]
    public void HeadersAreNotLookedForInThePage()
    {
        var page = "HTTP/1.1 200 OK\r\n\r\nServer: erfunden\r\nLocation: /nirgends\r\n";

        Assert.Null(WebProbe.ParseResponse(page, "http")!.Server);
        Assert.Null(WebProbe.RedirectLocation(page));
        Assert.Null(WebProbe.RedirectLocation("HTTP/1.1 302 Found\r\n\r\nLocation: /nirgends\r\n"));
    }

    [Theory]
    [InlineData("HTTP/1.1 301 Moved\r\nLocation: /a\r\n\r\n", "/a")]
    [InlineData("HTTP/1.0 302 Found\r\nlocation:/b\r\n\r\n", "/b")]
    [InlineData("HTTP/1.1 307 Temporary Redirect\r\nLocation: https://192.0.2.1/\r\n\r\n", "https://192.0.2.1/")]
    public void FindsTheTarget(string response, string location) =>
        Assert.Equal(location, WebProbe.RedirectLocation(response));

    [Theory]
    [InlineData("/login", false, 80, "/login")]
    [InlineData("login?a=1", false, 80, "/login?a=1")]
    [InlineData("https://192.0.2.1/", true, 443, "/")]
    [InlineData("https://192.0.2.1:8443/ui/#start", true, 8443, "/ui/")]
    [InlineData("http://user@192.0.2.1/x", false, 80, "/x")]
    public void FollowsWithinTheSameDevice(string location, bool useTls, int port, string path)
    {
        var target = WebProbe.ResolveRedirect(location, Device, 80, useTls: false);

        Assert.Equal(new RedirectTarget(useTls, port, path), target);
    }

    [Fact]
    public void RelativeTargetsStartFromTheCurrentPage()
    {
        var target = WebProbe.ResolveRedirect("next", Device, 8443, useTls: true, "/app/start");

        Assert.Equal(new RedirectTarget(true, 8443, "/app/next"), target);
    }

    [Theory]
    [InlineData("https://example.org/")]
    [InlineData("//example.org/")]
    [InlineData("http://192.0.2.2/")]
    [InlineData("https://192.0.2.1@example.org/")]
    [InlineData("https://nas.local/")]
    [InlineData("ftp://192.0.2.1/")]
    [InlineData("javascript:alert(1)")]
    [InlineData("http://192.0.2.1:9100/")] // would print the request on a network printer
    public void LeavesEverythingElseAlone(string location) =>
        Assert.Null(WebProbe.ResolveRedirect(location, Device, 80, useTls: false));

    [Fact]
    public void TargetCanNotSmuggleInMoreRequestLines()
    {
        var target = WebProbe.ResolveRedirect("/a\rX-Injected: 1", Device, 80, useTls: false);

        Assert.DoesNotContain('\r', target!.Path);
        Assert.DoesNotContain('\n', target.Path);
    }

    [Fact]
    public async Task ReadsTheTitleBehindARedirect()
    {
        await using var server = new TestServer(path => path == "/"
            ? "HTTP/1.1 302 Found\r\nLocation: /login\r\nConnection: close\r\n\r\n<title>302 Found</title>"
            : "HTTP/1.1 200 OK\r\nServer: dahinter\r\nConnection: close\r\n\r\n<title>Anmeldung</title>");

        var info = await WebProbe.ProbeAsync(IPAddress.Loopback, server.Port, CancellationToken.None);

        Assert.Equal("http", info!.Scheme);
        Assert.Equal("Anmeldung", info.Title);
        Assert.Equal("dahinter", info.Server);
    }

    [Fact]
    public async Task FollowsToAnotherPortOfTheSameDevice()
    {
        await using var target = new TestServer(_ => "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n<title>Ziel</title>");
        await using var server = new TestServer(_ => $"HTTP/1.1 301 Moved\r\nLocation: http://127.0.0.1:{target.Port}/\r\nConnection: close\r\n\r\n");

        var info = await WebProbe.ProbeAsync(IPAddress.Loopback, server.Port, CancellationToken.None);

        Assert.Equal("Ziel", info!.Title);
    }

    [Fact]
    public async Task RedirectLoopEndsWithoutATitle()
    {
        await using var server = new TestServer(_ => "HTTP/1.1 302 Found\r\nLocation: /\r\nConnection: close\r\n\r\n<title>302 Found</title>");

        var info = await WebProbe.ProbeAsync(IPAddress.Loopback, server.Port, CancellationToken.None);

        Assert.NotNull(info);
        Assert.Null(info!.Title);
        Assert.InRange(server.Requests, 1, 4);
    }

    [Fact]
    public async Task RedirectToAnotherHostIsNotFollowed()
    {
        await using var server = new TestServer(_ => "HTTP/1.1 302 Found\r\nLocation: http://example.invalid/\r\nConnection: close\r\n\r\n");

        var info = await WebProbe.ProbeAsync(IPAddress.Loopback, server.Port, CancellationToken.None);

        Assert.NotNull(info);
        Assert.Null(info!.Title);
    }

    /// <summary>Answers each GET by its path, on the loopback address. Drops anything else, such as a TLS hello.</summary>
    private sealed class TestServer : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _running;
        private int _requests;

        public TestServer(Func<string, string> respond)
        {
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _running = Task.Run(async () =>
            {
                try
                {
                    while (true)
                    {
                        using var client = await _listener.AcceptTcpClientAsync(_stop.Token);
                        var stream = client.GetStream();
                        var buffer = new byte[4096];
                        try
                        {
                            var read = await stream.ReadAsync(buffer, _stop.Token);
                            var request = Encoding.ASCII.GetString(buffer, 0, read);
                            if (!request.StartsWith("GET ")) continue;
                            Interlocked.Increment(ref _requests);
                            await stream.WriteAsync(Encoding.ASCII.GetBytes(respond(request.Split(' ')[1])), _stop.Token);
                        }
                        catch (IOException) { }
                    }
                }
                catch (OperationCanceledException) { }
            });
        }

        public int Port { get; }
        public int Requests => Volatile.Read(ref _requests);

        public async ValueTask DisposeAsync()
        {
            _stop.Cancel();
            await _running;
            _listener.Dispose();
            _stop.Dispose();
        }
    }
}
