using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NetzwerkScan.Core;
using NetzwerkScan.ViewModels;
using Xunit;

namespace NetzwerkScan.Tests;

/// <summary>Assembles DNS responses the way devices send them.</summary>
internal sealed class DnsResponse
{
    private readonly MemoryStream _body = new();
    private int _records;

    public DnsResponse Ptr(string owner, string target) => Add(owner, Mdns.TypePtr, Name(target));
    public DnsResponse A(string owner, uint address) =>
        Add(owner, Mdns.TypeA, new[] { (byte)(address >> 24), (byte)(address >> 16), (byte)(address >> 8), (byte)address });
    public DnsResponse Srv(string owner, string target) => Add(owner, Mdns.TypeSrv, new byte[6].Concat(Name(target)).ToArray());

    public DnsResponse Txt(string owner, params string[] values)
    {
        var data = values.SelectMany(v =>
        {
            var bytes = Encoding.UTF8.GetBytes(v);
            return new[] { (byte)bytes.Length }.Concat(bytes);
        }).ToArray();
        return Add(owner, Mdns.TypeTxt, data);
    }

    private DnsResponse Add(string owner, ushort type, byte[] data)
    {
        _records++;
        _body.Write(Name(owner));
        _body.Write(new byte[] { (byte)(type >> 8), (byte)type, 0, 1, 0, 0, 0, 120, (byte)(data.Length >> 8), (byte)data.Length });
        _body.Write(data);
        return this;
    }

    /// <summary>A label may contain dots, so "|" separates them here.</summary>
    public static byte[] Name(string name)
    {
        var bytes = new List<byte>();
        foreach (var label in name.Split('|'))
        {
            var text = Encoding.UTF8.GetBytes(label);
            bytes.Add((byte)text.Length);
            bytes.AddRange(text);
        }
        bytes.Add(0);
        return bytes.ToArray();
    }

    public byte[] Build() =>
        new byte[] { 0, 0, 0x84, 0, 0, 0, (byte)(_records >> 8), (byte)_records, 0, 0, 0, 0 }.Concat(_body.ToArray()).ToArray();

    public IReadOnlyCollection<MdnsRecord> Records() => Mdns.Parse(Build());
}

public class MdnsTests
{
    private const uint Device = 0xC0000232; // 192.0.2.50

    /// <summary>A service with everything that shows it runs on the sender.</summary>
    private static DnsResponse Service(string service, string instance, uint hostAddress = Device) => new DnsResponse()
        .Ptr($"{service}|_tcp|local", $"{instance}|{service}|_tcp|local")
        .Srv($"{instance}|{service}|_tcp|local", "host|local")
        .A("host|local", hostAddress);

    [Fact]
    public void FriendlyNameInTheTextRecordGoesFirst()
    {
        var records = Service("_googlecast", "Chromecast-0123456789abcdef0123")
            .Txt("Chromecast-0123456789abcdef0123|_googlecast|_tcp|local", "id=abc", "fn=Wohnzimmer TV", "md=Chromecast Ultra")
            .Records();

        Assert.Equal(new DeviceAnnouncement("Wohnzimmer TV", "Chromecast Ultra"), Mdns.Announcement(records, Device));
    }

    [Fact]
    public void ServiceInstanceNamesTheDevice_EvenWithDotsInIt()
    {
        var records = Service("_ipp", "Dr. Who's Drucker")
            .Txt("Dr. Who's Drucker|_ipp|_tcp|local", "ty=HP LaserJet", "note=Keller")
            .Records();

        Assert.Equal(new DeviceAnnouncement("Dr. Who's Drucker", "HP LaserJet"), Mdns.Announcement(records, Device));
    }

    [Fact]
    public void BetterServiceWinsOverGenericOne()
    {
        var records = Service("_http", "Webserver")
            .Ptr("_hap|_tcp|local", "Küchenlicht|_hap|_tcp|local")
            .Srv("Küchenlicht|_hap|_tcp|local", "host|local")
            .Records();

        Assert.Equal("Küchenlicht", Mdns.Announcement(records, Device)!.Name);
    }

    [Theory]
    [InlineData("_raop", "AABBCCDDEEFF@Küche", "Küche")]
    [InlineData("_workstation", "nas [aa:bb:cc:dd:ee:ff]", "nas")]
    public void TechnicalPartsOfInstanceNamesAreRemoved(string service, string instance, string expected) =>
        Assert.Equal(expected, Mdns.Announcement(Service(service, instance).Records(), Device)!.Name);

    [Theory]
    [InlineData("RINCON_347E5C000000")]
    [InlineData("0123456789abcdef")]
    [InlineData("AA:BB:CC:DD:EE:FF")]
    public void IdsAreNoNames_TheHostNameIsBetter(string instance) =>
        Assert.Equal("host", Mdns.Announcement(Service("_sonos", instance).Records(), Device)!.Name);

    [Fact]
    public void RouterPassingOnAnotherDevicesServiceIsNotThatDevice()
    {
        // Seen on a UniFi gateway: it answered for a MacBook on another network.
        var records = Service("_companion-link", "MacBook", hostAddress: Device + 1)
            .Txt("MacBook|_companion-link|_tcp|local", "model=MacBookPro18,3")
            .Records();

        Assert.Null(Mdns.Announcement(records, Device));
    }

    [Fact]
    public void RouterWithOwnAddressStillDoesNotGetForeignServices()
    {
        var records = new DnsResponse()
            .A("gateway|local", Device)
            .Ptr("_companion-link|_tcp|local", "MacBook|_companion-link|_tcp|local")
            .Srv("MacBook|_companion-link|_tcp|local", "macbook|local")
            .Txt("MacBook|_companion-link|_tcp|local", "model=MacBookPro18,3")
            .A("macbook|local", Device + 1)
            .Records();

        Assert.Equal(new DeviceAnnouncement("gateway", ""), Mdns.Announcement(records, Device));
    }

    [Fact]
    public void ServiceWithoutAnyAddressProvesNothing()
    {
        var records = new DnsResponse().Ptr("_ipp|_tcp|local", "Drucker|_ipp|_tcp|local").Records();

        Assert.Null(Mdns.Announcement(records, Device));
    }

    [Fact]
    public void RecordsSpreadOverSeveralPacketsCountTogether()
    {
        var first = new DnsResponse().Ptr("_ipp|_tcp|local", "Drucker|_ipp|_tcp|local").Records();
        var second = new DnsResponse().Srv("Drucker|_ipp|_tcp|local", "host|local").A("host|local", Device).Records();

        Assert.Equal("Drucker", Mdns.Announcement(first.Concat(second).ToList(), Device)!.Name);
    }

    [Fact]
    public void AirPlayMetadataListIsNoModel()
    {
        var records = Service("_raop", "AABBCCDDEEFF@Apple TV")
            .Txt("AABBCCDDEEFF@Apple TV|_raop|_tcp|local", "md=0,1,2", "am=AppleTV14,1", "fn=Nein")
            .Records();

        Assert.Equal(new DeviceAnnouncement("Apple TV", "AppleTV14,1"), Mdns.Announcement(records, Device));
    }

    [Fact]
    public void PrinterModelLosesItsParentheses()
    {
        var records = Service("_printer", "P").Txt("P|_printer|_tcp|local", "product=(LaserJet 4)").Records();

        Assert.Equal("LaserJet 4", Mdns.Announcement(records, Device)!.Model);
    }

    [Fact]
    public void InvisibleCharactersAreRemovedFromAnnouncedNames()
    {
        var records = Service("_googlecast", "x").Txt("x|_googlecast|_tcp|local", "fn=TV‮gnirts\r\nmehr").Records();

        Assert.Equal("TVgnirts mehr", Mdns.Announcement(records, Device)!.Name);
    }

    [Fact]
    public void FollowsCompressedNames()
    {
        var question = DnsResponse.Name("_ipp|_tcp|local");
        var header = new byte[] { 0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0 };
        var data = new List<byte>(header);
        data.AddRange(question);
        data.AddRange(new byte[] { 0, 12, 0, 1 });
        data.AddRange(new byte[] { 0xC0, 12 }); // owner: the name in the question
        data.AddRange(new byte[] { 0, 12, 0, 1, 0, 0, 0, 120 });
        var label = Encoding.UTF8.GetBytes("Drucker");
        data.AddRange(new byte[] { 0, (byte)(label.Length + 3) });
        data.Add((byte)label.Length);
        data.AddRange(label);
        data.AddRange(new byte[] { 0xC0, 12 });

        var record = Assert.Single(Mdns.Parse(data.ToArray()));

        Assert.Equal(new[] { "_ipp", "_tcp", "local" }, record.Owner);
        Assert.Equal(new[] { "Drucker", "_ipp", "_tcp", "local" }, record.Target);
    }

    [Fact]
    public void QueriesAreIgnored()
    {
        var data = new DnsResponse().A("x|local", Device).Build();
        data[2] = 0;

        Assert.Empty(Mdns.Parse(data));
    }

    [Fact]
    public void PointerLoopEndsWithoutRecords()
    {
        var data = new byte[] { 0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xC0, 14, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0 };

        Assert.Empty(Mdns.Parse(data));
    }

    [Fact]
    public void SelfPointerEndsWithoutRecords()
    {
        var data = new byte[] { 0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0 };

        Assert.Empty(Mdns.Parse(data));
    }

    [Fact]
    public void DamagedPacketsAtAnyLengthDoNotThrow()
    {
        var whole = new DnsResponse()
            .Ptr("_ipp|_tcp|local", "Drucker|_ipp|_tcp|local")
            .Txt("Drucker|_ipp|_tcp|local", "ty=HP")
            .A("drucker|local", Device)
            .Srv("Drucker|_ipp|_tcp|local", "drucker|local")
            .Build();

        for (var length = 0; length <= whole.Length; length++)
        {
            Assert.NotNull(Mdns.Parse(whole[..length]));
        }
    }

    [Fact]
    public void RecordLengthPastTheEndIsRejected()
    {
        var data = new DnsResponse().A("x|local", Device).Build();
        data[^6] = 0xFF;

        Assert.Empty(Mdns.Parse(data));
    }

    [Fact]
    public void ReverseQueryAsksForTheAddressBackwards()
    {
        var query = Mdns.BuildReverseQuery(Device);

        Assert.Contains("in-addr", Encoding.ASCII.GetString(query));
        Assert.Equal(1, query[5]);
        Assert.Equal(new byte[] { 2, (byte)'5', (byte)'0' }, query[12..15]);
    }

    [Fact]
    public void ServiceQueryFitsInOnePacket() => Assert.InRange(Mdns.BuildServiceQuery().Length, 12, 1400);

    [Fact]
    public void ReverseAnswerMustBeForTheAskedAddress()
    {
        var right = new DnsResponse().Ptr("50|2|0|192|in-addr|arpa", "nas|local").Records();
        var wrong = new DnsResponse().Ptr("51|2|0|192|in-addr|arpa", "nas|local").Records();

        Assert.Equal("nas", Mdns.ReverseAnswer(right, Device));
        Assert.Null(Mdns.ReverseAnswer(wrong, Device));
    }

    [Fact]
    public async Task ReverseLookupAsksTheDeviceDirectly()
    {
        using var device = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)device.Client.LocalEndPoint!).Port;
        var answering = Task.Run(async () =>
        {
            var query = await device.ReceiveAsync();
            var reply = new DnsResponse().Ptr("1|0|0|127|in-addr|arpa", "testgeraet|local").Build();
            await device.SendAsync(reply, query.RemoteEndPoint);
        });

        var name = await Mdns.ReverseLookupAsync(IPAddress.Loopback, CancellationToken.None, port);
        await answering;

        Assert.Equal("testgeraet", name);
    }

    [Fact]
    public async Task ReverseLookupGivesUpOnASilentDevice()
    {
        using var device = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)device.Client.LocalEndPoint!).Port;

        Assert.Null(await Mdns.ReverseLookupAsync(IPAddress.Loopback, CancellationToken.None, port));
    }
}

public class SsdpTests
{
    private const string Description =
        "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n" +
        "<root><device><friendlyName>NAS &amp; Medien</friendlyName><modelName>DS220+</modelName>" +
        "<deviceList><device><friendlyName>Unterger&#228;t</friendlyName><modelName>Teil</modelName></device></deviceList></device></root>";

    [Fact]
    public void DescriptionGivesNameAndModelOfTheDeviceItself() =>
        Assert.Equal(new DeviceAnnouncement("NAS & Medien", "DS220+"), Ssdp.ParseDescription(Description));

    [Theory]
    [InlineData("HTTP/1.1 404 Not Found\r\n\r\n<friendlyName>x</friendlyName>")]
    [InlineData("HTTP/1.1 200 OK\r\n\r\n<root/>")]
    [InlineData("kein http <friendlyName>x</friendlyName>")]
    [InlineData("")]
    public void UnusableDescriptionsGiveNothing(string response) => Assert.Null(Ssdp.ParseDescription(response));

    [Fact]
    public void RouterGoesBeforeItsMediaServer()
    {
        const string media = "HTTP/1.1 200 OK\r\n\r\n<deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType><friendlyName>AVM Mediaserver</friendlyName>";
        const string router = "HTTP/1.1 200 OK\r\n\r\n<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:2</deviceType><friendlyName>FRITZ!Box</friendlyName><modelName>5590</modelName>";

        Assert.Equal(new DeviceAnnouncement("FRITZ!Box", "5590"), Ssdp.BestDescription(new[] { media, router }));
    }

    [Fact]
    public void MediaServerAloneKeepsItsName()
    {
        const string media = "HTTP/1.1 200 OK\r\n\r\n<deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType><friendlyName>Synology</friendlyName>";

        Assert.Equal("Synology", Ssdp.BestDescription(new[] { media, "HTTP/1.1 404 Not Found\r\n\r\n" })!.Name);
    }

    [Fact]
    public void GeneratedFriendlyNameIsDropped_TheModelStays()
    {
        var response = "HTTP/1.1 200 OK\r\n\r\n<friendlyName>uuid:1234</friendlyName><modelName>Router</modelName>";

        Assert.Equal(new DeviceAnnouncement("", "Router"), Ssdp.ParseDescription(response));
    }

    [Fact]
    public void FindsLocationInSearchAnswer()
    {
        var reply = "HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nlocation: http://192.0.2.1:5000/desc.xml\r\n\r\n";

        Assert.Equal("http://192.0.2.1:5000/desc.xml", Ssdp.LocationOf(Encoding.ASCII.GetBytes(reply)));
    }

    [Theory]
    [InlineData("M-SEARCH * HTTP/1.1\r\nLOCATION: http://192.0.2.1/\r\n\r\n")]
    [InlineData("HTTP/1.1 200 OK\r\nST: x\r\n\r\n")]
    [InlineData("")]
    public void NoLocationWithoutProperAnswer(string reply) => Assert.Null(Ssdp.LocationOf(Encoding.ASCII.GetBytes(reply)));

    [Theory]
    [InlineData("http://198.51.100.9/desc.xml")]
    [InlineData("http://192.0.2.1:9100/")]
    [InlineData("ftp://192.0.2.1/desc.xml")]
    [InlineData("http://example.com/desc.xml")]
    public async Task OnlyTheDeviceItselfIsAskedForItsDescription(string location)
    {
        // None of these may lead to a connection, so no time passes and nothing comes back.
        var response = await WebProbe.FetchFromSameDeviceAsync(IPAddress.Parse("192.0.2.1"), location, CancellationToken.None);

        Assert.Null(response);
    }

    [Fact]
    public async Task FetchesDescriptionFromTheDevice()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serving = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            await using var stream = client.GetStream();
            var request = new byte[2048];
            var read = await stream.ReadAsync(request);
            Assert.StartsWith("GET /desc.xml HTTP/1.1", Encoding.ASCII.GetString(request, 0, read));
            await stream.WriteAsync(Encoding.UTF8.GetBytes(Description));
        });

        var found = await Ssdp.FetchDescriptionAsync(IPAddress.Loopback, new[] { $"http://127.0.0.1:{port}/desc.xml" }, CancellationToken.None);
        await serving;
        listener.Stop();

        Assert.Equal("NAS & Medien", found!.Name);
    }
}

public class LocalDiscoveryTests
{
    private static AdapterInfo Adapter(string address, int prefix)
    {
        Assert.True(Ipv4.TryParse(address, out var ip));
        return new AdapterInfo("Karte", "", ip, prefix, "AA:BB:CC:DD:EE:FF", true);
    }

    private static IpRangeSet Range(string text)
    {
        Assert.True(IpRangeSet.TryParse(text, out var range, out _));
        return range;
    }

    [Fact]
    public void AsksOnlyNetworksInTheRange()
    {
        var home = Adapter("192.168.1.5", 24);
        var other = Adapter("10.0.0.5", 24);

        Assert.Equal(new[] { home }, LocalDiscovery.AdaptersFor(new[] { home, other }, Range("192.168.1.0/24")));
        Assert.Equal(new[] { home }, LocalDiscovery.AdaptersFor(new[] { home, other }, Range("192.168.1.50")));
        Assert.Equal(new[] { home, other }, LocalDiscovery.AdaptersFor(new[] { home, other }, Range("192.168.1.0/24, 10.0.0.1")));
        Assert.Empty(LocalDiscovery.AdaptersFor(new[] { home, other }, Range("172.16.0.1")));
    }

    [Fact]
    public async Task RangeOutsideAllAdaptersAsksNobody()
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();

        var found = await LocalDiscovery.RunAsync(new[] { Adapter("192.168.1.5", 24) }, Range("127.0.0.1"), CancellationToken.None);

        Assert.Empty(found);
        Assert.True(watch.ElapsedMilliseconds < 1000);
    }

    [Fact]
    public async Task StoppedScanEndsWithoutError()
    {
        using var cancel = new CancellationTokenSource();
        cancel.Cancel();

        var found = await LocalDiscovery.RunAsync(new[] { Adapter("127.0.0.1", 8) }, Range("127.0.0.1"), cancel.Token);

        Assert.Empty(found);
    }

    [Theory]
    [InlineData("Dr. Who TV", "Dr. Who TV")]
    [InlineData("nas.fritz.box", "nas")]
    [InlineData("nas", "nas")]
    public void ShortNameKeepsNamesWithSpaces(string name, string expected) => Assert.Equal(expected, DeviceNames.Short(name));

    [Fact]
    public void VeryLongNameIsCut() => Assert.Equal(81, DeviceNames.Clean(new string('x', 500)).Length);

    [Fact]
    public void AnnouncementsComplementEachOther()
    {
        var mdns = new DeviceAnnouncement("Drucker", "");
        var upnp = new DeviceAnnouncement("Anderer Name", "LaserJet");

        Assert.Equal(new DeviceAnnouncement("Drucker", "LaserJet"), mdns.OrElse(upnp));
        Assert.Equal(mdns, mdns.OrElse(null));
    }
}

public class AnnouncedNameInListTests
{
    private static HostViewModel Host() => new(0xC0000232, 1, false, () => "root");

    [Fact]
    public void NamelessDeviceShowsWhatItAnnounces()
    {
        var host = Host();
        host.Announce("Dr. Who TV", "Chromecast");

        Assert.Equal("Dr. Who TV", host.DisplayName);
        Assert.Equal("Dr. Who TV", host.ExportName);
        Assert.Equal("Dr. Who TV", host.InventoryName);
        Assert.Equal("Meldet sich als: Dr. Who TV · Chromecast", host.AnnouncedText);
    }

    [Fact]
    public void DnsNameAndOwnNameGoFirst()
    {
        var host = Host();
        host.Announce("Wohnzimmer", "");
        host.Name = "tv.fritz.box";

        Assert.Equal("tv", host.DisplayName);
        Assert.Equal("Meldet sich als: Wohnzimmer", host.AnnouncedText);

        host.LoadCustomName("Mein TV");
        Assert.Equal("Mein TV", host.DisplayName);
    }

    [Fact]
    public void ModelEqualToTheNameIsShownOnce()
    {
        var host = Host();
        host.Announce("FRITZ!Box 5590", "FRITZ!Box 5590");

        Assert.Equal("Meldet sich als: FRITZ!Box 5590", host.AnnouncedText);
    }

    [Fact]
    public void NameIsNotRepeatedInTheDetails()
    {
        var host = Host();
        host.Name = "nas.local";
        host.Announce("nas", "");

        Assert.Equal("", host.AnnouncedText);
    }

    [Theory]
    [InlineData("wohnzimmer")]
    [InlineData("chromecast")]
    public void SearchFindsAnnouncedNameAndModel(string search)
    {
        var host = Host();
        host.Announce("Wohnzimmer", "Chromecast");

        Assert.True(host.Matches(search));
    }
}

public class WakeOnLanTests
{
    private const string Mac = "AA:BB:CC:DD:EE:01";

    private static AdapterInfo Adapter(string address, int prefix)
    {
        Assert.True(Ipv4.TryParse(address, out var ip));
        return new AdapterInfo("Karte", "", ip, prefix, "AA:BB:CC:DD:EE:FF", true);
    }

    [Fact]
    public void MagicPacketIsSixTimesFfAndSixteenTimesTheAddress()
    {
        var packet = WakeOnLan.BuildPacket(Mac);

        Assert.Equal(102, packet.Length);
        Assert.All(packet[..6], b => Assert.Equal(0xFF, b));
        for (var i = 1; i <= 16; i++)
        {
            Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01 }, packet[(i * 6)..(i * 6 + 6)]);
        }
    }

    [Theory]
    [InlineData("AA:BB:CC")]
    [InlineData("XX:BB:CC:DD:EE:01")]
    [InlineData("")]
    public void InvalidAddressIsRejected(string mac) => Assert.Throws<FormatException>(() => WakeOnLan.BuildPacket(mac));

    [Fact]
    public void GoesToTheBroadcastOfTheDevicesNetwork()
    {
        var other = Adapter("10.0.0.5", 8);
        var home = Adapter("192.168.1.5", 24);

        var adapter = WakeOnLan.AdapterFor(0xC0A80132, new[] { other, home });

        Assert.Equal(home, adapter);
        Assert.Equal(new[] { IPAddress.Parse("192.168.1.255"), IPAddress.Broadcast }, WakeOnLan.Targets(adapter!));
    }

    [Fact]
    public async Task DeviceInForeignNetworkIsNotSentAnything()
    {
        var result = await WakeOnLan.SendAsync(Mac, 0xC6336401, new[] { Adapter("192.168.1.5", 24) });

        Assert.Equal(WakeResult.NoNetwork, result);
    }

    [Theory]
    [InlineData(WakeResult.Sent, "gesendet")]
    [InlineData(WakeResult.NoNetwork, "keine Netzwerkkarte")]
    [InlineData(WakeResult.Failed, "nicht gesendet")]
    public void MessageSaysWhatHappened(WakeResult result, string expected) =>
        Assert.Contains(expected, WakeOnLan.Describe(result, "NAS"));

    [Fact]
    public void SendingNeverClaimsTheDeviceWokeUp() =>
        Assert.Contains("nächste Scan", WakeOnLan.Describe(WakeResult.Sent, "NAS"));

    private static KnownDevice Known(string key, uint ip, string mac) =>
        new(key, ip, mac, "", "", DateTime.UtcNow, DateTime.UtcNow);

    [Fact]
    public void CandidatesNeedAMacAndMustNotBeOnline()
    {
        var inventory = new DeviceInventory
        {
            Devices = new()
            {
                Known(Mac, 3, Mac),
                Known("AA:BB:CC:DD:EE:02", 1, "AA:BB:CC:DD:EE:02"),
                Known("ip:0.0.0.2", 2, ""),
                Known("AA:BB:CC:DD:EE:03", 4, "AA:BB:CC:DD:EE:03"),
            },
        };

        var candidates = inventory.WakeCandidates(new HashSet<string> { "AA:BB:CC:DD:EE:03" }).Select(d => d.Ip);

        Assert.Equal(new uint[] { 1, 3 }, candidates);
    }

    [Fact]
    public void ChipOffersWakingOnlyWithMacAndHandler()
    {
        MissingDeviceViewModel? woken = null;
        var device = new KnownDevice(Mac, 1, Mac, "nas.fritz.box", "", DateTime.UtcNow, DateTime.UtcNow);

        var withWake = new MissingDeviceViewModel(device, "", d => woken = d);
        withWake.WakeCommand.Execute(null);

        Assert.Same(withWake, woken);
        Assert.True(withWake.CanWake);
        Assert.Contains("Wake-on-LAN", withWake.ToolTipText);
        Assert.Equal("nas", withWake.Label);

        Assert.False(new MissingDeviceViewModel(device).CanWake);
        Assert.False(new MissingDeviceViewModel(device with { Mac = "" }, "", _ => { }).CanWake);
    }
}
