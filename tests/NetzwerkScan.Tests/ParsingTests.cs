using NetzwerkScan.Core;
using Xunit;

namespace NetzwerkScan.Tests;

public class IpRangeTests
{
    [Theory]
    [InlineData("192.168.1.0/24", "192.168.1.1", "192.168.1.254", 254)]
    [InlineData("192.168.1.77/24", "192.168.1.1", "192.168.1.254", 254)]
    [InlineData("10.0.0.0/30", "10.0.0.1", "10.0.0.2", 2)]
    [InlineData("10.0.0.0/31", "10.0.0.0", "10.0.0.1", 2)]
    [InlineData("10.0.0.5/32", "10.0.0.5", "10.0.0.5", 1)]
    [InlineData("10.1.0.0/16", "10.1.0.1", "10.1.255.254", 65534)]
    [InlineData("192.168.1.10-50", "192.168.1.10", "192.168.1.50", 41)]
    [InlineData("192.168.1.250-192.168.2.5", "192.168.1.250", "192.168.2.5", 12)]
    [InlineData(" 192.168.1.10 ", "192.168.1.10", "192.168.1.10", 1)]
    public void Parses(string text, string first, string last, int count)
    {
        Assert.True(IpRange.TryParse(text, out var range, out _));
        Assert.Equal(first, Ipv4.ToText(range.First));
        Assert.Equal(last, Ipv4.ToText(range.Last));
        Assert.Equal(count, range.Count);
        Assert.Equal(count, range.Addresses().Count());
    }

    [Theory]
    [InlineData("")]
    [InlineData("192.168")]
    [InlineData("192.168.1.300")]
    [InlineData("192.168.1.0/33")]
    [InlineData("192.168.1.50-10")]
    [InlineData("10.0.0.0/8")]
    [InlineData("abc")]
    public void Rejects(string text)
    {
        Assert.False(IpRange.TryParse(text, out _, out var error));
        Assert.NotEmpty(error);
    }

    [Fact]
    public void TopOfAddressSpaceDoesNotOverflow()
    {
        Assert.True(IpRange.TryParse("255.255.255.250-255", out var range, out _));
        Assert.Equal(6, range.Addresses().Count());
    }
}

public class PortListTests
{
    [Fact]
    public void ParsesListsAndRangesSortedWithoutDuplicates()
    {
        Assert.True(PortList.TryParse("443, 80,8000-8002;80", out var ports, out _));
        Assert.Equal(new[] { 80, 443, 8000, 8001, 8002 }, ports);
    }

    [Theory]
    [InlineData("")]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("90-80")]
    [InlineData("1-2-3")]
    [InlineData("http")]
    public void Rejects(string text) => Assert.False(PortList.TryParse(text, out _, out _));

}

public class PortCatalogTests
{
    [Fact]
    public void StandardSelectionIsValidAndCoversWhatMatters()
    {
        Assert.True(PortList.TryParse(PortCatalog.DefaultPortsText, out var ports, out var error), error);
        Assert.Equal(63, ports.Length);
        Assert.Contains(80, ports);
        Assert.Contains(443, ports);
        Assert.Contains(8006, ports);
        Assert.Contains(445, ports);
    }

    [Fact]
    public void WebSelectionHasOnlyWebPorts()
    {
        var web = PortCatalog.WebPorts.ToList();
        Assert.Contains(80, web);
        Assert.Contains(443, web);
        Assert.Contains(8006, web);
        Assert.Contains(8123, web);
        Assert.DoesNotContain(22, web);
        Assert.DoesNotContain(445, web);
    }

    [Fact]
    public void WebPortsMayBeProbed()
    {
        foreach (var port in PortCatalog.WebPorts) Assert.True(ServiceCatalog.MayProbeWeb(port), $"Port {port}");
    }

    [Fact]
    public void EveryPortIsListedOnceAndDescribed()
    {
        Assert.Equal(PortCatalog.All.Count, PortCatalog.All.Select(p => p.Port).Distinct().Count());
        foreach (var info in PortCatalog.All)
        {
            Assert.False(string.IsNullOrWhiteSpace(info.Name), $"Port {info.Port}");
            Assert.False(string.IsNullOrWhiteSpace(info.Description), $"Port {info.Port}");
            Assert.False(string.IsNullOrWhiteSpace(info.Category), $"Port {info.Port}");
            Assert.InRange(info.Description.Length, 1, 60);
        }
    }

    [Fact]
    public void SplitSeparatesListedPortsFromTheRest()
    {
        var (listed, extra) = PortCatalog.Split("80, 8006,12345;8000-8100 1-1024");

        Assert.Equal(new HashSet<int> { 80, 8006 }, listed);
        Assert.Equal("12345,8000-8100,1-1024", extra);
    }

    [Fact]
    public void SplitAndComposeAreInverse()
    {
        var text = PortCatalog.DefaultPortsText + ",12345,20000-20010";

        var (listed, extra) = PortCatalog.Split(text);
        Assert.True(PortList.TryParse(PortCatalog.Compose(listed, extra), out var ports, out _));
        Assert.True(PortList.TryParse(text, out var expected, out _));
        Assert.Equal(expected, ports);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ,, ")]
    public void EmptyListSplitsIntoNothing(string? text)
    {
        var (listed, extra) = PortCatalog.Split(text);
        Assert.Empty(listed);
        Assert.Equal("", extra);
    }

    [Fact]
    public void ComposeKeepsInvalidExtrasSoThatValidationSeesThem()
    {
        Assert.False(PortList.TryParse(PortCatalog.Compose(new[] { 80 }, "abc"), out _, out var error));
        Assert.Contains("abc", error);
    }
}

public class ServiceCatalogTests
{
    [Theory]
    [InlineData(9100)] // would be printed on paper
    [InlineData(515)]
    [InlineData(502)]  // Modbus
    [InlineData(22)]
    public void DangerousOrNonHttpPortsAreNotProbed(int port) => Assert.False(ServiceCatalog.MayProbeWeb(port));

    [Theory]
    [InlineData(80)]
    [InlineData(8006)]
    [InlineData(12345)]
    public void OtherPortsAreProbed(int port) => Assert.True(ServiceCatalog.MayProbeWeb(port));

    [Fact]
    public void ProxmoxFallsBackToHttps() => Assert.Equal("https", ServiceCatalog.DefaultWebScheme(8006));
}

public class ShareNameTests
{
    [Theory]
    [InlineData("Daten")]
    [InlineData("C$")]
    [InlineData("Meine Filme")]
    public void AcceptsRealNames(string name) => Assert.True(SmbShares.IsValidShareName(name));

    [Theory]
    [InlineData("share\\evil.exe")]
    [InlineData("..\\..")]
    [InlineData("a/b")]
    [InlineData("a\"b")]
    [InlineData("..")]
    [InlineData("")]
    [InlineData("  ")]
    [InlineData("a\nb")]
    public void RejectsNamesThatCouldEscapeThePath(string name) => Assert.False(SmbShares.IsValidShareName(name));

    [Fact]
    public void HidesIpcAndFlagsAdministrativeShares()
    {
        Assert.Null(SmbShares.ToEntry("IPC$", 0x80000003, ""));

        var admin = SmbShares.ToEntry("C$", 0x80000000, "Standardfreigabe");
        Assert.NotNull(admin);
        Assert.True(admin!.IsAdministrative);
        Assert.Equal(ShareKind.Disk, admin.Kind);

        Assert.Equal(ShareKind.Printer, SmbShares.ToEntry("HP", 1, null)!.Kind);
    }
}

public class WebResponseTests
{
    [Fact]
    public void ReadsTitleAndServer()
    {
        var info = WebProbe.ParseResponse(
            "HTTP/1.1 200 OK\r\nserver: pve-api-daemon/3.0\r\n\r\n<html><head><TITLE lang=\"de\">\n pve &amp; co - Proxmox  VE\n</TITLE>", "https");
        Assert.NotNull(info);
        Assert.Equal("https", info!.Scheme);
        Assert.Equal("pve & co - Proxmox VE", info.Title);
        Assert.Equal("pve-api-daemon/3.0", info.Server);
    }

    [Fact]
    public void ResponseWithoutTitleStillCountsAsWeb()
    {
        var info = WebProbe.ParseResponse("HTTP/1.0 302 Found\r\nLocation: /login\r\n\r\n", "http");
        Assert.NotNull(info);
        Assert.Null(info!.Title);
        Assert.Null(info.Server);
    }

    [Theory]
    [InlineData("SSH-2.0-OpenSSH_9.6\r\n")]
    [InlineData("")]
    [InlineData("220 ftp ready")]
    public void OtherProtocolsAreNotWeb(string response) => Assert.Null(WebProbe.ParseResponse(response, "http"));
}

public class NetBiosTests
{
    [Fact]
    public void ReadsComputerNameAndWorkgroup()
    {
        var names = new (string Name, byte Suffix, bool Group)[]
        {
            ("NAS", 0x20, false),   // file service entry, not the computer name
            ("NAS", 0x00, false),
            ("WORKGROUP", 0x00, true),
        };

        var packet = new byte[56 + 1 + names.Length * 18 + 6];
        packet[56] = (byte)names.Length;
        for (var i = 0; i < names.Length; i++)
        {
            var offset = 57 + i * 18;
            var text = names[i].Name.PadRight(15);
            for (var c = 0; c < 15; c++) packet[offset + c] = (byte)text[c];
            packet[offset + 15] = names[i].Suffix;
            packet[offset + 16] = names[i].Group ? (byte)0x80 : (byte)0;
        }

        var info = NetBios.ParseNodeStatus(packet);
        Assert.Equal("NAS", info!.Name);
        Assert.Equal("WORKGROUP", info.Workgroup);
    }

    [Fact]
    public void ToleratesTruncatedPackets()
    {
        Assert.Null(NetBios.ParseNodeStatus(new byte[10]));

        var claimsTooMany = new byte[60];
        claimsTooMany[56] = 200;
        Assert.Null(NetBios.ParseNodeStatus(claimsTooMany));
    }
}

