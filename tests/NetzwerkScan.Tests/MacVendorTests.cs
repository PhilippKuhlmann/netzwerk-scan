using System.IO;
using NetzwerkScan.Core;
using Xunit;

namespace NetzwerkScan.Tests;

public class MacVendorLookupTests
{
    [Theory]
    [InlineData("BC:24:11:AA:BB:CC", "Proxmox VM")]
    [InlineData("52:54:00:12:34:56", "QEMU/KVM")]
    [InlineData("00:15:5D:12:34:56", "Hyper-V")]
    [InlineData("08:00:27:12:34:56", "VirtualBox")]
    public void VirtualMachinesGetTheirFriendlyName(string mac, string vendor) =>
        Assert.Equal(vendor, MacVendors.Lookup(mac));

    [Theory]
    [InlineData("00:50:56:00:00:01", "VMware")]
    [InlineData("DC:A6:32:00:00:01", "Raspberry Pi")]
    [InlineData("00:11:32:00:00:01", "Synology")]
    [InlineData("24:A4:3C:00:00:01", "Ubiquiti")]
    [InlineData("3C:A6:2F:00:00:01", "AVM")]
    public void FindsRealManufacturers(string mac, string expectedPart) =>
        Assert.Contains(expectedPart, MacVendors.Lookup(mac), StringComparison.OrdinalIgnoreCase);

    [Fact]
    public void AcceptsLowerCaseAndDashes() =>
        Assert.Equal(MacVendors.Lookup("00:50:56:00:00:01"), MacVendors.Lookup("00-50-56-00-00-01".ToLowerInvariant()));

    [Theory]
    [InlineData("DA:A1:19:00:00:01", "Zufällige MAC")]
    [InlineData("", "")]
    [InlineData("00:50", "")]
    [InlineData("ZZ:ZZ:ZZ:ZZ:ZZ:ZZ", "")]
    [InlineData("00:50:56:00:00:01:02:03", "")] // 8 byte hardware address, not a MAC
    public void HandlesRandomAndInvalidAddresses(string mac, string expected) =>
        Assert.Equal(expected, MacVendors.Lookup(mac));

    [Fact]
    public void RegistryIsComplete() => Assert.True(MacVendors.RegistrySize > 50000, $"Only {MacVendors.RegistrySize} entries");

    [Theory]
    [InlineData("00:50:C2:00:00:01")] // IAB blocks, which only iab.csv names
    [InlineData("40:D8:55:00:00:01")]
    public void CoversIabBlocks(string mac) => Assert.NotEqual("", MacVendors.Lookup(mac));

    [Fact]
    public void HtmlEntitiesAreDecoded() => Assert.Equal("R&M AG", MacVendors.Lookup("34:4F:5C:00:00:01"));
}

public class BestMacTests
{
    private const uint Ip = 0xC00002FC; // 192.0.2.252
    private static readonly AdapterInfo Ethernet = new("Ethernet", "", 0xC00002FE, 24, "", true, InterfaceIndex: 4);
    private static readonly AdapterInfo Other = new("Ethernet 2", "", 0xC6336401, 24, "", true, InterfaceIndex: 7);
    private static readonly AdapterInfo[] Adapters = { Ethernet, Other };

    [Fact]
    public void PrefersTheAdapterWhoseSubnetHoldsTheIp()
    {
        var rows = new[]
        {
            new NeighborEntry(Ip, "BC:24:11:00:00:01", NeighborState.Stale, 4),
            new NeighborEntry(Ip, "BC:24:11:00:00:02", NeighborState.Reachable, 7),
        };

        Assert.Equal("BC:24:11:00:00:01", NeighborTable.BestMacs(rows, Adapters)[Ip]);
        Assert.Equal("BC:24:11:00:00:01", NeighborTable.BestMacs(rows.Reverse(), Adapters)[Ip]);
    }

    [Fact]
    public void WithoutSuchAdapterTheConfirmedRowWins()
    {
        var rows = new[]
        {
            new NeighborEntry(Ip, "00:00:00:00:00:01", NeighborState.Stale, 7),
            new NeighborEntry(Ip, "00:00:00:00:00:02", NeighborState.Reachable, 9),
        };

        Assert.Equal("00:00:00:00:00:02", NeighborTable.BestMacs(rows, Adapters)[Ip]);
    }

    [Fact]
    public void IgnoresRowsWithoutAUsableAddress()
    {
        var rows = new[]
        {
            new NeighborEntry(Ip, "00:00:00:00:00:00", NeighborState.Reachable, 4),
            new NeighborEntry(Ip + 1, "BC:24:11:00:00:01", NeighborState.Unreachable, 4),
            new NeighborEntry(Ip + 2, "BC:24:11:00:00:01", NeighborState.Incomplete, 4),
        };

        Assert.Empty(NeighborTable.BestMacs(rows, Adapters));
    }
}

public class MacVendorRegistryFormatTests
{
    [Fact]
    public void ParsesAllPrefixLengthsAndSkipsMalformedLines()
    {
        var registry = MacVendors.ParseRegistry(new StringReader(
            "AABBCC\tSix\nAABBCCD\tSeven\nAABBCCDDE\tNine\nnonsense\nAABB\tTooShort\nAABBCC12\tEight\nDDEEFF\t\n\n"));

        Assert.Equal(3, registry.Count);
        Assert.Equal("Six", registry["AABBCC"]);
        Assert.Equal("Seven", registry["AABBCCD"]);
        Assert.Equal("Nine", registry["AABBCCDDE"]);
    }
}

public class VendorShortNameTests
{
    [Theory]
    [InlineData("Apple, Inc.", "Apple")]
    [InlineData("Samsung Electronics Co.,Ltd", "Samsung Electronics")]
    [InlineData("HUAWEI TECHNOLOGIES CO.,LTD", "HUAWEI TECHNOLOGIES")]
    [InlineData("Ubiquiti Inc", "Ubiquiti")]
    [InlineData("Synology Incorporated", "Synology")]
    [InlineData("Proxmox Server Solutions GmbH", "Proxmox Server Solutions")]
    [InlineData("Foo GmbH & Co. KG", "Foo")]
    [InlineData("Intel Corporate", "Intel Corporate")]
    [InlineData("AVM Audiovisuelles Marketing und Computersysteme GmbH", "AVM")]
    [InlineData("Motorola Mobility LLC, a Lenovo Company", "Motorola Mobility")]
    [InlineData("Festo AG & Co. KG", "Festo")]
    [InlineData("PuS GmbH und Co. KG", "PuS")]
    [InlineData("LINEAGE POWER PVT LTD.,", "LINEAGE POWER")]
    [InlineData("Nokia Solutions and Networks India Private Limited", "Nokia Solutions and Networks India")]
    [InlineData("San Telequip (P) Ltd.,", "San Telequip")]
    [InlineData("SHENZHEN BILIAN ELECTRONIC CO.，LTD", "SHENZHEN BILIAN ELECTRONIC")]
    [InlineData("Wistron InfoComm(Kunshan)Co.,Ltd.", "Wistron InfoComm(Kunshan)")]
    [InlineData("SHEN ZHEN HUAWANG TECHNOLOGY CO; LTD", "SHEN ZHEN HUAWANG TECHNOLOGY")]
    [InlineData("Amgen U.S.A. Inc.", "Amgen U.S.A")]
    [InlineData("R.I.CO. S.r.l.", "R.I.CO")]
    [InlineData("BUFFALO.INC", "BUFFALO")]
    [InlineData("Canal +", "Canal +")]
    [InlineData("SBS TECHNOLOGIES,", "SBS TECHNOLOGIES")]
    [InlineData("CBL - GMBH", "CBL")]
    [InlineData("Zufällige MAC", "Zufällige MAC")]
    [InlineData("Hyper-V", "Hyper-V")]
    [InlineData("", "")]
    public void RemovesLegalForm(string vendor, string expected) =>
        Assert.Equal(expected, MacVendors.ShortName(vendor));

    [Theory]
    [InlineData("Inc.")]
    [InlineData("Co")]
    [InlineData("AG")]
    public void NeverRemovesTheWholeName(string vendor) => Assert.Equal(vendor, MacVendors.ShortName(vendor));

    [Fact]
    public void WordsThatOnlyLookLikeLegalFormsSurvive()
    {
        Assert.Equal("Cisco", MacVendors.ShortName("Cisco"));
        Assert.Equal("Sonos", MacVendors.ShortName("Sonos, Inc."));
        Assert.Equal("Tesla", MacVendors.ShortName("Tesla"));
    }
}

public class ThemeModeTests
{
    [Theory]
    [InlineData("Dark", AppTheme.Dark)]
    [InlineData("dark\r\n", AppTheme.Dark)]
    [InlineData("Light", AppTheme.Light)]
    [InlineData("System", AppTheme.System)]
    [InlineData(null, AppTheme.System)]
    [InlineData("", AppTheme.System)]
    [InlineData("Lila", AppTheme.System)]
    [InlineData("7", AppTheme.System)]
    [InlineData("1", AppTheme.System)]
    public void ReadsSavedValueAndFallsBackToWindows(string? text, AppTheme expected) =>
        Assert.Equal(expected, ThemeManager.ParseMode(text));
}
