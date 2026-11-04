using System.IO;
using NetzwerkScan.Core;
using NetzwerkScan.ViewModels;
using Xunit;

namespace NetzwerkScan.Tests;

public class CsvExportTests
{
    [Fact]
    public void QuotesAndSeparatesWithSemicolons()
    {
        var csv = CsvExport.Build(new[] { new CsvRow("Neu", "192.0.2.1", "nas;01", "", "A \"B\" C", "1 ms", "22 SSH, 80 HTTP", "http://192.0.2.1/", "") });

        var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        Assert.StartsWith("\"Status\";\"IP-Adresse\"", lines[0]);
        Assert.Equal("\"Neu\";\"192.0.2.1\";\"nas;01\";\"\";\"A \"\"B\"\" C\";\"1 ms\";\"22 SSH, 80 HTTP\";\"http://192.0.2.1/\";\"\"", lines[1]);
    }

    [Theory]
    [InlineData("=HYPERLINK(\"http://evil\")", "\"'=HYPERLINK(\"\"http://evil\"\")\"")]
    [InlineData("+1+1", "\"'+1+1\"")]
    [InlineData("-1", "\"'-1\"")]
    [InlineData("@SUM(A1)", "\"'@SUM(A1)\"")]
    [InlineData("Normal", "\"Normal\"")]
    [InlineData("", "\"\"")]
    public void DefusesFormulasFromDeviceNames(string value, string expected) =>
        Assert.Equal(expected, CsvExport.Cell(value));

    [Fact]
    public void LineBreaksStayInOneRow() => Assert.Equal("\"a b\"", CsvExport.Cell("a\r\nb"));

    [Fact]
    public void FileStartsWithByteOrderMarkForExcel() => Assert.NotEmpty(CsvExport.FileEncoding.GetPreamble());
}

public class DeviceInventoryTests
{
    private const uint A = 0xC0000201, B = 0xC0000202, C = 0xC0000203;
    private const string MacA = "00:00:5E:00:53:01", MacB = "00:00:5E:00:53:02", MacC = "00:00:5E:00:53:03";
    private static readonly IpRange Range = new(0xC0000201, 0xC00002FE);
    private static readonly DateTime T1 = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime T2 = T1.AddHours(1);

    private static SeenDevice Seen(uint ip, string mac = "") => new(ip, mac, "", "");

    [Fact]
    public void FirstScanReportsNothingAndHasNoHistory()
    {
        var result = new DeviceInventory().Compare(Range, new[] { Seen(A, MacA) });

        Assert.Empty(result.NewIps);
        Assert.Empty(result.Missing);
        Assert.False(result.HadHistory);
    }

    [Fact]
    public void FindsNewAndMissingDevices()
    {
        var inventory = new DeviceInventory();
        inventory.Record(Range, new[] { Seen(A, MacA), Seen(B, MacB) }, T1);

        var result = inventory.Compare(Range, new[] { Seen(A, MacA), Seen(C, MacC) });

        Assert.Equal(new[] { C }, result.NewIps);
        Assert.Equal(MacB, Assert.Single(result.Missing).Mac);
        Assert.True(result.HadHistory);
    }

    [Fact]
    public void MissingDeviceIsReportedOnlyOnce()
    {
        var inventory = new DeviceInventory();
        inventory.Record(Range, new[] { Seen(A, MacA), Seen(B, MacB) }, T1);
        inventory.Record(Range, new[] { Seen(A, MacA) }, T2);

        Assert.Empty(inventory.Compare(Range, new[] { Seen(A, MacA) }).Missing);
    }

    [Fact]
    public void DeviceThatMovedToAnotherIpIsNeitherNewNorMissing()
    {
        var inventory = new DeviceInventory();
        inventory.Record(Range, new[] { Seen(A, MacA) }, T1);

        var result = inventory.Compare(Range, new[] { Seen(C, MacA) });

        Assert.Empty(result.NewIps);
        Assert.Empty(result.Missing);
    }

    [Fact]
    public void AnotherDeviceOnAKnownIpIsNew()
    {
        var inventory = new DeviceInventory();
        inventory.Record(Range, new[] { Seen(A, MacA) }, T1);

        var result = inventory.Compare(Range, new[] { Seen(A, MacB) });

        Assert.Equal(new[] { A }, result.NewIps);
        Assert.Single(result.Missing);
    }

    [Fact]
    public void DevicesOutsideTheScannedRangeAreNotMissing()
    {
        var inventory = new DeviceInventory();
        inventory.Record(Range, new[] { Seen(A, MacA), Seen(B, MacB) }, T1);

        var narrow = new IpRange(A, A);
        Assert.Empty(inventory.Compare(narrow, new[] { Seen(A, MacA) }).Missing);
    }

    [Fact]
    public void NarrowScanDoesNotHideALaterMissingDevice()
    {
        var inventory = new DeviceInventory();
        inventory.Record(Range, new[] { Seen(A, MacA), Seen(B, MacB) }, T1);
        inventory.Record(new IpRange(A, A), new[] { Seen(A, MacA) }, T2);

        Assert.Equal(MacB, Assert.Single(inventory.Compare(Range, new[] { Seen(A, MacA) }).Missing).Mac);
    }

    [Fact]
    public void AddressNeverScannedBeforeIsNotNew()
    {
        var inventory = new DeviceInventory();
        inventory.Record(new IpRange(A, A), new[] { Seen(A, MacA) }, T1);

        Assert.Empty(inventory.Compare(Range, new[] { Seen(A, MacA), Seen(B, MacB) }).NewIps);
    }

    [Fact]
    public void DeviceWithoutMacIsMatchedByIp()
    {
        var inventory = new DeviceInventory();
        inventory.Record(Range, new[] { Seen(A) }, T1);

        var routed = inventory.Compare(Range, new[] { Seen(A) });
        Assert.Empty(routed.NewIps);
        Assert.Empty(routed.Missing);

        var nowWithMac = inventory.Compare(Range, new[] { Seen(A, MacA) });
        Assert.Empty(nowWithMac.NewIps);
        Assert.Empty(nowWithMac.Missing);
    }

    [Fact]
    public void KnownDeviceWithMacIsNotNewWhenScannedWithout()
    {
        var inventory = new DeviceInventory();
        inventory.Record(Range, new[] { Seen(A, MacA) }, T1);

        Assert.Empty(inventory.Compare(Range, new[] { Seen(A) }).NewIps);
    }

    [Fact]
    public void KeepsFirstSeenAndFillsNamesWithoutLosingThem()
    {
        var inventory = new DeviceInventory();
        inventory.Record(Range, new[] { new SeenDevice(A, MacA, "nas", "Synology") }, T1);
        inventory.Record(Range, new[] { Seen(A, MacA) }, T2);

        var device = Assert.Single(inventory.Devices);
        Assert.Equal("nas", device.Name);
        Assert.Equal("Synology", device.Vendor);
        Assert.Equal(T1, device.FirstSeenUtc);
        Assert.Equal(T2, device.LastSeenUtc);
    }

    [Fact]
    public void ForgetsDevicesNotSeenForLong()
    {
        var inventory = new DeviceInventory();
        inventory.Record(Range, new[] { Seen(A, MacA), Seen(B, MacB) }, T1);
        inventory.Record(Range, new[] { Seen(A, MacA) }, T1.AddDays(200));

        Assert.Equal(MacA, Assert.Single(inventory.Devices).Mac);
    }

    [Fact]
    public void SurvivesSavingAndLoadingWithExactTimes()
    {
        var inventory = new DeviceInventory();
        inventory.Record(Range, new[] { Seen(A, MacA), Seen(B, MacB) }, DateTime.UtcNow);

        var loaded = DeviceInventory.Parse(inventory.ToJson());

        Assert.Equal(2, loaded.Devices.Count);
        Assert.Equal(MacB, Assert.Single(loaded.Compare(Range, new[] { Seen(A, MacA) }).Missing).Mac);
    }

    [Theory]
    [InlineData("")]
    [InlineData("kaputt")]
    [InlineData("null")]
    public void DamagedFileStartsEmpty(string json) => Assert.Empty(DeviceInventory.Parse(json).Devices);

    [Theory]
    [InlineData(2, 1, true, true, "Seit dem letzten Scan: 2 Geräte neu, 1 verschwunden")]
    [InlineData(1, 2, true, true, "Seit dem letzten Scan: 1 Gerät neu, 2 verschwunden")]
    [InlineData(0, 0, true, true, "Keine Änderungen seit dem letzten Scan.")]
    [InlineData(0, 0, false, true, "Erster Scan dieses Bereichs: Die Geräte sind jetzt bekannt.")]
    [InlineData(0, 0, true, false, "")]
    [InlineData(1, 0, true, false, "1 Gerät neu (Scan abgebrochen, verschwundene Geräte nicht geprüft)")]
    public void DescribesChanges(int added, int missing, bool history, bool completed, string expected) =>
        Assert.Equal(expected, MainViewModel.DescribeChanges(added, missing, history, completed));
}

public class RemoteCommandTests
{
    [Fact]
    public void RdpTargetsTheHost()
    {
        var start = RemoteCommands.Rdp("192.0.2.1");
        Assert.Equal("mstsc.exe", start.FileName);
        Assert.Equal(new[] { "/v:192.0.2.1" }, start.ArgumentList);
    }

    [Theory]
    [InlineData("", "192.0.2.1")]
    [InlineData("root", "root@192.0.2.1")]
    [InlineData("a.b-c_d", "a.b-c_d@192.0.2.1")]
    public void SshUsesTheUserIfThereIsOne(string user, string target)
    {
        var start = RemoteCommands.Ssh("192.0.2.1", user);
        Assert.Equal("cmd.exe", start.FileName);
        Assert.Equal(new[] { "/k", "ssh", target }, start.ArgumentList);
    }

    [Theory]
    [InlineData("-oProxyCommand=calc")]
    [InlineData("a b")]
    [InlineData("a&calc")]
    [InlineData("a|b")]
    [InlineData("a\"b")]
    [InlineData("a@b")]
    public void UnsafeUserNameNeverReachesTheCommandLine(string user)
    {
        Assert.False(RemoteCommands.IsValidSshUser(user));
        Assert.Equal("192.0.2.1", RemoteCommands.SshTarget("192.0.2.1", user));
    }
}

public class PortViewModelTests
{
    private static PortViewModel Port(int port, string user = "") => new("192.0.2.1", port, () => user);

    [Theory]
    [InlineData(22)]
    [InlineData(3389)]
    public void RemotePortsAreClickableWithoutBeingWeb(int port)
    {
        var vm = Port(port);
        Assert.True(vm.IsClickable);
        Assert.True(vm.IsRemote);
        Assert.False(vm.IsWeb);
        Assert.EndsWith("↗", vm.ChipText);
    }

    [Fact]
    public void OtherPortsBecomeClickableOnlyAsWebsite()
    {
        var vm = Port(8006);
        Assert.False(vm.IsClickable);

        vm.SetWeb(new WebInfo("https", "Proxmox", null));
        Assert.True(vm.IsClickable);
        Assert.False(vm.IsRemote);
        Assert.Equal("https://192.0.2.1:8006/", vm.Url);
    }

    [Fact]
    public void TooltipShowsTheSshCommand() =>
        Assert.Contains("ssh root@192.0.2.1", Port(22, "root").ToolTipText);
}

public class SettingsSshUserTests
{
    [Fact]
    public void BadUserFromFileIsDropped() => Assert.Equal("", AppSettings.Parse("{\"SshUser\":\"-oProxyCommand=calc\"}").SshUser);

    [Fact]
    public void GoodUserSurvives() => Assert.Equal("root", AppSettings.Parse(new AppSettings { SshUser = "root" }.ToJson()).SshUser);
}

public class AppUpdaterTests
{
    private const string Base = "https://github.com/PhilippKuhlmann/netzwerk-scan/releases/download/v1.2.0/";
    private static readonly Version Current = new(1, 1, 0);

    private static string Release(string tag = "v1.2.0", string exeUrl = Base + "NetzwerkScan.exe", string shaUrl = Base + "NetzwerkScan.exe.sha256") =>
        $$"""
        {"tag_name":"{{tag}}","assets":[
          {"name":"NetzwerkScan.exe","browser_download_url":"{{exeUrl}}"},
          {"name":"NetzwerkScan.exe.sha256","browser_download_url":"{{shaUrl}}"}]}
        """;

    [Fact]
    public void FindsNewerRelease()
    {
        var update = AppUpdater.ParseRelease(Release(), Current);
        Assert.NotNull(update);
        Assert.Equal(new Version(1, 2, 0), update!.Version);
        Assert.EndsWith("NetzwerkScan.exe", update.ExeUrl);
    }

    [Theory]
    [InlineData("v1.1.0")]  // same version
    [InlineData("v1.0.9")]  // never downgrade
    [InlineData("1.2.0")]   // not our tag format
    [InlineData("v1.2")]
    [InlineData("v1.2.0-beta")]
    [InlineData("latest")]
    public void IgnoresTagsThatAreNotANewerRelease(string tag) =>
        Assert.Null(AppUpdater.ParseRelease(Release(tag), Current));

    [Theory]
    [InlineData("https://evil.example/NetzwerkScan.exe")]
    [InlineData("http://github.com/PhilippKuhlmann/netzwerk-scan/releases/download/v1.2.0/NetzwerkScan.exe")]
    [InlineData("https://github.com/Someone/netzwerk-scan/releases/download/v1.2.0/NetzwerkScan.exe")]
    [InlineData("https://github.com.evil.example/PhilippKuhlmann/netzwerk-scan/releases/download/v1.2.0/NetzwerkScan.exe")]
    public void RefusesDownloadsFromAnywhereElse(string url) =>
        Assert.Null(AppUpdater.ParseRelease(Release(exeUrl: url), Current));

    [Theory]
    [InlineData("")]
    [InlineData("kein json")]
    [InlineData("{}")]
    [InlineData("{\"tag_name\":\"v9.9.9\"}")]
    [InlineData("{\"tag_name\":\"v9.9.9\",\"assets\":[]}")]
    [InlineData("{\"tag_name\":null,\"assets\":[]}")]
    public void BadAnswersMeanNoUpdate(string json) => Assert.Null(AppUpdater.ParseRelease(json, Current));

    [Fact]
    public void ReleaseWithoutChecksumIsIgnored()
    {
        const string json = "{\"tag_name\":\"v9.9.9\",\"assets\":[{\"name\":\"NetzwerkScan.exe\",\"browser_download_url\":\"" + Base + "NetzwerkScan.exe\"}]}";
        Assert.Null(AppUpdater.ParseRelease(json, Current));
    }

    [Theory]
    [InlineData("ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789  NetzwerkScan.exe\n")]
    [InlineData("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")]
    public void ReadsChecksum(string text) =>
        Assert.Equal("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", AppUpdater.ParseChecksum(text));

    [Theory]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("zzzdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")]
    public void RejectsBadChecksum(string text) => Assert.Null(AppUpdater.ParseChecksum(text));

    [Fact]
    public void DevelopmentBuildsNeverUpdateThemselves() => Assert.Null(AppUpdater.InstallPath);

    [Fact]
    public void ReplaceFileSwapsAndKeepsTheOldVersion()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var (exe, fresh, old) = (Path.Combine(dir, "a.exe"), Path.Combine(dir, "a.exe.new"), Path.Combine(dir, "a.exe.old"));
            File.WriteAllText(exe, "alt");
            File.WriteAllText(fresh, "neu");

            AppUpdater.ReplaceFile(exe, fresh, old);

            Assert.Equal("neu", File.ReadAllText(exe));
            Assert.Equal("alt", File.ReadAllText(old));
            Assert.False(File.Exists(fresh));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void ReplaceFileRestoresTheExeIfTheNewFileIsMissing()
    {
        var dir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var (exe, fresh, old) = (Path.Combine(dir, "a.exe"), Path.Combine(dir, "a.exe.new"), Path.Combine(dir, "a.exe.old"));
            File.WriteAllText(exe, "alt");

            Assert.Throws<FileNotFoundException>(() => AppUpdater.ReplaceFile(exe, fresh, old));

            Assert.Equal("alt", File.ReadAllText(exe));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}
