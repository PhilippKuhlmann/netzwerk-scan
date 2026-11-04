using NetzwerkScan.Core;
using Xunit;

namespace NetzwerkScan.Tests;

public class AppSettingsTests
{
    [Fact]
    public void RoundTripKeepsEveryValue()
    {
        var original = new AppSettings
        {
            Theme = nameof(AppTheme.Dark),
            ScanPorts = false,
            Ports = "22,8006",
            FindShares = false,
            TimeoutMs = 1500,
        };

        var loaded = AppSettings.Parse(original.ToJson());

        Assert.Equal(nameof(AppTheme.Dark), loaded.Theme);
        Assert.False(loaded.ScanPorts);
        Assert.Equal("22,8006", loaded.Ports);
        Assert.False(loaded.FindShares);
        Assert.Equal(1500, loaded.TimeoutMs);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("null")]
    [InlineData("[1,2]")]
    [InlineData("{\"TimeoutMs\":\"schnell\"}")]
    public void DamagedFileGivesDefaults(string json)
    {
        var settings = AppSettings.Parse(json);

        Assert.Equal(AppSettings.DefaultTimeoutMs, settings.TimeoutMs);
        Assert.True(settings.ScanPorts);
        Assert.True(settings.FindShares);
        Assert.Equal(PortCatalog.DefaultPortsText, settings.Ports);
    }

    [Theory]
    [InlineData("{\"Ports\":\"abc\"}")]
    [InlineData("{\"Ports\":\"\"}")]
    [InlineData("{\"Ports\":null}")]
    [InlineData("{\"TimeoutMs\":0}")]
    [InlineData("{\"TimeoutMs\":99999}")]
    [InlineData("{\"Theme\":\"Lila\"}")]
    public void SingleBadValueFallsBackWithoutLosingTheRest(string json)
    {
        var settings = AppSettings.Parse(json);

        Assert.True(PortList.TryParse(settings.Ports, out _, out _));
        Assert.InRange(settings.TimeoutMs, AppSettings.MinTimeoutMs, AppSettings.MaxTimeoutMs);
        Assert.Equal(AppTheme.System, ThemeManager.ParseMode(settings.Theme));
    }

    [Fact]
    public void GoodValuesNextToABadOneSurvive()
    {
        var settings = AppSettings.Parse("{\"Ports\":\"abc\",\"TimeoutMs\":2000,\"FindShares\":false}");

        Assert.Equal(PortCatalog.DefaultPortsText, settings.Ports);
        Assert.Equal(2000, settings.TimeoutMs);
        Assert.False(settings.FindShares);
    }
}

