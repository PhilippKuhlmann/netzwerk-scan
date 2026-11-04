using System.IO;
using System.Text.Json;
using NetzwerkScan.Core;

namespace NetzwerkScan;

/// <summary>What the settings window remembers between runs. Network adapter and range are chosen per scan.</summary>
public sealed class AppSettings
{
    public const int DefaultTimeoutMs = 800;
    public const int MinTimeoutMs = 50;
    public const int MaxTimeoutMs = 30000;

    private static readonly string FilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetzwerkScan", "settings.json");

    public string Theme { get; set; } = nameof(AppTheme.System);
    public bool ScanPorts { get; set; } = true;
    public string Ports { get; set; } = PortCatalog.DefaultPortsText;
    public bool FindShares { get; set; } = true;
    public int TimeoutMs { get; set; } = DefaultTimeoutMs;
    public string SshUser { get; set; } = "";

    public static AppSettings Load()
    {
        try
        {
            return File.Exists(FilePath) ? Parse(File.ReadAllText(FilePath)) : new AppSettings();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return new AppSettings();
        }
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, ToJson());
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Not being able to remember the choice is no reason to get in the way. It still applies for now.
        }
    }

    /// <summary>The file can be edited by hand, so anything that doesn't make sense falls back to its default.</summary>
    public static AppSettings Parse(string json)
    {
        AppSettings? settings;
        try
        {
            settings = JsonSerializer.Deserialize<AppSettings>(json);
        }
        catch (JsonException)
        {
            return new AppSettings();
        }
        if (settings is null) return new AppSettings();

        var defaults = new AppSettings();
        if (!PortList.TryParse(settings.Ports, out _, out _)) settings.Ports = defaults.Ports;
        if (settings.TimeoutMs is < MinTimeoutMs or > MaxTimeoutMs) settings.TimeoutMs = defaults.TimeoutMs;
        settings.Theme = ThemeManager.ParseMode(settings.Theme).ToString();
        if (settings.SshUser is null || !RemoteCommands.IsValidSshUser(settings.SshUser)) settings.SshUser = "";
        return settings;
    }

    public string ToJson() => JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
}
