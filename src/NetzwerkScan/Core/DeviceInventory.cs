using System.IO;
using System.Text.Json;

namespace NetzwerkScan.Core;

public sealed record SeenDevice(uint Ip, string Mac, string Name, string Vendor);

public sealed record KnownDevice(string Key, uint Ip, string Mac, string Name, string Vendor, DateTime FirstSeenUtc, DateTime LastSeenUtc);

public sealed record ScannedRange(uint First, uint Last, DateTime LastScanUtc);

/// <param name="NewIps">Found now, unknown before, at an address that was already scanned earlier.</param>
/// <param name="Missing">Present in the previous scan of their address, gone in this one.</param>
/// <param name="HadHistory">This range overlaps something scanned earlier, so a comparison means something.</param>
public sealed record ScanComparison(IReadOnlySet<uint> NewIps, IReadOnlyList<KnownDevice> Missing, bool HadHistory);

/// <summary>
/// Remembers which devices were seen on earlier scans. Stays on this PC. A device is identified by its MAC
/// address, or by its IP where no MAC is available, as behind a router. Phones with random MAC addresses
/// show up as new whenever they pick another address.
/// </summary>
public sealed class DeviceInventory
{
    private static readonly TimeSpan ForgetAfter = TimeSpan.FromDays(180);

    private static readonly string DefaultPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetzwerkScan", "devices.json");

    public List<KnownDevice> Devices { get; set; } = new();
    public List<ScannedRange> Ranges { get; set; } = new();

    /// <summary>Names given by the user, by device key. Kept for as long as the user wants them, unlike the scan history.</summary>
    public Dictionary<string, string> CustomNames { get; set; } = new();

    public static string KeyFor(string mac, uint ip) => NeighborTable.IsRealMac(mac) ? mac : "ip:" + Ipv4.ToText(ip);

    /// <summary>A name given while the MAC address was not known is still found once it is.</summary>
    public string CustomNameFor(string mac, uint ip) =>
        NeighborTable.IsRealMac(mac) && CustomNames.TryGetValue(mac, out var name)
            ? name
            : CustomNames.GetValueOrDefault(IpKey(ip), "");

    public void SetCustomName(string mac, uint ip, string name)
    {
        CustomNames.Remove(IpKey(ip));

        name = name.Trim();
        if (name.Length == 0) CustomNames.Remove(KeyFor(mac, ip));
        else CustomNames[KeyFor(mac, ip)] = name;
    }

    private static string IpKey(uint ip) => "ip:" + Ipv4.ToText(ip);

    public ScanComparison Compare(IpRangeSet range, IReadOnlyCollection<SeenDevice> seen)
    {
        var keys = Devices.Select(d => d.Key).ToHashSet();
        var ips = Devices.Select(d => d.Ip).ToHashSet();
        var seenKeys = seen.Select(s => KeyFor(s.Mac, s.Ip)).ToHashSet();
        var seenIps = seen.Select(s => s.Ip).ToHashSet();
        var seenWithoutMac = seen.Where(s => !NeighborTable.IsRealMac(s.Mac)).Select(s => s.Ip).ToHashSet();

        var newIps = new HashSet<uint>();
        foreach (var device in seen)
        {
            if (!WasScannedBefore(device.Ip)) continue; // first look at this address: nothing to compare with

            // Without a MAC the IP is all there is to go by, for a device that may be known with its MAC.
            var known = NeighborTable.IsRealMac(device.Mac)
                ? keys.Contains(device.Mac) || keys.Contains("ip:" + Ipv4.ToText(device.Ip))
                : ips.Contains(device.Ip);
            if (!known) newIps.Add(device.Ip);
        }

        var missing = Devices
            .Where(d => range.Contains(d.Ip)
                        && !seenKeys.Contains(d.Key)
                        && !(d.Key.StartsWith("ip:", StringComparison.Ordinal) && seenIps.Contains(d.Ip))
                        && !seenWithoutMac.Contains(d.Ip) // something answers there, it just can't show its MAC
                        && WasInLatestScan(d))
            .OrderBy(d => d.Ip)
            .ToList();

        var hadHistory = Ranges.Any(r => range.Ranges.Any(scanned => r.First <= scanned.Last && r.Last >= scanned.First));
        return new ScanComparison(newIps, missing, hadHistory);
    }

    /// <summary>Stores the result of a completed scan. An interrupted scan proves nothing about absent devices.</summary>
    public void Record(IpRangeSet range, IEnumerable<SeenDevice> seen, DateTime nowUtc)
    {
        var byKey = Devices.ToDictionary(d => d.Key);
        foreach (var device in seen)
        {
            var key = KeyFor(device.Mac, device.Ip);
            byKey.TryGetValue(key, out var known);
            byKey[key] = new KnownDevice(
                key,
                device.Ip,
                device.Mac,
                device.Name.Length > 0 ? device.Name : known?.Name ?? "",
                device.Vendor.Length > 0 ? device.Vendor : known?.Vendor ?? "",
                known?.FirstSeenUtc ?? nowUtc,
                nowUtc);
        }

        Devices = byKey.Values.Where(d => nowUtc - d.LastSeenUtc < ForgetAfter).OrderBy(d => d.Ip).ToList();
        // Forgotten together: a range kept without its devices would make them all look new on return.
        Ranges.RemoveAll(r => range.Ranges.Any(scanned => r.First == scanned.First && r.Last == scanned.Last) || nowUtc - r.LastScanUtc >= ForgetAfter);
        Ranges.AddRange(range.Ranges.Select(scanned => new ScannedRange(scanned.First, scanned.Last, nowUtc)));
    }

    private bool WasScannedBefore(uint ip) => Ranges.Any(r => ip >= r.First && ip <= r.Last);

    /// <summary>Otherwise a device gone for good would be reported again after every single scan.</summary>
    private bool WasInLatestScan(KnownDevice device)
    {
        var scans = Ranges.Where(r => device.Ip >= r.First && device.Ip <= r.Last).ToList();
        return scans.Count > 0 && device.LastSeenUtc >= scans.Max(r => r.LastScanUtc);
    }

    public static DeviceInventory Load()
    {
        try
        {
            return File.Exists(DefaultPath) ? Parse(File.ReadAllText(DefaultPath)) : new DeviceInventory();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return new DeviceInventory();
        }
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(DefaultPath)!);
            var temporary = DefaultPath + ".tmp";
            File.WriteAllText(temporary, ToJson());
            File.Move(temporary, DefaultPath, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // The comparison just doesn't get more history this time. No reason to bother anybody.
        }
    }

    public static DeviceInventory Parse(string json)
    {
        DeviceInventory? inventory;
        try
        {
            inventory = JsonSerializer.Deserialize<DeviceInventory>(json);
        }
        catch (JsonException)
        {
            return new DeviceInventory();
        }
        if (inventory is null) return new DeviceInventory();

        // Valid JSON can still be nonsense if the file was edited or damaged. Keep what is usable.
        inventory.Devices = (inventory.Devices ?? new())
            .Where(d => d?.Key is not null)
            .DistinctBy(d => d.Key)
            .Select(d => d with { Mac = d.Mac ?? "", Name = d.Name ?? "", Vendor = d.Vendor ?? "" })
            .ToList();
        inventory.Ranges = (inventory.Ranges ?? new()).Where(r => r is not null).ToList();
        inventory.CustomNames = (inventory.CustomNames ?? new())
            .Where(n => !string.IsNullOrWhiteSpace(n.Value))
            .ToDictionary(n => n.Key, n => n.Value.Trim());
        return inventory;
    }

    public string ToJson() => JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
}
