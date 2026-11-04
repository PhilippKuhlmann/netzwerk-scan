using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace NetzwerkScan.Core;

/// <summary>
/// Finds the manufacturer of a network card from its MAC address, using the IEEE registries
/// embedded in the app. tools\update-oui.ps1 refreshes the list.
/// </summary>
public static partial class MacVendors
{
    private const string ResourceName = "oui.txt.gz";
    private const string RandomMacLabel = "Zufällige MAC";
    private const int MaxStrippedLegalForms = 4;

    // Prefix lengths in hex digits: MA-S, MA-M, MA-L. The longest match is the most specific one.
    private static readonly int[] PrefixLengths = { 9, 7, 6 };

    // Virtual machines. The registry alone would be misleading or empty for these: QEMU's prefix isn't
    // registered at all, and "PCS Systemtechnik" tells nobody that this is a VirtualBox guest.
    private static readonly Dictionary<string, string> VirtualMachines = new()
    {
        ["BC2411"] = "Proxmox VM",
        ["525400"] = "QEMU/KVM",
        ["00155D"] = "Hyper-V",
        ["080027"] = "VirtualBox",
    };

    private static readonly Lazy<Dictionary<string, string>> Registry = new(LoadEmbeddedRegistry);

    /// <summary>Loads the list ahead of time, so that the first lookup doesn't cost time on the UI thread.</summary>
    public static void Preload() => _ = Registry.Value;

    public static int RegistrySize => Registry.Value.Count;

    public static string Lookup(string mac)
    {
        var hex = mac.Replace(":", "").Replace("-", "").ToUpperInvariant();
        if (hex.Length != 12 || !hex.All(Uri.IsHexDigit)) return "";

        if (VirtualMachines.TryGetValue(hex[..6], out var machine)) return machine;

        foreach (var length in PrefixLengths)
        {
            if (Registry.Value.TryGetValue(hex[..length], out var vendor)) return vendor;
        }

        // Phones and laptops often use a random address, recognisable by the "locally administered" bit.
        return (Convert.ToByte(hex[..2], 16) & 0x02) != 0 ? RandomMacLabel : "";
    }

    /// <summary>The vendor name without legal form: "Samsung Electronics Co.,Ltd" becomes "Samsung Electronics".</summary>
    public static string ShortName(string vendor)
    {
        if (vendor.StartsWith("AVM Audiovisuelles", StringComparison.OrdinalIgnoreCase)) return "AVM";

        var name = ParentCompany().Replace(vendor, "");
        for (var i = 0; i < MaxStrippedLegalForms; i++)
        {
            var shorter = LegalForm().Replace(name, "");
            if (shorter.Length < 2 || shorter == name) break;
            name = shorter;
        }

        // Leftovers like "SBS TECHNOLOGIES," or the "-" of "CBL - GMBH".
        var trimmed = name.TrimEnd(' ', ',', ';', '-');
        return trimmed.Length >= 2 ? trimmed : name;
    }

    /// <summary>Reads the list format written by tools\update-oui.ps1. Lines that don't fit are skipped.</summary>
    public static Dictionary<string, string> ParseRegistry(TextReader reader)
    {
        var registry = new Dictionary<string, string>(60000, StringComparer.Ordinal);
        while (reader.ReadLine() is { } line)
        {
            var tab = line.IndexOf('\t');
            if (tab is 6 or 7 or 9 && tab < line.Length - 1) registry[line[..tab]] = line[(tab + 1)..];
        }
        return registry;
    }

    private static Dictionary<string, string> LoadEmbeddedRegistry()
    {
        using var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException($"Eingebettete Datei {ResourceName} fehlt.");
        using var gzip = new GZipStream(resource, CompressionMode.Decompress);
        using var reader = new StreamReader(gzip, Encoding.UTF8);
        return ParseRegistry(reader);
    }

    // A legal form at the end of the name, with the punctuation around it, and a connector if one comes
    // first ("AG & Co. KG"). The connector only goes along with a legal form, so "Canal +" stays whole.
    // It may follow a closing bracket without a gap: "Wistron InfoComm(Kunshan)Co.,Ltd."
    // The lookbehind protects dotted initials: "U.S.A." must not end up as "U" by way of "S.A."
    [GeneratedRegex(
        @"(?:[\s,.，;]+(?:&|\+|und|and|u\.?))?(?:[\s,.，;]+|(?<=[)）]))(?<!\b\p{L}\.)" +
        @"((?:pvt|private)[\s,.]+(?:ltd|limited)|\(p(?:vt)?\)\s*(?:ltd|limited)|gmbh\s*&\s*co\.?\s*kg|gmbh|mbh|kg|ag|se|inc|incorporated|ltd|limited|llc|l\.l\.c|corp|corporation|co|company|s\.?a\.?s|s\.?a|s\.?r\.?l|s\.?l|b\.?v|n\.?v|a/?s|ab|oy|plc|pte|pty|k\.?k)" +
        @"[\s,.，;]*$",
        RegexOptions.IgnoreCase)]
    private static partial Regex LegalForm();

    // "Motorola Mobility LLC, a Lenovo Company"
    [GeneratedRegex(@",\s*an?\s+.*\b(?:company|corporation)\W*$", RegexOptions.IgnoreCase)]
    private static partial Regex ParentCompany();
}
