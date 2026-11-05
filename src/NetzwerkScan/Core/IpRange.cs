using System.Globalization;
using System.Net;

namespace NetzwerkScan.Core;

public static class Ipv4
{
    public static uint ToUInt(IPAddress address)
    {
        var b = address.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    public static IPAddress ToAddress(uint value) =>
        new(new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value });

    public static string ToText(uint value) =>
        $"{value >> 24}.{(value >> 16) & 255}.{(value >> 8) & 255}.{value & 255}";

    /// <summary>
    /// Strict dotted-quad parser. IPAddress.TryParse is too lenient here: it reads "192.168" as 192.0.0.168.
    /// </summary>
    public static bool TryParse(string text, out uint value)
    {
        value = 0;
        var parts = text.Trim().Split('.');
        if (parts.Length != 4) return false;
        foreach (var part in parts)
        {
            if (!byte.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out var octet)) return false;
            value = (value << 8) | octet;
        }
        return true;
    }
}

/// <summary>An inclusive range of IPv4 addresses.</summary>
public readonly record struct IpRange(uint First, uint Last)
{
    public const int MaxAddresses = 65536;

    public long Count => (long)Last - First + 1;

    public bool Contains(uint ip) => ip >= First && ip <= Last;

    public IEnumerable<uint> Addresses()
    {
        for (ulong a = First; a <= Last; a++) yield return (uint)a;
    }

    /// <summary>The usable host addresses of a subnet: network and broadcast address are left out.</summary>
    public static IpRange FromCidr(uint address, int prefix)
    {
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        var network = address & mask;
        var broadcast = network | ~mask;
        return prefix >= 31 ? new IpRange(network, broadcast) : new IpRange(network + 1, broadcast - 1);
    }

    /// <summary>
    /// Accepts "192.168.1.0/24", "192.168.1.10-192.168.1.50", "192.168.1.10-50" and "192.168.1.10".
    /// </summary>
    public static bool TryParse(string? text, out IpRange range, out string error)
    {
        range = default;
        error = "";
        text = text?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            error = "Bitte einen Bereich angeben, z. B. 192.168.1.0/24";
            return false;
        }

        if (text.Contains('/'))
        {
            var parts = text.Split('/');
            if (parts.Length != 2 || !Ipv4.TryParse(parts[0], out var ip)
                || !int.TryParse(parts[1].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var prefix)
                || prefix is < 0 or > 32)
            {
                error = "Ungültiges Netz. Beispiel: 192.168.1.0/24";
                return false;
            }
            range = FromCidr(ip, prefix);
        }
        else if (text.Contains('-'))
        {
            var parts = text.Split('-');
            if (parts.Length != 2 || !Ipv4.TryParse(parts[0], out var first))
            {
                error = "Ungültiger Bereich. Beispiel: 192.168.1.10-50";
                return false;
            }

            var endText = parts[1].Trim();
            if (!endText.Contains('.'))
            {
                // Short form: only the last octet of the end address is given.
                endText = parts[0].Trim()[..(parts[0].Trim().LastIndexOf('.') + 1)] + endText;
            }

            if (!Ipv4.TryParse(endText, out var last))
            {
                error = "Ungültiger Bereich. Beispiel: 192.168.1.10-50";
                return false;
            }
            if (last < first)
            {
                error = "Die Endadresse liegt vor der Startadresse.";
                return false;
            }
            range = new IpRange(first, last);
        }
        else
        {
            if (!Ipv4.TryParse(text, out var single))
            {
                error = "Ungültige Adresse. Beispiel: 192.168.1.0/24";
                return false;
            }
            range = new IpRange(single, single);
        }

        if (range.Count > MaxAddresses)
        {
            error = $"Bereich zu groß ({range.Count:N0} Adressen). Maximal {MaxAddresses:N0}, also z. B. ein /16.";
            range = default;
            return false;
        }
        return true;
    }

    public override string ToString() =>
        First == Last ? Ipv4.ToText(First) : $"{Ipv4.ToText(First)} – {Ipv4.ToText(Last)}";
}

/// <summary>One or more ranges without overlaps, so that no address is scanned or counted twice.</summary>
public sealed class IpRangeSet
{
    public IpRangeSet(IEnumerable<IpRange> ranges)
    {
        var merged = new List<IpRange>();
        foreach (var range in ranges.OrderBy(r => r.First))
        {
            // As long: the last range can end at 255.255.255.255, where adding 1 would wrap around.
            if (merged.Count > 0 && range.First <= (long)merged[^1].Last + 1)
            {
                merged[^1] = merged[^1] with { Last = Math.Max(merged[^1].Last, range.Last) };
            }
            else
            {
                merged.Add(range);
            }
        }
        Ranges = merged;
    }

    public IReadOnlyList<IpRange> Ranges { get; }

    public long Count => Ranges.Sum(r => r.Count);

    public bool Contains(uint ip) => Ranges.Any(r => r.Contains(ip));

    public IEnumerable<uint> Addresses() => Ranges.SelectMany(r => r.Addresses());

    public static implicit operator IpRangeSet(IpRange range) => new(new[] { range });

    /// <summary>Accepts what IpRange.TryParse accepts, several separated by a comma or semicolon.</summary>
    public static bool TryParse(string? text, out IpRangeSet set, out string error)
    {
        set = null!;
        var parts = (text ?? "").Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length <= 1)
        {
            if (!IpRange.TryParse(parts.FirstOrDefault(), out var single, out error)) return false;
            set = single;
            return true;
        }

        var ranges = new List<IpRange>();
        foreach (var part in parts)
        {
            if (!IpRange.TryParse(part, out var range, out error))
            {
                error = $"{part}: {error}";
                return false;
            }
            ranges.Add(range);
        }

        var result = new IpRangeSet(ranges);
        if (result.Count > IpRange.MaxAddresses)
        {
            error = $"Bereiche zusammen zu groß ({result.Count:N0} Adressen). Maximal {IpRange.MaxAddresses:N0}.";
            return false;
        }

        error = "";
        set = result;
        return true;
    }

    public override string ToString() => string.Join(", ", Ranges);
}
