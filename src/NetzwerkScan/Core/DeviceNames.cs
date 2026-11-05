using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace NetzwerkScan.Core;

/// <summary>What a device says about itself: the name its owner gave it and its model.</summary>
public sealed record DeviceAnnouncement(string Name, string Model)
{
    public DeviceAnnouncement OrElse(DeviceAnnouncement? other) => new(
        Name.Length > 0 ? Name : other?.Name ?? "",
        Model.Length > 0 ? Model : other?.Model ?? "");
}

public static partial class DeviceNames
{
    private const int MaxLength = 80;

    /// <summary>
    /// Devices can announce anything, so line breaks and invisible characters such as text direction
    /// overrides are taken out before a name reaches the list.
    /// </summary>
    public static string Clean(string? text)
    {
        if (string.IsNullOrEmpty(text)) return "";

        var visible = new StringBuilder(text.Length);
        foreach (var c in text)
        {
            var category = char.GetUnicodeCategory(c);
            if (char.IsWhiteSpace(c) || category == UnicodeCategory.Control) visible.Append(' ');
            else if (category != UnicodeCategory.Format) visible.Append(c);
        }

        var cleaned = Whitespace().Replace(visible.ToString(), " ").Trim();
        return cleaned.Length > MaxLength ? cleaned[..MaxLength].TrimEnd() + "…" : cleaned;
    }

    /// <summary>Serial numbers and IDs identify a device to software, but mean nothing to a person.</summary>
    public static bool IsGenerated(string name) => Generated().IsMatch(name);

    /// <summary>The first part of a host name. A name with spaces like "Dr. Who TV" stays whole.</summary>
    public static string Short(string name) => HostName().IsMatch(name) ? name.Split('.')[0] : name;

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();

    [GeneratedRegex(@"^(?:uuid:.*|RINCON_.*|[0-9a-f:_-]{8,}|.*[0-9a-f]{16,})$", RegexOptions.IgnoreCase)]
    private static partial Regex Generated();

    [GeneratedRegex(@"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$")]
    private static partial Regex HostName();
}
