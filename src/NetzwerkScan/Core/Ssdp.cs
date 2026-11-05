using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace NetzwerkScan.Core;

/// <summary>SSDP and UPnP: routers, NAS systems, TVs and media players describe themselves this way.</summary>
public static partial class Ssdp
{
    public static readonly IPEndPoint Group = new(IPAddress.Parse("239.255.255.250"), 1900);

    public static byte[] BuildSearch() => Encoding.ASCII.GetBytes(
        "M-SEARCH * HTTP/1.1\r\n" +
        "HOST: 239.255.255.250:1900\r\n" +
        "MAN: \"ssdp:discover\"\r\n" +
        "MX: 2\r\n" +
        "ST: upnp:rootdevice\r\n\r\n");

    /// <summary>Where the device keeps its description, from its answer to a search.</summary>
    public static string? LocationOf(byte[] reply)
    {
        var text = Encoding.UTF8.GetString(reply);
        if (!OkStatus().IsMatch(text)) return null;
        return Location().Match(text) is { Success: true } match ? match.Groups[1].Value.Trim() : null;
    }

    /// <summary>
    /// Reads the description without an XML parser. Devices are sloppy with XML and may send it in chunks,
    /// and so the fields are simply picked out. The first of each belongs to the device itself; those of its
    /// built-in sub-devices follow later.
    /// </summary>
    public static DeviceAnnouncement? ParseDescription(string response)
    {
        if (!OkStatus().IsMatch(response)) return null;

        var name = Field(FriendlyName(), response);
        if (DeviceNames.IsGenerated(name)) name = "";
        var model = Field(ModelName(), response);

        return name.Length == 0 && model.Length == 0 ? null : new DeviceAnnouncement(name, model);
    }

    private static string Field(Regex field, string response) =>
        field.Match(response) is { Success: true } match
            ? DeviceNames.Clean(WebUtility.HtmlDecode(match.Groups[1].Value))
            : "";

    /// <summary>
    /// One box can be several UPnP devices. A router with a media server would otherwise be listed as "Mediaserver",
    /// depending on which part happens to answer first, so the router goes before anything else, and a media server last.
    /// </summary>
    public static DeviceAnnouncement? BestDescription(IEnumerable<string> responses)
    {
        DeviceAnnouncement? best = null;
        foreach (var response in responses.OrderBy(Rank))
        {
            if (ParseDescription(response) is { } description) best = best?.OrElse(description) ?? description;
        }
        return best;
    }

    private static int Rank(string response)
    {
        var type = DeviceType().Match(response).Groups[1].Value;
        return type.Contains("InternetGatewayDevice", StringComparison.OrdinalIgnoreCase) ? 0
            : type.Contains("MediaServer", StringComparison.OrdinalIgnoreCase) ? 2
            : 1;
    }

    /// <summary>Fetches the descriptions, but only from the device that answered. See WebProbe.ResolveRedirect.</summary>
    public static async Task<DeviceAnnouncement?> FetchDescriptionAsync(IPAddress device, IEnumerable<string> locations, CancellationToken ct)
    {
        var responses = await Task.WhenAll(locations.Select(l => WebProbe.FetchFromSameDeviceAsync(device, l, ct)));
        return BestDescription(responses.OfType<string>());
    }

    [GeneratedRegex(@"<deviceType>(.*?)</deviceType>", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex DeviceType();

    [GeneratedRegex(@"\AHTTP/\d(?:\.\d)? 200\b")]
    private static partial Regex OkStatus();

    [GeneratedRegex(@"^Location:[ \t]*(.+?)\r?$", RegexOptions.Multiline | RegexOptions.IgnoreCase)]
    private static partial Regex Location();

    [GeneratedRegex(@"<friendlyName>(.*?)</friendlyName>", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex FriendlyName();

    [GeneratedRegex(@"<modelName>(.*?)</modelName>", RegexOptions.Singleline | RegexOptions.IgnoreCase)]
    private static partial Regex ModelName();
}
