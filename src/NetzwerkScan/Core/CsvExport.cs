using System.Text;

namespace NetzwerkScan.Core;

public sealed record CsvRow(string Status, string Ip, string Name, string Mac, string Vendor, string Ping, string Ports, string WebAddresses, string Shares);

/// <summary>Writes scan results so that a German Excel opens them directly: semicolons, UTF-8 with BOM.</summary>
public static class CsvExport
{
    private static readonly string[] Header =
    {
        "Status", "IP-Adresse", "Name", "MAC-Adresse", "Hersteller", "Ping", "Offene Ports", "Weboberflächen", "Freigaben",
    };

    public static readonly Encoding FileEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: true);

    public static string Build(IEnumerable<CsvRow> rows)
    {
        var text = new StringBuilder();
        AppendLine(text, Header);
        foreach (var r in rows)
        {
            AppendLine(text, new[] { r.Status, r.Ip, r.Name, r.Mac, r.Vendor, r.Ping, r.Ports, r.WebAddresses, r.Shares });
        }
        return text.ToString();
    }

    private static void AppendLine(StringBuilder text, IEnumerable<string> cells) =>
        text.Append(string.Join(';', cells.Select(Cell))).Append("\r\n");

    /// <summary>
    /// Names and page titles come from the devices on the network, so they can't be trusted. Excel would
    /// run a cell starting with "=" as a formula, hence the leading apostrophe, which makes it plain text.
    /// </summary>
    public static string Cell(string value)
    {
        var text = value.ReplaceLineEndings(" ");
        if (text.Length > 0 && "=+-@\t\r".Contains(text[0])) text = "'" + text;
        return "\"" + text.Replace("\"", "\"\"") + "\"";
    }
}
