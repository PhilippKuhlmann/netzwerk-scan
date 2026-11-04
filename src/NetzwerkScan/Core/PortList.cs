using System.Globalization;

namespace NetzwerkScan.Core;

public static class PortList
{
    private static readonly char[] Separators = { ',', ';', ' ' };

    /// <summary>The individual entries of a list like "80, 443, 8000-8100".</summary>
    public static string[] Tokens(string? text) =>
        (text ?? "").Split(Separators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>Parses "80, 443, 8000-8100" into a sorted list without duplicates.</summary>
    public static bool TryParse(string? text, out int[] ports, out string error)
    {
        ports = Array.Empty<int>();
        error = "";
        var result = new SortedSet<int>();

        foreach (var raw in Tokens(text))
        {
            var bounds = raw.Split('-');
            if (bounds.Length > 2
                || !TryParsePort(bounds[0], out var from)
                || !TryParsePort(bounds[^1], out var to))
            {
                error = $"Ungültiger Port: {raw}";
                return false;
            }
            if (to < from)
            {
                error = $"Ungültiger Portbereich: {raw}";
                return false;
            }
            for (var p = from; p <= to; p++) result.Add(p);
        }

        if (result.Count == 0)
        {
            error = "Bitte mindestens einen Port angeben.";
            return false;
        }
        ports = result.ToArray();
        return true;
    }

    private static bool TryParsePort(string text, out int port) =>
        int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is >= 1 and <= 65535;
}
