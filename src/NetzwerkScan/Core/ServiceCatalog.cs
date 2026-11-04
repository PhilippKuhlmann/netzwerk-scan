namespace NetzwerkScan.Core;

/// <summary>What is commonly found behind a TCP port.</summary>
public static class ServiceCatalog
{
    /// <summary>
    /// Used when a port is open but the probe gave no answer, for example with legacy TLS that Windows
    /// refuses to negotiate. The browser may still get through, so these stay clickable.
    /// </summary>
    private static readonly Dictionary<int, string> WebDefaults = new()
    {
        [80] = "http", [81] = "http", [443] = "https", [4443] = "https", [5000] = "http", [5001] = "https",
        [7080] = "http", [7443] = "https", [8000] = "http", [8006] = "https", [8007] = "https", [8080] = "http",
        [8081] = "http", [8088] = "http", [8096] = "http", [8123] = "http", [8443] = "https", [8888] = "http",
        [8920] = "https", [9443] = "https", [10000] = "https", [32400] = "http",
    };

    /// <summary>
    /// Ports that must not receive an HTTP request or TLS handshake. Raw print ports put everything they
    /// receive on paper, and industrial controllers can react badly to unexpected bytes. The rest speak
    /// protocols known not to be HTTP, so probing them would only add noise to their logs.
    /// </summary>
    private static readonly HashSet<int> NeverProbe = new()
    {
        // Printers: 9100-9103 raw (JetDirect), 515 LPD
        515, 9100, 9101, 9102, 9103,
        // Industrial control: S7, Modbus, DNP3, EtherNet/IP, BACnet, OPC UA, IEC 104, Niagara Fox
        102, 502, 1911, 2404, 4840, 20000, 44818, 47808,
        // Known non-HTTP services
        21, 22, 23, 25, 53, 88, 110, 111, 135, 137, 138, 139, 143, 389, 445, 465, 514, 548, 587, 636, 873,
        993, 995, 1433, 1521, 1723, 1883, 2049, 3268, 3269, 3306, 3389, 5060, 5061, 5432, 5900, 5901, 5902,
        5903, 5985, 5986, 6379, 8883, 11211, 27017,
    };

    public static string Name(int port) => PortCatalog.Find(port)?.Name ?? "";

    public static string? DefaultWebScheme(int port) => WebDefaults.GetValueOrDefault(port);

    public static bool MayProbeWeb(int port) => !NeverProbe.Contains(port);
}
