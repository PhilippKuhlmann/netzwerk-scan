using System.Runtime.InteropServices;

namespace NetzwerkScan.Core;

public enum NeighborState
{
    Unreachable = 0,
    Incomplete = 1,
    Probe = 2,
    Delay = 3,
    Stale = 4,
    Reachable = 5,
    Permanent = 6,
}

public readonly record struct NeighborEntry(uint Ip, string Mac, NeighborState State, int InterfaceIndex = -1);

/// <summary>
/// Reads the Windows ARP table. A device that ignores ping still has to answer ARP, so this
/// finds hosts in the local subnet that a firewall would otherwise hide.
/// </summary>
public static class NeighborTable
{
    private const ushort AfInet = 2;

    // Layout of MIB_IPNET_TABLE2 / MIB_IPNET_ROW2 on x64.
    private const int RowsOffset = 8;
    private const int RowSize = 88;
    private const int AddressOffset = 4;
    private const int InterfaceIndexOffset = 28;
    private const int MacOffset = 40;
    private const int MacLengthOffset = 72;
    private const int StateOffset = 76;

    [DllImport("iphlpapi.dll")]
    private static extern int GetIpNetTable2(ushort family, out IntPtr table);

    [DllImport("iphlpapi.dll")]
    private static extern void FreeMibTable(IntPtr memory);

    public static List<NeighborEntry> Read()
    {
        var entries = new List<NeighborEntry>();
        if (GetIpNetTable2(AfInet, out var table) != 0) return entries;

        try
        {
            var count = Marshal.ReadInt32(table);
            for (var i = 0; i < count; i++)
            {
                var row = table + RowsOffset + i * RowSize;
                var ip = ((uint)Marshal.ReadByte(row, AddressOffset) << 24)
                         | ((uint)Marshal.ReadByte(row, AddressOffset + 1) << 16)
                         | ((uint)Marshal.ReadByte(row, AddressOffset + 2) << 8)
                         | Marshal.ReadByte(row, AddressOffset + 3);

                var length = Math.Min(Marshal.ReadInt32(row, MacLengthOffset), 32);
                var mac = new byte[length];
                Marshal.Copy(row + MacOffset, mac, 0, length);

                entries.Add(new NeighborEntry(ip, FormatMac(mac), (NeighborState)Marshal.ReadInt32(row, StateOffset),
                    Marshal.ReadInt32(row, InterfaceIndexOffset)));
            }
        }
        finally
        {
            FreeMibTable(table);
        }
        return entries;
    }

    /// <summary>
    /// Windows keeps one table row per adapter, so the same IP can appear with different MAC addresses:
    /// an old entry from another network, for example. Returns the believable MAC for each IP. The row on
    /// the adapter whose own subnet holds the IP comes first, then the most recently confirmed one.
    /// </summary>
    public static Dictionary<uint, string> BestMacs(IEnumerable<NeighborEntry> entries, IReadOnlyList<AdapterInfo> adapters)
    {
        bool OnOwnSubnet(NeighborEntry e) =>
            adapters.Any(a => a.InterfaceIndex == e.InterfaceIndex && a.Subnet.Contains(e.Ip));

        return entries
            .Where(e => e.State is not (NeighborState.Unreachable or NeighborState.Incomplete) && IsRealMac(e.Mac))
            .GroupBy(e => e.Ip)
            .ToDictionary(
                g => g.Key,
                g => g.OrderByDescending(OnOwnSubnet).ThenByDescending(e => e.State == NeighborState.Reachable).First().Mac);
    }

    public static string FormatMac(byte[] mac) => string.Join(":", mac.Select(b => b.ToString("X2")));

    public static bool IsRealMac(string mac) =>
        mac.Length == 17 && mac != "00:00:00:00:00:00" && mac != "FF:FF:FF:FF:FF:FF";
}
