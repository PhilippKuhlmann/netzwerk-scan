using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetzwerkScan.Core;

public sealed record AdapterInfo(string Name, string Description, uint Address, int PrefixLength, string Mac, bool HasGateway, int InterfaceIndex = -1)
{
    public IpRange Range => IpRange.FromCidr(Address, PrefixLength);

    /// <summary>The whole subnet, unlike Range also with the network and broadcast address.</summary>
    public IpRange Subnet
    {
        get
        {
            var mask = PrefixLength == 0 ? 0u : uint.MaxValue << (32 - PrefixLength);
            return new IpRange(Address & mask, (Address & mask) | ~mask);
        }
    }

    public string Cidr
    {
        get
        {
            var mask = PrefixLength == 0 ? 0u : uint.MaxValue << (32 - PrefixLength);
            return $"{Ipv4.ToText(Address & mask)}/{PrefixLength}";
        }
    }
}

public static class NetworkAdapters
{
    public static List<AdapterInfo> List()
    {
        var adapters = new List<AdapterInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up
                || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

            var properties = nic.GetIPProperties();
            var hasGateway = properties.GatewayAddresses.Any(g =>
                g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(System.Net.IPAddress.Any));

            foreach (var unicast in properties.UnicastAddresses)
            {
                if (unicast.Address.AddressFamily != AddressFamily.InterNetwork) continue;

                var address = Ipv4.ToUInt(unicast.Address);
                if (address >> 16 == 0xA9FE) continue; // 169.254.x.x: adapter has no real network

                adapters.Add(new AdapterInfo(nic.Name, nic.Description, address, unicast.PrefixLength,
                    NeighborTable.FormatMac(nic.GetPhysicalAddress().GetAddressBytes()), hasGateway,
                    properties.GetIPv4Properties()?.Index ?? -1));
            }
        }
        return adapters.OrderByDescending(a => a.HasGateway).ThenBy(a => a.Name).ToList();
    }
}
