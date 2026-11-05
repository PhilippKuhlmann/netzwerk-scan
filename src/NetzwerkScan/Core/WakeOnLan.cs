using System.Net;
using System.Net.Sockets;

namespace NetzwerkScan.Core;

public enum WakeResult { Sent, NoNetwork, Failed }

/// <summary>
/// Sends the "magic packet" that makes a sleeping device with Wake-on-LAN enabled start up. Nothing answers
/// it, so all this can tell is that it was sent. Only the next scan shows whether the device woke up.
/// </summary>
public static class WakeOnLan
{
    public const int Port = 9;
    private const int Attempts = 3;
    private const int PauseMs = 100;

    /// <summary>Six times FF, then sixteen times the MAC address.</summary>
    public static byte[] BuildPacket(string mac)
    {
        var address = Convert.FromHexString(mac.Replace(":", ""));
        if (address.Length != 6) throw new FormatException($"Keine MAC-Adresse: {mac}");

        var packet = new byte[102];
        packet.AsSpan(0, 6).Fill(0xFF);
        for (var i = 1; i <= 16; i++) address.CopyTo(packet, i * 6);
        return packet;
    }

    /// <summary>A sleeping device has no IP address to speak of, so the packet has to go to its whole network.</summary>
    public static AdapterInfo? AdapterFor(uint ip, IEnumerable<AdapterInfo> adapters) =>
        adapters.FirstOrDefault(a => a.Subnet.Contains(ip));

    public static IEnumerable<IPAddress> Targets(AdapterInfo adapter) =>
        new[] { Ipv4.ToAddress(adapter.Subnet.Last), IPAddress.Broadcast }.Distinct();

    public static async Task<WakeResult> SendAsync(string mac, uint ip, IEnumerable<AdapterInfo> adapters)
    {
        if (AdapterFor(ip, adapters) is not { } adapter) return WakeResult.NoNetwork;

        try
        {
            var packet = BuildPacket(mac);
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { EnableBroadcast = true };
            socket.Bind(new IPEndPoint(Ipv4.ToAddress(adapter.Address), 0));

            for (var attempt = 0; attempt < Attempts; attempt++)
            {
                if (attempt > 0) await Task.Delay(PauseMs);
                foreach (var target in Targets(adapter))
                {
                    await socket.SendToAsync(packet, SocketFlags.None, new IPEndPoint(target, Port));
                }
            }
            return WakeResult.Sent;
        }
        catch (Exception e) when (e is SocketException or FormatException)
        {
            return WakeResult.Failed;
        }
    }

    public static string Describe(WakeResult result, string device) => result switch
    {
        WakeResult.Sent => $"Weckruf an {device} gesendet. Ob das Gerät aufwacht, zeigt der nächste Scan.",
        WakeResult.NoNetwork => $"{device}: Dieser PC hat keine Netzwerkkarte in diesem Netz, der Weckruf würde nicht ankommen.",
        _ => $"Weckruf an {device} konnte nicht gesendet werden.",
    };
}
