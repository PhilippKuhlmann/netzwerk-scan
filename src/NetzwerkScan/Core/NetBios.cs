using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NetzwerkScan.Core;

public sealed record NetBiosInfo(string? Name, string? Workgroup);

/// <summary>NetBIOS node status query (UDP 137). Finds Windows and Samba names where no reverse DNS exists.</summary>
public static class NetBios
{
    private const int TimeoutMs = 1000;
    private const int NamesOffset = 56;

    public static async Task<NetBiosInfo?> QueryAsync(IPAddress address, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeoutMs);
        try
        {
            using var udp = new UdpClient(AddressFamily.InterNetwork);
            udp.Connect(address, 137);
            await udp.SendAsync(BuildRequest(), timeout.Token);
            var reply = await udp.ReceiveAsync(timeout.Token);
            return ParseNodeStatus(reply.Buffer);
        }
        catch (Exception e) when (e is SocketException || (e is OperationCanceledException && !ct.IsCancellationRequested))
        {
            return null;
        }
    }

    private static byte[] BuildRequest()
    {
        var packet = new byte[50];
        packet[1] = 0x42;   // Transaction id
        packet[5] = 0x01;   // One question
        packet[12] = 0x20;  // Length of the encoded name
        packet[13] = (byte)'C';  // "*" in NetBIOS first-level encoding
        packet[14] = (byte)'K';
        for (var i = 15; i < 45; i++) packet[i] = (byte)'A';
        packet[47] = 0x21;  // Type NBSTAT
        packet[49] = 0x01;  // Class IN
        return packet;
    }

    public static NetBiosInfo? ParseNodeStatus(byte[] data)
    {
        if (data.Length <= NamesOffset) return null;

        int count = data[NamesOffset];
        string? name = null, workgroup = null;

        for (var i = 0; i < count; i++)
        {
            var offset = NamesOffset + 1 + i * 18;
            if (offset + 18 > data.Length) break;

            var text = Encoding.Latin1.GetString(data, offset, 15).Trim('\0', ' ');
            var suffix = data[offset + 15];
            var isGroup = (data[offset + 16] & 0x80) != 0;

            if (suffix != 0x00 || text.Length == 0) continue;
            if (isGroup) workgroup ??= text;
            else name ??= text;
        }
        return name is null && workgroup is null ? null : new NetBiosInfo(name, workgroup);
    }
}
