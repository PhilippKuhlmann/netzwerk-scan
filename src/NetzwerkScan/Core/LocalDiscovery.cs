using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace NetzwerkScan.Core;

/// <summary>
/// Asks the local network who is there and what they call themselves. The questions go out from a temporary
/// port, so answers come back to it directly. That needs neither administrator rights nor a firewall rule,
/// unlike listening on the well-known ports. A device that only ever answers to those ports stays unnamed.
/// </summary>
public static class LocalDiscovery
{
    private const int ListenMs = 3000;
    private const int RepeatAfterMs = 1000;
    private const int MaxReplies = 2000;
    private const int MaxDatagramBytes = 9000;
    private const int DescriptionParallelism = 8;
    private const int MaxDescriptionsPerDevice = 4;

    /// <summary>
    /// Only networks that overlap the range get asked. Another adapter on the PC can lead to a network the
    /// user has no business scanning.
    /// </summary>
    public static List<AdapterInfo> AdaptersFor(IEnumerable<AdapterInfo> adapters, IpRangeSet range) =>
        adapters.Where(a => range.Ranges.Any(r => r.First <= a.Subnet.Last && r.Last >= a.Subnet.First)).ToList();

    /// <summary>Whatever could be found out, also after Stopp. Answers from outside the range are left out.</summary>
    public static async Task<Dictionary<uint, DeviceAnnouncement>> RunAsync(IEnumerable<AdapterInfo> adapters, IpRangeSet range, CancellationToken ct)
    {
        var chosen = AdaptersFor(adapters, range);
        if (chosen.Count == 0) return new();

        var mdnsSearches = Task.WhenAll(chosen.Select(a => SearchAsync(a, Mdns.Group, Mdns.BuildServiceQuery(), range, ct)));
        var ssdpSearches = Task.WhenAll(chosen.Select(a => SearchAsync(a, Ssdp.Group, Ssdp.BuildSearch(), range, ct)));
        var mdnsReplies = (await mdnsSearches).SelectMany(r => r);
        var ssdpReplies = (await ssdpSearches).SelectMany(r => r);

        var found = new ConcurrentDictionary<uint, DeviceAnnouncement>();
        foreach (var device in mdnsReplies.GroupBy(r => r.Ip))
        {
            // A device may spread its records over several packets.
            var records = device.SelectMany(r => Mdns.Parse(r.Data)).ToList();
            if (Mdns.Announcement(records, device.Key) is { } announcement) found[device.Key] = announcement;
        }

        var devices = ssdpReplies
            .Select(r => (r.Ip, Location: Ssdp.LocationOf(r.Data)))
            .Where(r => r.Location is not null)
            .GroupBy(r => r.Ip, r => r.Location!)
            .Where(d => !found.TryGetValue(d.Key, out var known) || known.Name.Length == 0 || known.Model.Length == 0)
            .ToList();

        try
        {
            await Parallel.ForEachAsync(devices,
                new ParallelOptions { MaxDegreeOfParallelism = DescriptionParallelism, CancellationToken = ct },
                async (device, token) =>
                {
                    var locations = device.Distinct().Take(MaxDescriptionsPerDevice);
                    var description = await Ssdp.FetchDescriptionAsync(Ipv4.ToAddress(device.Key), locations, token);
                    if (description is null) return;
                    found[device.Key] = found.TryGetValue(device.Key, out var known) ? known.OrElse(description) : description;
                });
        }
        catch (OperationCanceledException)
        {
            // Stopp: what has arrived so far is still good.
        }
        return new Dictionary<uint, DeviceAnnouncement>(found);
    }

    private static async Task<List<(uint Ip, byte[] Data)>> SearchAsync(AdapterInfo adapter, IPEndPoint group, byte[] query, IpRangeSet range, CancellationToken ct)
    {
        var replies = new List<(uint Ip, byte[] Data)>();
        using var window = CancellationTokenSource.CreateLinkedTokenSource(ct);
        window.CancelAfter(ListenMs);
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            var local = Ipv4.ToAddress(adapter.Address);
            socket.Bind(new IPEndPoint(local, 0));
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, local.GetAddressBytes());
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 1);

            // Multicast over WLAN gets lost easily, hence the second attempt.
            var sending = SendTwiceAsync(socket, group, query, window.Token);
            var buffer = new byte[MaxDatagramBytes];
            while (replies.Count < MaxReplies)
            {
                try
                {
                    var reply = await socket.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), window.Token);
                    var sender = Ipv4.ToUInt(((IPEndPoint)reply.RemoteEndPoint).Address);
                    if (range.Contains(sender)) replies.Add((sender, buffer[..reply.ReceivedBytes]));
                }
                catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionReset)
                {
                    // An earlier packet was refused somewhere. That says nothing about the next answer.
                }
            }
            await sending;
        }
        catch (Exception e) when (e is SocketException or OperationCanceledException)
        {
            // The listening time is over, or this adapter can't do multicast. Either way: use what came.
        }
        return replies;
    }

    private static async Task SendTwiceAsync(Socket socket, IPEndPoint group, byte[] query, CancellationToken token)
    {
        try
        {
            await socket.SendToAsync(query, SocketFlags.None, group, token);
            await Task.Delay(RepeatAfterMs, token);
            await socket.SendToAsync(query, SocketFlags.None, group, token);
        }
        catch (Exception e) when (e is SocketException or OperationCanceledException or ObjectDisposedException)
        {
            // Answers to the first attempt may still arrive.
        }
    }
}
