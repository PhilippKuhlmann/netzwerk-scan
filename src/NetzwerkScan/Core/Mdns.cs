using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NetzwerkScan.Core;

public sealed record MdnsRecord(string[] Owner, ushort Type, string[] Target, uint Address, IReadOnlyList<string> Text);

/// <summary>
/// Multicast DNS, also known as Bonjour. Printers, Apple devices, Chromecasts and much of the smart home
/// announce their names this way, even where neither DNS nor NetBIOS knows them.
/// </summary>
public static class Mdns
{
    public const int Port = 5353;
    public static readonly IPEndPoint Group = new(IPAddress.Parse("224.0.0.251"), Port);

    public const ushort TypeA = 1;
    public const ushort TypePtr = 12;
    public const ushort TypeTxt = 16;
    public const ushort TypeSrv = 33;

    private const int HeaderLength = 12;
    private const int MaxNameLength = 255;
    private const int ReverseTimeoutMs = 800;

    /// <summary>Where a device has several, the first one in this list provides its name.</summary>
    private static readonly string[] NamingServices =
    {
        "_airplay", "_raop", "_companion-link", "_hap", "_googlecast", "_ipp", "_ipps", "_printer", "_pdl-datastream",
        "_uscan", "_scanner", "_smb", "_afpovertcp", "_esphomelib", "_home-assistant", "_shelly", "_hue", "_sonos",
        "_spotify-connect", "_axis-video", "_workstation", "_ssh", "_sftp-ssh", "_nut", "_mqtt", "_http", "_https", "_rfb",
    };

    /// <summary>Only here "fn" and "md" mean name and model. In AirPlay for example, md=0,1,2 lists metadata types.</summary>
    private static readonly string[] ServicesWithFriendlyKeys = { "_googlecast", "_hap" };

    private static readonly string[] ModelKeys = { "model", "am", "ty", "usb_MDL", "product" };

    public static byte[] BuildServiceQuery() =>
        BuildQuery(NamingServices.Select(s => new[] { s, "_tcp", "local" }).ToList(), TypePtr);

    public static byte[] BuildReverseQuery(uint ip) => BuildQuery(new[] { ReverseName(ip) }, TypePtr);

    private static string[] ReverseName(uint ip) => new[]
    {
        (ip & 255).ToString(), ((ip >> 8) & 255).ToString(), ((ip >> 16) & 255).ToString(), (ip >> 24).ToString(), "in-addr", "arpa",
    };

    private static byte[] BuildQuery(IReadOnlyCollection<string[]> names, ushort type)
    {
        using var packet = new MemoryStream();
        packet.Write(new byte[] { 0, 0, 0, 0, (byte)(names.Count >> 8), (byte)names.Count, 0, 0, 0, 0, 0, 0 });
        foreach (var name in names)
        {
            foreach (var label in name)
            {
                var bytes = Encoding.UTF8.GetBytes(label);
                packet.WriteByte((byte)bytes.Length);
                packet.Write(bytes);
            }
            packet.Write(new byte[] { 0, (byte)(type >> 8), (byte)type, 0, 1 });
        }
        return packet.ToArray();
    }

    /// <summary>
    /// Reads the records of a response. The data comes straight from the network, so nothing in it is
    /// trusted. Whatever follows a damaged record is dropped, and an unusable packet just has no records.
    /// </summary>
    public static List<MdnsRecord> Parse(byte[] data)
    {
        var records = new List<MdnsRecord>();
        if (data.Length < HeaderLength || (data[2] & 0x80) == 0) return records;

        var offset = HeaderLength;
        for (var i = ReadUInt16(data, 4); i > 0; i--)
        {
            if (!TryReadName(data, ref offset, out _) || offset + 4 > data.Length) return records;
            offset += 4;
        }

        var count = ReadUInt16(data, 6) + ReadUInt16(data, 8) + ReadUInt16(data, 10);
        for (var i = 0; i < count; i++)
        {
            if (!TryReadName(data, ref offset, out var owner) || offset + 10 > data.Length) return records;

            var type = (ushort)ReadUInt16(data, offset);
            var length = ReadUInt16(data, offset + 8);
            var start = offset + 10;
            if (start + length > data.Length) return records;

            if (ReadPayload(data, start, length, type, owner) is { } record) records.Add(record);
            offset = start + length;
        }
        return records;
    }

    private static MdnsRecord? ReadPayload(byte[] data, int start, int length, ushort type, string[] owner)
    {
        var position = start;
        switch (type)
        {
            case TypeA when length == 4:
                var address = ((uint)data[start] << 24) | ((uint)data[start + 1] << 16) | ((uint)data[start + 2] << 8) | data[start + 3];
                return new MdnsRecord(owner, type, Array.Empty<string>(), address, Array.Empty<string>());

            case TypePtr when TryReadName(data, ref position, out var pointer) && position <= start + length:
                return new MdnsRecord(owner, type, pointer, 0, Array.Empty<string>());

            case TypeSrv when length > 6:
                position = start + 6; // priority, weight and port
                return TryReadName(data, ref position, out var host) && position <= start + length
                    ? new MdnsRecord(owner, type, host, 0, Array.Empty<string>())
                    : null;

            case TypeTxt:
                var text = new List<string>();
                while (position < start + length)
                {
                    int size = data[position++];
                    if (position + size > start + length) break;
                    text.Add(Encoding.UTF8.GetString(data, position, size));
                    position += size;
                }
                return new MdnsRecord(owner, type, Array.Empty<string>(), 0, text);

            default:
                return null;
        }
    }

    /// <summary>A pointer may only lead further back than the last one, so that a crafted packet can't send this in circles.</summary>
    private static bool TryReadName(byte[] data, ref int offset, out string[] name)
    {
        var labels = new List<string>();
        name = Array.Empty<string>();
        var position = offset;
        var lowest = offset;
        var jumped = false;
        var total = 0;

        while (true)
        {
            if (position >= data.Length) return false;
            int length = data[position];

            if (length == 0)
            {
                if (!jumped) offset = position + 1;
                name = labels.ToArray();
                return true;
            }

            if ((length & 0xC0) == 0xC0)
            {
                if (position + 1 >= data.Length) return false;
                var target = ((length & 0x3F) << 8) | data[position + 1];
                if (target >= lowest) return false;
                if (!jumped) offset = position + 2;
                jumped = true;
                lowest = target;
                position = target;
                continue;
            }

            if ((length & 0xC0) != 0 || position + 1 + length > data.Length) return false;
            total += length + 1;
            if (total > MaxNameLength) return false;
            labels.Add(Encoding.UTF8.GetString(data, position + 1, length));
            position += length + 1;
        }
    }

    private static int ReadUInt16(byte[] data, int offset) => (data[offset] << 8) | data[offset + 1];

    /// <summary>
    /// The name and model in the records from one device. Routers that pass mDNS on between networks answer
    /// with the services of other devices, so a service only counts if it leads to a host name with the
    /// address of the sender: a device can speak for itself, not for others.
    /// </summary>
    public static DeviceAnnouncement? Announcement(IReadOnlyCollection<MdnsRecord> records, uint sender)
    {
        var hosts = records.Where(r => r.Type == TypeA && r.Address == sender).Select(r => r.Owner).ToList();
        if (hosts.Count == 0) return null;

        var hostKeys = hosts.Select(Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var instances = records
            .Where(r => r.Type == TypeSrv && IsInstanceName(r.Owner) && hostKeys.Contains(Key(r.Target)))
            .Select(r => Key(r.Owner))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var text = records.Where(r => r.Type == TypeTxt && instances.Contains(Key(r.Owner))).ToList();
        var friendly = Values(text.Where(r => ServicesWithFriendlyKeys.Contains(r.Owner[1], StringComparer.OrdinalIgnoreCase)));
        var general = Values(text);

        var name = DeviceNames.Clean(friendly["fn"].FirstOrDefault());
        if (name.Length == 0) name = InstanceName(records, instances);
        if (name.Length == 0) name = LocalHostName(hosts[0]);

        var model = friendly["md"].Concat(ModelKeys.SelectMany(key => general[key]))
            .Select(value => DeviceNames.Clean(value.Trim('(', ')', ' ')))
            .FirstOrDefault(value => value.Length > 0) ?? "";

        return name.Length == 0 && model.Length == 0 ? null : new DeviceAnnouncement(name, model);
    }

    private static ILookup<string, string> Values(IEnumerable<MdnsRecord> text) => text
        .SelectMany(r => r.Text)
        .Select(t => t.Split('=', 2))
        .Where(t => t.Length == 2)
        .ToLookup(t => t[0], t => t[1], StringComparer.OrdinalIgnoreCase);

    /// <summary>A label may contain a dot, so joining them with one could make two different names look the same.</summary>
    private static string Key(string[] name) => string.Join('\u0001', name);

    private static bool IsInstanceName(string[] name) =>
        name.Length >= 4 && name[1].StartsWith('_') && name[2] is "_tcp" or "_udp";

    private static string InstanceName(IReadOnlyCollection<MdnsRecord> records, HashSet<string> ownInstances)
    {
        var instances = records
            .Where(r => r.Type == TypePtr && r.Owner.Length >= 3 && r.Target.Length == r.Owner.Length + 1
                        && r.Target.Skip(1).SequenceEqual(r.Owner, StringComparer.OrdinalIgnoreCase)
                        && ownInstances.Contains(Key(r.Target)))
            .ToLookup(r => r.Owner[0], r => r.Target[0], StringComparer.OrdinalIgnoreCase);

        foreach (var service in NamingServices)
        {
            foreach (var instance in instances[service])
            {
                var name = DeviceNames.Clean(WithoutTechnicalParts(instance));
                if (name.Length > 0 && !DeviceNames.IsGenerated(name)) return name;
            }
        }
        return "";
    }

    /// <summary>AirPlay puts a hardware address in front of the name, Linux workstations one behind it.</summary>
    private static string WithoutTechnicalParts(string instance)
    {
        var at = instance.IndexOf('@');
        if (at > 0) instance = instance[(at + 1)..];

        var bracket = instance.LastIndexOf(" [", StringComparison.Ordinal);
        return bracket > 0 && instance.EndsWith(']') ? instance[..bracket] : instance;
    }

    private static string LocalHostName(string[] name)
    {
        var parts = name.Length > 1 && name[^1].Equals("local", StringComparison.OrdinalIgnoreCase) ? name[..^1] : name;
        return DeviceNames.Clean(string.Join('.', parts));
    }

    /// <summary>The answer to a reverse lookup: only a name given for exactly this address counts.</summary>
    public static string? ReverseAnswer(IEnumerable<MdnsRecord> records, uint ip)
    {
        var question = ReverseName(ip);
        var answer = records.FirstOrDefault(r => r.Type == TypePtr && r.Target.Length > 0
                                                 && r.Owner.SequenceEqual(question, StringComparer.OrdinalIgnoreCase));
        return answer is null || LocalHostName(answer.Target) is not { Length: > 0 } name ? null : name;
    }

    /// <summary>Asks the device directly for its name. This finds names on devices that offer none of the known services.</summary>
    public static async Task<string?> ReverseLookupAsync(IPAddress address, CancellationToken ct, int port = Port)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(ReverseTimeoutMs);
        try
        {
            var ip = Ipv4.ToUInt(address);
            using var udp = new UdpClient(AddressFamily.InterNetwork);
            udp.Connect(address, port);
            await udp.SendAsync(BuildReverseQuery(ip), timeout.Token);
            var reply = await udp.ReceiveAsync(timeout.Token);
            return ReverseAnswer(Parse(reply.Buffer), ip);
        }
        catch (Exception e) when (e is SocketException || (e is OperationCanceledException && !ct.IsCancellationRequested))
        {
            return null;
        }
    }
}
