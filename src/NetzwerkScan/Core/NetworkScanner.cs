using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetzwerkScan.Core;

public sealed record ScanOptions(IpRange Range, int[] Ports, bool FindShares, int TimeoutMs);

public abstract record ScanEvent(uint Ip);
public sealed record HostFoundEvent(uint Ip, long? PingMs, bool IsThisPc) : ScanEvent(Ip);
public sealed record HostMacEvent(uint Ip, string Mac) : ScanEvent(Ip);
public sealed record HostNameEvent(uint Ip, string? Name, string? Workgroup) : ScanEvent(Ip);
public sealed record PortOpenEvent(uint Ip, int Port) : ScanEvent(Ip);
public sealed record PortWebEvent(uint Ip, int Port, WebInfo Info) : ScanEvent(Ip);
public sealed record SharesEvent(uint Ip, ShareResult Result) : ScanEvent(Ip);
public sealed record HostFinishedEvent(uint Ip) : ScanEvent(Ip);

public enum ScanPhase { Discovery, Services }

public readonly record struct ScanProgress(ScanPhase Phase, int Checked, int Found, int Finished);

/// <summary>
/// Scans in two passes: first find out which addresses are in use, then look closer at those that are.
/// Results arrive as events, in whatever order they are discovered.
/// </summary>
public sealed class NetworkScanner
{
    private const int DiscoveryParallelism = 100;
    private const int HostParallelism = 32;
    private const int PortsPerHostParallelism = 64;
    private const int WebProbesPerHost = 8;
    private const int ConnectionLimit = 400;
    private const int ShareQueryLimit = 16;
    private const int PingTimeoutMs = 700;
    private const int NeighborSettleMs = 6000;

    // Tried only when a host doesn't answer ping. Windows firewalls usually block ping but not these.
    private static readonly int[] DiscoveryPorts = { 445, 80, 443, 22, 3389, 8006 };
    private static readonly byte[] PingPayload = new byte[32];

    private readonly SemaphoreSlim _connections = new(ConnectionLimit);
    private readonly SemaphoreSlim _shareQueries = new(ShareQueryLimit);
    private readonly ConcurrentDictionary<uint, byte> _alive = new();
    private volatile ScanPhase _phase = ScanPhase.Discovery;
    private int _checked;
    private int _finished;

    public ScanProgress Progress => new(_phase, Volatile.Read(ref _checked), _alive.Count, Volatile.Read(ref _finished));

    public async Task RunAsync(ScanOptions options, IProgress<ScanEvent> events, CancellationToken ct)
    {
        var adapters = NetworkAdapters.List();
        var localIps = adapters.Select(a => a.Address).ToHashSet();

        try
        {
            await Parallel.ForEachAsync(options.Range.Addresses(),
                new ParallelOptions { MaxDegreeOfParallelism = DiscoveryParallelism, CancellationToken = ct },
                async (ip, token) =>
                {
                    var (alive, pingMs) = await CheckAliveAsync(ip, options.TimeoutMs, token);
                    if (alive && _alive.TryAdd(ip, 0))
                    {
                        events.Report(new HostFoundEvent(ip, pingMs, localIps.Contains(ip)));
                    }
                    Interlocked.Increment(ref _checked);
                });

            await CollectFromArpTableAsync(options.Range, localIps, events, ct);
        }
        finally
        {
            // Also after Stopp: the hosts found so far stay in the list and should show their vendor.
            ReportMacAddresses(adapters, events);
        }

        _phase = ScanPhase.Services;

        var portsToScan = options.Ports;
        if (options.FindShares) portsToScan = portsToScan.Union(new[] { 139, 445 }).ToArray();

        await Parallel.ForEachAsync(_alive.Keys.OrderBy(ip => ip),
            new ParallelOptions { MaxDegreeOfParallelism = HostParallelism, CancellationToken = ct },
            async (ip, token) =>
            {
                await InspectHostAsync(ip, localIps.Contains(ip), portsToScan, options, events, token);
                Interlocked.Increment(ref _finished);
                events.Report(new HostFinishedEvent(ip));
            });
    }

    private async Task<(bool Alive, long? PingMs)> CheckAliveAsync(uint ip, int timeoutMs, CancellationToken ct)
    {
        var address = Ipv4.ToAddress(ip);

        var firstPing = await PingAsync(address, ct);
        if (firstPing is not null) return (true, firstPing);

        var secondPing = PingAsync(address, ct);
        var anyPort = AnyPortOpenAsync(address, timeoutMs, ct);
        var pingMs = await secondPing;
        var portOpen = await anyPort;
        return (pingMs is not null || portOpen, pingMs);
    }

    private static async Task<long?> PingAsync(IPAddress address, CancellationToken ct)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(address, TimeSpan.FromMilliseconds(PingTimeoutMs), PingPayload, null, ct);
            return reply.Status == IPStatus.Success ? reply.RoundtripTime : null;
        }
        catch (PingException)
        {
            return null;
        }
    }

    private async Task<bool> AnyPortOpenAsync(IPAddress address, int timeoutMs, CancellationToken ct)
    {
        var results = await Task.WhenAll(DiscoveryPorts.Select(p => IsPortOpenAsync(address, p, timeoutMs, ct)));
        return results.Any(open => open);
    }

    /// <summary>
    /// A refused connection would prove a host exists too, but firewalls often send those on behalf of
    /// addresses nobody uses. To keep the count honest, only an accepted connection counts as alive here.
    /// </summary>
    private static async Task<bool> IsPortOpenAsync(IPAddress address, int port, int timeoutMs, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(timeoutMs);
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(address, port, timeout.Token);
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return false;
        }
    }

    /// <summary>
    /// Pinging an address makes Windows send an ARP request first, so silent devices end up here too.
    /// A stale entry only proves the device existed at some point, and Windows needs a few seconds to
    /// re-verify it, so only entries confirmed as reachable count.
    /// </summary>
    private async Task CollectFromArpTableAsync(IpRange range, HashSet<uint> localIps, IProgress<ScanEvent> events, CancellationToken ct)
    {
        var deadline = Environment.TickCount64 + NeighborSettleMs;
        while (true)
        {
            var pending = false;
            foreach (var entry in NeighborTable.Read())
            {
                if (!range.Contains(entry.Ip) || _alive.ContainsKey(entry.Ip)) continue;

                if (entry.State == NeighborState.Reachable && NeighborTable.IsRealMac(entry.Mac))
                {
                    if (_alive.TryAdd(entry.Ip, 0))
                    {
                        events.Report(new HostFoundEvent(entry.Ip, null, localIps.Contains(entry.Ip)));
                    }
                }
                else if (entry.State is NeighborState.Delay or NeighborState.Probe or NeighborState.Incomplete)
                {
                    pending = true;
                }
            }

            if (!pending || Environment.TickCount64 >= deadline) return;
            await Task.Delay(500, ct);
        }
    }

    private void ReportMacAddresses(List<AdapterInfo> adapters, IProgress<ScanEvent> events)
    {
        foreach (var (ip, mac) in NeighborTable.BestMacs(NeighborTable.Read(), adapters))
        {
            if (_alive.ContainsKey(ip)) events.Report(new HostMacEvent(ip, mac));
        }

        foreach (var adapter in adapters)
        {
            if (_alive.ContainsKey(adapter.Address) && NeighborTable.IsRealMac(adapter.Mac))
            {
                events.Report(new HostMacEvent(adapter.Address, adapter.Mac));
            }
        }
    }

    private async Task InspectHostAsync(uint ip, bool isThisPc, int[] ports, ScanOptions options, IProgress<ScanEvent> events, CancellationToken ct)
    {
        var address = Ipv4.ToAddress(ip);

        var names = ResolveNameAsync(ip, address, isThisPc, events, ct);
        var open = await ScanPortsAsync(ip, address, ports, options.TimeoutMs, events, ct);
        await names;

        await Parallel.ForEachAsync(open.Where(ServiceCatalog.MayProbeWeb),
            new ParallelOptions { MaxDegreeOfParallelism = WebProbesPerHost, CancellationToken = ct },
            async (port, token) =>
            {
                var info = await WebProbe.ProbeAsync(address, port, token);
                if (info is null && ServiceCatalog.DefaultWebScheme(port) is { } scheme)
                {
                    info = new WebInfo(scheme, null, null);
                }
                if (info is not null) events.Report(new PortWebEvent(ip, port, info));
            });

        if (options.FindShares && (open.Contains(445) || open.Contains(139)))
        {
            await _shareQueries.WaitAsync(ct);
            try
            {
                events.Report(new SharesEvent(ip, await SmbShares.EnumerateAsync(Ipv4.ToText(ip), ct)));
            }
            finally
            {
                _shareQueries.Release();
            }
        }
    }

    private async Task<List<int>> ScanPortsAsync(uint ip, IPAddress address, int[] ports, int timeoutMs, IProgress<ScanEvent> events, CancellationToken ct)
    {
        var open = new ConcurrentBag<int>();
        await Parallel.ForEachAsync(ports,
            new ParallelOptions { MaxDegreeOfParallelism = PortsPerHostParallelism, CancellationToken = ct },
            async (port, token) =>
            {
                await _connections.WaitAsync(token);
                try
                {
                    if (await IsPortOpenAsync(address, port, timeoutMs, token))
                    {
                        open.Add(port);
                        events.Report(new PortOpenEvent(ip, port));
                    }
                }
                finally
                {
                    _connections.Release();
                }
            });
        return open.ToList();
    }

    private static async Task ResolveNameAsync(uint ip, IPAddress address, bool isThisPc, IProgress<ScanEvent> events, CancellationToken ct)
    {
        var dnsName = ReverseDnsAsync(address, ct);
        var netBios = NetBios.QueryAsync(address, ct);

        var name = await dnsName;
        var info = await netBios;

        name ??= info?.Name;
        if (isThisPc) name ??= Environment.MachineName;

        if (name is not null || info?.Workgroup is not null)
        {
            events.Report(new HostNameEvent(ip, name, info?.Workgroup));
        }
    }

    private static async Task<string?> ReverseDnsAsync(IPAddress address, CancellationToken ct)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(address).WaitAsync(TimeSpan.FromSeconds(2), ct);
            return string.IsNullOrEmpty(entry.HostName) || entry.HostName == address.ToString() ? null : entry.HostName;
        }
        catch (Exception e) when (e is SocketException or TimeoutException)
        {
            return null;
        }
    }
}
