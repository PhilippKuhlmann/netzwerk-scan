using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace NetzwerkScan.Core;

public enum ShareKind { Disk, Printer, Device, Ipc }

public sealed record ShareEntry(string Name, ShareKind Kind, string Remark, bool IsAdministrative);

public enum ShareStatus { Ok, NeedsLogin, Error }

public sealed record ShareResult(ShareStatus Status, IReadOnlyList<ShareEntry> Shares, string Message)
{
    public static ShareResult Failed(ShareStatus status, string message) =>
        new(status, Array.Empty<ShareEntry>(), message);
}

/// <summary>Lists Windows/Samba shares through the same API that Explorer uses.</summary>
public static class SmbShares
{
    private const int ErrorSuccess = 0;
    private const int ErrorAccessDenied = 5;
    private const int ErrorMoreData = 234;
    private const int ErrorSessionCredentialConflict = 1219;
    private const int ErrorLogonFailure = 1326;
    private const int MaxPreferredLength = -1;
    private const uint TypeMask = 0xFF;
    private const uint TypeSpecial = 0x80000000;

    private static readonly TimeSpan EnumerateTimeout = TimeSpan.FromSeconds(8);
    private static readonly char[] InvalidNameChars = { '\\', '/', ':', '*', '?', '"', '<', '>', '|' };

    // Errors that say "you may not", as opposed to "something is broken".
    private static readonly HashSet<int> LoginErrors = new()
    {
        ErrorAccessDenied, 86, ErrorLogonFailure, 1327, 1331, 1272, 1385, 1907, 1909,
    };

    private static readonly ConcurrentDictionary<string, byte> OpenConnections = new();

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ShareInfo1
    {
        public string Name;
        public uint Type;
        public string Remark;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class NetResource
    {
        public int Scope;
        public int Type;
        public int DisplayType;
        public int Usage;
        public string? LocalName;
        public string? RemoteName;
        public string? Comment;
        public string? Provider;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetShareEnum(string server, int level, out IntPtr buffer, int maxLength,
        out int entriesRead, out int totalEntries, ref int resumeHandle);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    [DllImport("mpr.dll", CharSet = CharSet.Unicode, EntryPoint = "WNetAddConnection2W")]
    private static extern int WNetAddConnection2(NetResource resource, string? password, string? user, int flags);

    [DllImport("mpr.dll", CharSet = CharSet.Unicode, EntryPoint = "WNetCancelConnection2W")]
    private static extern int WNetCancelConnection2(string name, int flags, bool force);

    /// <summary>Lists shares using the current Windows login.</summary>
    public static async Task<ShareResult> EnumerateAsync(string ip, CancellationToken ct)
    {
        try
        {
            // NetShareEnum blocks and cannot be cancelled. On timeout the worker thread is simply abandoned.
            return await Task.Run(() => Enumerate(ip), CancellationToken.None).WaitAsync(EnumerateTimeout, ct);
        }
        catch (TimeoutException)
        {
            return ShareResult.Failed(ShareStatus.Error, "Keine Antwort beim Abfragen der Freigaben.");
        }
    }

    /// <summary>
    /// Signs in with the given account and lists shares. The session stays open until the app exits,
    /// so that Explorer can use it to open the shares without asking again. Nothing is stored.
    /// </summary>
    public static Task<ShareResult> LoginAndEnumerateAsync(string ip, string user, string password) =>
        Task.Run(() =>
        {
            var ipc = $@"\\{ip}\IPC$";
            var error = WNetAddConnection2(new NetResource { RemoteName = ipc }, password, user, 0);
            if (error != ErrorSuccess)
            {
                return ShareResult.Failed(ShareStatus.NeedsLogin, error switch
                {
                    ErrorLogonFailure => "Benutzername oder Passwort ist falsch.",
                    ErrorSessionCredentialConflict =>
                        "Windows ist mit diesem Gerät bereits unter einem anderen Konto verbunden. " +
                        "Bitte die bestehende Verbindung trennen (net use) und erneut versuchen.",
                    _ => new Win32Exception(error).Message,
                });
            }
            OpenConnections[ipc] = 0;
            return Enumerate(ip);
        });

    public static void CloseConnections()
    {
        foreach (var connection in OpenConnections.Keys)
        {
            WNetCancelConnection2(connection, 0, true);
        }
        OpenConnections.Clear();
    }

    private static ShareResult Enumerate(string ip)
    {
        var resume = 0;
        var error = NetShareEnum($@"\\{ip}", 1, out var buffer, MaxPreferredLength, out var read, out _, ref resume);
        try
        {
            if (error is not (ErrorSuccess or ErrorMoreData))
            {
                return LoginErrors.Contains(error)
                    ? ShareResult.Failed(ShareStatus.NeedsLogin, "Zum Anzeigen der Freigaben ist eine Anmeldung nötig.")
                    : ShareResult.Failed(ShareStatus.Error, new Win32Exception(error).Message);
            }

            var shares = new List<ShareEntry>(read);
            var size = Marshal.SizeOf<ShareInfo1>();
            for (var i = 0; i < read; i++)
            {
                var info = Marshal.PtrToStructure<ShareInfo1>(buffer + i * size);
                var entry = ToEntry(info.Name, info.Type, info.Remark);
                if (entry is not null) shares.Add(entry);
            }
            return new ShareResult(ShareStatus.Ok, Sort(shares), "");
        }
        finally
        {
            if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
        }
    }

    public static ShareEntry? ToEntry(string? name, uint type, string? remark)
    {
        // The name comes from the remote device and is later opened through the Windows shell. Anything
        // that isn't a legal share name, such as "share\evil.exe", must never reach that point.
        if (!IsValidShareName(name)) return null;

        var kind = (type & TypeMask) switch
        {
            0 => ShareKind.Disk,
            1 => ShareKind.Printer,
            2 => ShareKind.Device,
            _ => ShareKind.Ipc,
        };
        return kind == ShareKind.Ipc ? null : new ShareEntry(name!, kind, remark ?? "", (type & TypeSpecial) != 0);
    }

    public static bool IsValidShareName(string? name) =>
        !string.IsNullOrWhiteSpace(name)
        && name.Length <= 255
        && name.IndexOfAny(InvalidNameChars) < 0
        && !name.Any(char.IsControl)
        && name.Trim('.').Length > 0;

    private static IReadOnlyList<ShareEntry> Sort(List<ShareEntry> shares) =>
        shares.OrderBy(s => s.IsAdministrative).ThenBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList();
}
