using System.Diagnostics;
using System.Text.RegularExpressions;

namespace NetzwerkScan.Core;

/// <summary>Starts the Windows programs for connecting to a device.</summary>
public static partial class RemoteCommands
{
    public const int SshPort = 22;
    public const int RdpPort = 3389;

    public static bool IsValidSshUser(string user) => SshUser().IsMatch(user);

    public static string SshTarget(string ip, string user) => IsValidSshUser(user) ? $"{user}@{ip}" : ip;

    public static ProcessStartInfo Rdp(string ip)
    {
        var start = new ProcessStartInfo("mstsc.exe") { UseShellExecute = false };
        start.ArgumentList.Add("/v:" + ip);
        return start;
    }

    public static ProcessStartInfo Ssh(string ip, string user)
    {
        // Through cmd /k, so that the window stays open with the message if the connection fails.
        var start = new ProcessStartInfo("cmd.exe") { UseShellExecute = false };
        start.ArgumentList.Add("/k");
        start.ArgumentList.Add("ssh");
        start.ArgumentList.Add(SshTarget(ip, user));
        return start;
    }

    // Goes on a command line, so nothing else. Must not start with "-", which ssh would read as an option.
    [GeneratedRegex(@"^[A-Za-z0-9_][A-Za-z0-9._\-]*$")]
    private static partial Regex SshUser();
}
