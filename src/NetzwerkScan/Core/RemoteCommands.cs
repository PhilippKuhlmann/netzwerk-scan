using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;

namespace NetzwerkScan.Core;

/// <summary>
/// Starts the Windows programs for connecting to a device. Always by full path from the system folder and
/// with that as working directory: the EXE may sit in Downloads or on a share, and Windows would otherwise
/// prefer a "cmd.exe" or "ssh.exe" that somebody placed next to it.
/// </summary>
public static partial class RemoteCommands
{
    public const int SshPort = 22;
    public const int RdpPort = 3389;
    public const string DefaultSshUser = "root";

    public static bool IsValidSshUser(string user) => SshUser().IsMatch(user);

    /// <summary>What a click on port 22 logs in with. Nothing usable entered means the default.</summary>
    public static string SshUserOrDefault(string user) => IsValidSshUser(user) ? user : DefaultSshUser;

    public static string SshTarget(string ip, string user) => IsValidSshUser(user) ? $"{user}@{ip}" : ip;

    public static ProcessStartInfo Rdp(string ip)
    {
        var start = SystemProgram("mstsc.exe");
        start.ArgumentList.Add("/v:" + ip);
        return start;
    }

    public static ProcessStartInfo Ssh(string ip, string user)
    {
        // Through cmd /k, so that the window stays open with the message if the connection fails.
        var start = SystemProgram("cmd.exe");
        start.ArgumentList.Add("/k");
        start.ArgumentList.Add(Path.Combine(Environment.SystemDirectory, "OpenSSH", "ssh.exe"));
        start.ArgumentList.Add(SshTarget(ip, user));
        return start;
    }

    private static ProcessStartInfo SystemProgram(string name) =>
        new(Path.Combine(Environment.SystemDirectory, name))
        {
            UseShellExecute = false,
            WorkingDirectory = Environment.SystemDirectory,
        };

    // Goes on a command line, so nothing else. Must not start with "-", which ssh would read as an option.
    // \z rather than $, which would let a trailing line break through.
    [GeneratedRegex(@"^[A-Za-z0-9_][A-Za-z0-9._\-]*\z")]
    private static partial Regex SshUser();
}
