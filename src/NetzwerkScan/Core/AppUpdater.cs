using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NetzwerkScan.Core;

public sealed record UpdateInfo(Version Version, string ExeUrl, string ChecksumUrl);

public sealed class UpdateException : Exception
{
    public UpdateException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>
/// Installs new versions from the GitHub releases of this repository. What protects this is HTTPS and
/// the fixed repository: whoever controls the GitHub account decides what every client runs next. The
/// checksum comes from the same release, so it catches damaged downloads, not a manipulated release.
/// </summary>
public static partial class AppUpdater
{
    public const string Repository = "PhilippKuhlmann/netzwerk-scan";

    private const string ExeAssetName = "NetzwerkScan.exe";
    private const string ChecksumAssetName = "NetzwerkScan.exe.sha256";
    private const string AllowedDownloadPrefix = $"https://github.com/{Repository}/releases/download/";
    private const string LatestReleaseUrl = $"https://api.github.com/repos/{Repository}/releases/latest";

    private static readonly TimeSpan CheckTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan StallTimeout = TimeSpan.FromSeconds(30);

    private static readonly HttpClient Http = new() { Timeout = Timeout.InfiniteTimeSpan };

    public static Version CurrentVersion
    {
        get
        {
            var version = Assembly.GetExecutingAssembly().GetName().Version ?? new Version(0, 0, 0);
            return new Version(version.Major, version.Minor, version.Build);
        }
    }

    /// <summary>
    /// The file to replace. Null when not running as the published single EXE: a development build
    /// must not overwrite itself with a release.
    /// </summary>
    public static string? InstallPath
    {
#pragma warning disable IL3000 // Being empty in a single-file app is exactly what this looks for.
        get => Assembly.GetExecutingAssembly().Location.Length == 0 ? Environment.ProcessPath : null;
#pragma warning restore IL3000
    }

    /// <summary>Asks GitHub for a newer version. Any problem, such as being offline, simply means no update.</summary>
    public static async Task<UpdateInfo?> CheckAsync()
    {
        using var timeout = new CancellationTokenSource(CheckTimeout);
        try
        {
            using var request = NewRequest(LatestReleaseUrl);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
            using var response = await Http.SendAsync(request, timeout.Token);
            if (!response.IsSuccessStatusCode) return null;

            return ParseRelease(await response.Content.ReadAsStringAsync(timeout.Token), CurrentVersion);
        }
        catch (Exception e) when (e is HttpRequestException or OperationCanceledException)
        {
            return null;
        }
    }

    public static UpdateInfo? ParseRelease(string json, Version current)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;

            var tag = root.GetProperty("tag_name").GetString() ?? "";
            var match = ReleaseTag().Match(tag);
            if (!match.Success || !Version.TryParse(match.Groups[1].Value, out var version) || version <= current) return null;

            string? exe = null, checksum = null;
            foreach (var asset in root.GetProperty("assets").EnumerateArray())
            {
                var name = asset.GetProperty("name").GetString();
                var url = asset.GetProperty("browser_download_url").GetString();
                if (url is null || !url.StartsWith(AllowedDownloadPrefix, StringComparison.Ordinal)) continue;

                if (name == ExeAssetName) exe = url;
                else if (name == ChecksumAssetName) checksum = url;
            }
            return exe is null || checksum is null ? null : new UpdateInfo(version, exe, checksum);
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or KeyNotFoundException)
        {
            return null;
        }
    }

    /// <summary>Reads the format of sha256sum: the hash in hex, optionally followed by the file name.</summary>
    public static string? ParseChecksum(string text)
    {
        var first = text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return first is not null && Sha256Hex().IsMatch(first) ? first.ToLowerInvariant() : null;
    }

    /// <summary>Downloads and checks the new version and puts it in place. The app must restart to use it.</summary>
    public static async Task InstallAsync(UpdateInfo update, IProgress<double>? progress, CancellationToken ct)
    {
        var exe = InstallPath ?? throw new UpdateException("Diese Version kann sich nicht selbst aktualisieren.");
        var newFile = exe + ".new";
        var oldFile = exe + ".old";

        try
        {
            using var checksumRequest = NewRequest(update.ChecksumUrl);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(StallTimeout);
            using var checksumResponse = await Http.SendAsync(checksumRequest, timeout.Token);
            checksumResponse.EnsureSuccessStatusCode();
            var expected = ParseChecksum(await checksumResponse.Content.ReadAsStringAsync(timeout.Token))
                           ?? throw new UpdateException("Die Prüfsumme des Updates ist ungültig.");

            var actual = await DownloadAsync(update.ExeUrl, newFile, progress, ct);
            if (actual != expected) throw new UpdateException("Die Prüfsumme des Updates stimmt nicht.");

            // A release whose EXE reports another version would be installed again on every start.
            if (ReadFileVersion(newFile) != update.Version)
            {
                throw new UpdateException("Die heruntergeladene Datei hat nicht die erwartete Version.");
            }

            // "Überspringen" may have come in during the last step. From here on it is too late for that.
            ct.ThrowIfCancellationRequested();
            ReplaceFile(exe, newFile, oldFile);
        }
        catch (Exception e) when (e is HttpRequestException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            TryDelete(newFile);
            throw new UpdateException($"Update fehlgeschlagen: {e.Message}", e);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            TryDelete(newFile);
            throw new UpdateException("Das Update konnte nicht geladen werden: Zeitüberschreitung.");
        }
        catch
        {
            TryDelete(newFile);
            throw;
        }
    }

    /// <summary>
    /// Swaps the files in one step, keeping the running EXE as backup. Two separate moves could end with no
    /// EXE at all, for example if a virus scanner blocks the second one and then the way back.
    /// </summary>
    public static void ReplaceFile(string exe, string newFile, string oldFile)
    {
        ClearReadOnly(exe);
        ClearReadOnly(oldFile);
        File.Replace(newFile, exe, oldFile, ignoreMetadataErrors: true);
    }

    /// <summary>Starts the new version. If that fails, for example because a virus scanner took it, the old one goes back.</summary>
    public static void RestartOrRollBack()
    {
        var exe = InstallPath!;
        try
        {
            Process.Start(new ProcessStartInfo(exe) { UseShellExecute = false });
        }
        catch (Exception e) when (e is Win32Exception or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            try
            {
                File.Move(exe + ".old", exe, overwrite: true);
            }
            catch (Exception restore) when (restore is IOException or UnauthorizedAccessException)
            {
                throw new UpdateException($"Die neue Version startet nicht, und die alte konnte nicht zurückkommen. Sie liegt als {exe}.old daneben.", restore);
            }
            throw new UpdateException("Die neue Version konnte nicht gestartet werden. Die bisherige bleibt installiert.", e);
        }
    }

    /// <summary>Says why installing here won't work, if it won't. Checked first, to save the download.</summary>
    public static string? FindInstallObstacle()
    {
        if (InstallPath is not { } exe) return "Diese Version kann sich nicht selbst aktualisieren.";

        try
        {
            using (File.Create(exe + ".new")) { }
            File.Delete(exe + ".new");
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return "Der Ordner der Anwendung ist schreibgeschützt.";
        }

        // A running copy loads parts of itself from the EXE on demand and would break after the swap.
        return IsAnotherInstanceRunning(exe) ? "Die Anwendung läuft noch in einem anderen Fenster." : null;
    }

    private static bool IsAnotherInstanceRunning(string exe)
    {
        foreach (var process in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(exe)))
        {
            using (process)
            {
                if (process.Id == Environment.ProcessId) continue;
                try
                {
                    if (string.Equals(process.MainModule?.FileName, exe, StringComparison.OrdinalIgnoreCase)) return true;
                }
                catch (Exception e) when (e is Win32Exception or InvalidOperationException)
                {
                    // Exited in the meantime, or belongs to another user and so isn't running from here for us.
                }
            }
        }
        return false;
    }

    /// <summary>Removes what the previous version left behind. It may still be shutting down for a moment.</summary>
    public static async Task CleanUpAsync()
    {
        if (InstallPath is not { } exe) return;
        TryDelete(exe + ".new");

        var old = exe + ".old";
        for (var attempt = 0; attempt < 20 && File.Exists(old); attempt++)
        {
            TryDelete(old);
            if (File.Exists(old)) await Task.Delay(500);
        }
    }

    public static Version? ReadFileVersion(string path)
    {
        var text = FileVersionInfo.GetVersionInfo(path).FileVersion;
        return Version.TryParse(text, out var v) ? new Version(v.Major, v.Minor, Math.Max(v.Build, 0)) : null;
    }

    private static async Task<string> DownloadAsync(string url, string path, IProgress<double>? progress, CancellationToken ct)
    {
        using var stall = CancellationTokenSource.CreateLinkedTokenSource(ct);
        stall.CancelAfter(StallTimeout);

        using var request = NewRequest(url);
        using var response = await Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, stall.Token);
        response.EnsureSuccessStatusCode();
        var length = response.Content.Headers.ContentLength;

        await using var source = await response.Content.ReadAsStreamAsync(stall.Token);
        await using var target = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        var buffer = new byte[81920];
        long total = 0;
        try
        {
            while (true)
            {
                stall.CancelAfter(StallTimeout);
                var read = await source.ReadAsync(buffer, stall.Token);
                if (read == 0) break;

                await target.WriteAsync(buffer.AsMemory(0, read), ct);
                hash.AppendData(buffer, 0, read);
                total += read;
                if (length is > 0) progress?.Report((double)total / length.Value);
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new UpdateException("Der Download des Updates ist hängen geblieben.");
        }

        // All the way to the disk: a power cut right after the swap must not leave a damaged EXE.
        await target.FlushAsync(ct);
        target.Flush(flushToDisk: true);
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static HttpRequestMessage NewRequest(string url)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("NetzwerkScan", CurrentVersion.ToString()));
        return request;
    }

    /// <summary>A read-only leftover would otherwise block every later update.</summary>
    private static void ClearReadOnly(string path)
    {
        if (File.Exists(path) && File.GetAttributes(path).HasFlag(FileAttributes.ReadOnly))
        {
            File.SetAttributes(path, File.GetAttributes(path) & ~FileAttributes.ReadOnly);
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            ClearReadOnly(path);
            File.Delete(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Still in use or not ours to remove. Next start tries again.
        }
    }

    [GeneratedRegex(@"^v(\d+\.\d+\.\d+)$")]
    private static partial Regex ReleaseTag();

    [GeneratedRegex(@"^[0-9a-fA-F]{64}$")]
    private static partial Regex Sha256Hex();
}
