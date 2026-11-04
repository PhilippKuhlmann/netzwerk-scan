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

            ReplaceFile(exe, newFile, oldFile);
        }
        catch (Exception e) when (e is HttpRequestException or IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            TryDelete(newFile);
            throw new UpdateException($"Update fehlgeschlagen: {e.Message}", e);
        }
        catch
        {
            TryDelete(newFile);
            throw;
        }
    }

    /// <summary>A running EXE can't be overwritten, but it can be renamed. Goes back if the second step fails.</summary>
    public static void ReplaceFile(string exe, string newFile, string oldFile)
    {
        File.Move(exe, oldFile, overwrite: true);
        try
        {
            File.Move(newFile, exe);
        }
        catch
        {
            File.Move(oldFile, exe);
            throw;
        }
    }

    public static void Restart()
    {
        Process.Start(new ProcessStartInfo(InstallPath!) { UseShellExecute = false });
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
        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static HttpRequestMessage NewRequest(string url)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("NetzwerkScan", CurrentVersion.ToString()));
        return request;
    }

    private static void TryDelete(string path)
    {
        try
        {
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
