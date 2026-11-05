using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;
using NetzwerkScan.Core;

namespace NetzwerkScan.ViewModels;

// ToString is also what screen readers announce for an entry in a drop-down.
public sealed record AdapterOption(string Text, AdapterInfo? Adapter)
{
    public override string ToString() => Text;
}

public sealed record ThemeOption(string Text, AppTheme Theme)
{
    public override string ToString() => Text;
}

public sealed class MainViewModel : ObservableObject
{
    private const string ManualText = "Eigener Bereich (manuell)";

    private readonly Dictionary<uint, HostViewModel> _hostsByIp = new();
    private readonly DispatcherTimer _timer;
    private readonly Stopwatch _stopwatch = new();
    private readonly ICollectionView _hostsView;

    private AdapterOption? _selectedAdapter;
    private HostViewModel? _selectedHost;
    private string _rangeText = "";
    private string _rangeInfo = "";
    private bool _rangeHasError;
    private string _portsText = "";
    private string _portsInfo = "";
    private bool _portsHaveError;
    private bool _scanPorts;
    private bool _findShares;
    private string _timeoutText = "";
    private bool _timeoutHasError;
    private string _search = "";
    private bool _isScanning;
    private bool _hasScanned;
    private double _progress;
    private string _statusText = "Bereit";
    private string _elapsedText = "";
    private long _totalAddresses;
    private string _foundText = "–";
    private string _freeText = "noch kein Scan";
    private int _hostsWithPorts;
    private string _openPortsText = "";
    private int _webCount;
    private string _webHostsText = "";
    private int _shareCount;
    private string _shareHostsText = "";
    private bool _settingRange;
    private bool _applyingPorts;
    private string _extraPortsText = "";

    private NetworkScanner? _scanner;
    private CancellationTokenSource? _cancel;
    private Task? _running;
    private readonly AppSettings _settings;
    private readonly DeviceInventory _inventory = DeviceInventory.Load();
    private string _sshUser = "";
    private string _changeSummary = "";
    private bool _customNamesChanged;

    public MainViewModel(AppSettings settings)
    {
        _settings = settings;
        _sshUser = settings.SshUser;

        Adapters = new ObservableCollection<AdapterOption>(
            NetworkAdapters.List().Select(a => new AdapterOption($"{a.Name}  –  {a.Cidr}  ({a.Description})", a)));
        Adapters.Add(new AdapterOption(ManualText, null));

        _hostsView = CollectionViewSource.GetDefaultView(Hosts);
        _hostsView.SortDescriptions.Add(new SortDescription(nameof(HostViewModel.IpKey), ListSortDirection.Ascending));
        _hostsView.Filter = item => _search.Length == 0 || ((HostViewModel)item).Matches(_search);

        // Vendors and ports arrive after the hosts, so a list sorted by those columns must follow along.
        ((ListCollectionView)_hostsView).IsLiveSorting = true;

        _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(200) };
        _timer.Tick += (_, _) => UpdateLiveState();

        ToggleScanCommand = new RelayCommand(() => _ = ToggleScanAsync());
        SelectStandardPortsCommand = new RelayCommand(() => ApplyPorts(PortCatalog.DefaultPorts, ""));
        SelectWebPortsCommand = new RelayCommand(() => ApplyPorts(PortCatalog.WebPorts, ""));
        ClearPortsCommand = new RelayCommand(() => ApplyPorts(Array.Empty<int>(), ""));

        PortGroups = PortCatalog.All
            .GroupBy(p => p.Category)
            .Select(g => new PortGroupViewModel(g.Key, g.Select(p => new PortOptionViewModel(p, UpdatePorts)).ToList()))
            .ToList();

        ScanPorts = settings.ScanPorts;
        FindShares = settings.FindShares;
        TimeoutText = settings.TimeoutMs.ToString();
        var (listedPorts, extraPorts) = PortCatalog.Split(settings.Ports);
        ApplyPorts(listedPorts, extraPorts);
        RestoreNetwork(settings);
    }

    private void RestoreNetwork(AppSettings settings)
    {
        var adapter = Adapters.FirstOrDefault(o => o.Adapter is not null && o.Adapter.Name == settings.LastAdapter);
        if (adapter is not null) SelectedAdapter = adapter;
        else if (settings.LastAdapter.Length == 0 && settings.LastRange.Length > 0) RangeText = settings.LastRange;
        else SelectedAdapter = Adapters[0]; // nothing remembered, or that adapter is gone
    }

    public ObservableCollection<AdapterOption> Adapters { get; }
    /// <summary>Devices from the previous scan that this one did not find.</summary>
    public ObservableCollection<MissingDeviceViewModel> MissingDevices { get; } = new();

    /// <summary>One line on what changed since the previous scan. Empty before the first result.</summary>
    public string ChangeSummary { get => _changeSummary; private set => Set(ref _changeSummary, value); }

    public bool CanExport => Hosts.Count > 0 || MissingDevices.Count > 0;

    public string VersionText => $"Version {AppUpdater.CurrentVersion}";

    public string SshUser
    {
        get => _sshUser;
        set
        {
            if (!Set(ref _sshUser, value.Trim())) return;
            Raise(nameof(SshUserHasError));
        }
    }

    public bool SshUserHasError => _sshUser.Length > 0 && !RemoteCommands.IsValidSshUser(_sshUser);

    public void ShowNotice(string message) => StatusText = message;

    public string BuildCsv()
    {
        var rows = Hosts.OrderBy(h => h.IpKey).Select(h => new CsvRow(
            h.IsNew ? "Neu" : "Bekannt",
            h.Ip,
            h.ExportName,
            h.Mac,
            h.Vendor,
            h.PingText,
            string.Join(", ", h.Ports.Select(p => p.ServiceName.Length > 0 ? $"{p.Port} {p.ServiceName}" : p.Port.ToString())),
            string.Join(", ", h.WebPorts.Select(p => p.Url)),
            h.NeedsLogin ? "Anmeldung nötig" : string.Join(", ", h.Shares.Select(s => s.Name))));

        var missing = MissingDevices.Select(m => new CsvRow(
            "Verschwunden", m.Ip, m.Name, m.Mac, m.Vendor, "", "", "", ""));

        return CsvExport.Build(rows.Concat(missing));
    }

    public IReadOnlyList<PortGroupViewModel> PortGroups { get; }
    public ICommand SelectStandardPortsCommand { get; }
    public ICommand SelectWebPortsCommand { get; }
    public ICommand ClearPortsCommand { get; }

    public ThemeOption[] ThemeOptions { get; } =
    {
        new("Wie Windows", AppTheme.System),
        new("Hell", AppTheme.Light),
        new("Dunkel", AppTheme.Dark),
    };

    public ThemeOption SelectedTheme
    {
        get => ThemeOptions.First(o => o.Theme == ThemeManager.Mode);
        set
        {
            if (value is null) return; // the drop-down reports this while it is being taken down
            ThemeManager.SetMode(value.Theme);
            Raise();
        }
    }

    public ObservableCollection<HostViewModel> Hosts { get; } = new();
    public ICommand ToggleScanCommand { get; }

    public AdapterOption? SelectedAdapter
    {
        get => _selectedAdapter;
        set
        {
            if (!Set(ref _selectedAdapter, value)) return;
            if (value?.Adapter is { } adapter)
            {
                _settingRange = true;
                RangeText = adapter.Cidr;
                _settingRange = false;
            }
        }
    }

    public string RangeText
    {
        get => _rangeText;
        set
        {
            if (!Set(ref _rangeText, value)) return;

            RangeHasError = !IpRangeSet.TryParse(value, out var range, out var error);
            RangeInfo = RangeHasError ? error
                : range.Ranges.Count > 1 ? $"{range.Count:N0} Adressen in {range.Ranges.Count} Bereichen"
                : $"{range.Count:N0} Adressen: {range}";

            if (!_settingRange) SelectedAdapter = Adapters[^1]; // typing a range means it is now a manual one
        }
    }

    public string RangeInfo { get => _rangeInfo; private set => Set(ref _rangeInfo, value); }
    public bool RangeHasError { get => _rangeHasError; private set => Set(ref _rangeHasError, value); }

    public string ExtraPortsText
    {
        get => _extraPortsText;
        set
        {
            if (Set(ref _extraPortsText, value)) UpdatePorts();
        }
    }

    /// <summary>The whole selection as one list: the ticked ports plus "Weitere Ports".</summary>
    public string PortsText => _portsText;

    private void ApplyPorts(IEnumerable<int> listedPorts, string extraPorts)
    {
        var listed = listedPorts.ToHashSet();
        _applyingPorts = true;
        foreach (var option in PortGroups.SelectMany(g => g.Options)) option.IsChecked = listed.Contains(option.Port);
        ExtraPortsText = extraPorts;
        _applyingPorts = false;
        UpdatePorts();
    }

    private void UpdatePorts()
    {
        if (_applyingPorts) return;

        var ticked = PortGroups.SelectMany(g => g.Options).Where(o => o.IsChecked).Select(o => o.Port);
        _portsText = PortCatalog.Compose(ticked, _extraPortsText);

        PortsHaveError = !PortList.TryParse(_portsText, out var ports, out var error);
        PortsInfo = PortsHaveError ? error : ports.Length == 1 ? "1 Port ausgewählt" : $"{ports.Length:N0} Ports ausgewählt";
        RaiseScanSummary();
    }

    public string PortsInfo { get => _portsInfo; private set => Set(ref _portsInfo, value); }
    public bool PortsHaveError { get => _portsHaveError; private set => Set(ref _portsHaveError, value); }

    public bool ScanPorts
    {
        get => _scanPorts;
        set
        {
            if (Set(ref _scanPorts, value)) RaiseScanSummary();
        }
    }

    public bool FindShares
    {
        get => _findShares;
        set
        {
            if (Set(ref _findShares, value)) RaiseScanSummary();
        }
    }

    public string TimeoutText
    {
        get => _timeoutText;
        set
        {
            if (!Set(ref _timeoutText, value)) return;
            TimeoutHasError = !TryParseTimeout(value, out _);
            RaiseScanSummary();
        }
    }

    public bool TimeoutHasError { get => _timeoutHasError; private set => Set(ref _timeoutHasError, value); }

    public string TimeoutRangeText => $"Zahl zwischen {AppSettings.MinTimeoutMs} und {AppSettings.MaxTimeoutMs}";

    /// <summary>One line in the main window, so that the settings don't have to be opened to know what a scan does.</summary>
    public string ScanSummary
    {
        get
        {
            if (ScanSettingsInvalid) return "Einstellungen prüfen: " + (PortsActiveAndInvalid ? "Portliste ungültig" : "Timeout ungültig");

            if (_scanPorts && PortList.TryParse(_portsText, out var ports, out _))
            {
                var count = ports.Length == 1 ? "1 Port" : $"{ports.Length:N0} Ports";
                return _findShares ? $"Scannt {count} und Windows-Freigaben" : $"Scannt {count}";
            }
            return _findShares ? "Sucht Geräte und Windows-Freigaben, keine weiteren Ports" : "Sucht nur Geräte, keine Ports";
        }
    }

    public bool ScanSettingsInvalid => PortsActiveAndInvalid || _timeoutHasError;

    private bool PortsActiveAndInvalid => _scanPorts && _portsHaveError;

    private void RaiseScanSummary()
    {
        Raise(nameof(ScanSummary));
        Raise(nameof(ScanSettingsInvalid));
    }

    private static bool TryParseTimeout(string text, out int timeout) =>
        int.TryParse(text, out timeout) && timeout is >= AppSettings.MinTimeoutMs and <= AppSettings.MaxTimeoutMs;

    /// <summary>Stores the current choices. Invalid entries keep the last good value on disk.</summary>
    public void SaveSettings()
    {
        _settings.Theme = ThemeManager.Mode.ToString();
        _settings.ScanPorts = _scanPorts;
        _settings.FindShares = _findShares;
        if (!_portsHaveError) _settings.Ports = _portsText;
        if (TryParseTimeout(_timeoutText, out var timeout)) _settings.TimeoutMs = timeout;
        if (!SshUserHasError) _settings.SshUser = _sshUser;
        _settings.LastAdapter = _selectedAdapter?.Adapter?.Name ?? "";
        if (_selectedAdapter?.Adapter is null && !_rangeHasError) _settings.LastRange = _rangeText.Trim();
        _settings.Save();
    }

    private void OnCustomNameChanged(HostViewModel host)
    {
        _inventory.SetCustomName(host.Mac, host.IpKey, host.CustomName);
        _customNamesChanged = true;
    }

    public void SaveCustomNames()
    {
        if (!_customNamesChanged) return;
        _customNamesChanged = false;
        _inventory.Save();
    }

    public string Search
    {
        get => _search;
        set
        {
            if (Set(ref _search, value.Trim())) _hostsView.Refresh();
        }
    }

    public HostViewModel? SelectedHost { get => _selectedHost; set => Set(ref _selectedHost, value); }

    public bool IsScanning
    {
        get => _isScanning;
        private set
        {
            if (Set(ref _isScanning, value)) Raise(nameof(ShowEmptyHint));
        }
    }

    public bool ShowEmptyHint => !_isScanning && Hosts.Count == 0;
    public string EmptyHintText => _hasScanned
        ? "Im gewählten Bereich wurde kein Gerät gefunden."
        : "Netzwerkkarte auswählen oder Bereich eingeben und den Scan starten.";

    public double Progress { get => _progress; private set => Set(ref _progress, value); }
    public string StatusText { get => _statusText; private set => Set(ref _statusText, value); }
    public string ElapsedText { get => _elapsedText; private set => Set(ref _elapsedText, value); }
    public string FoundText { get => _foundText; private set => Set(ref _foundText, value); }
    public string FreeText { get => _freeText; private set => Set(ref _freeText, value); }
    public int HostsWithPorts { get => _hostsWithPorts; private set => Set(ref _hostsWithPorts, value); }
    public string OpenPortsText { get => _openPortsText; private set => Set(ref _openPortsText, value); }
    public int WebCount { get => _webCount; private set => Set(ref _webCount, value); }
    public string WebHostsText { get => _webHostsText; private set => Set(ref _webHostsText, value); }
    public int ShareCount { get => _shareCount; private set => Set(ref _shareCount, value); }
    public string ShareHostsText { get => _shareHostsText; private set => Set(ref _shareHostsText, value); }

    private async Task ToggleScanAsync()
    {
        if (IsScanning) _cancel?.Cancel();
        else await StartScanAsync();
    }

    /// <summary>Starts a scan. A scan that is still running gets cancelled first.</summary>
    public async Task StartScanAsync()
    {
        if (_running is not null)
        {
            _cancel?.Cancel();
            try { await _running; } catch { /* its outcome no longer matters */ }
        }

        if (!TryBuildOptions(out var options, out var error))
        {
            StatusText = error;
            return;
        }

        SaveSettings();
        Hosts.Clear();
        _hostsByIp.Clear();
        MissingDevices.Clear();
        ChangeSummary = "";
        Raise(nameof(CanExport));
        SelectedHost = null;
        Search = "";
        _totalAddresses = options.Range.Count;
        _hasScanned = true;
        Raise(nameof(EmptyHintText));
        Progress = 0;
        UpdateStatistics();

        var scanner = new NetworkScanner();
        var cancel = new CancellationTokenSource();
        _scanner = scanner;
        _cancel = cancel;
        IsScanning = true;
        _stopwatch.Restart();
        _timer.Start();

        var events = new Progress<ScanEvent>(Apply);
        var running = Task.Run(() => scanner.RunAsync(options, events, cancel.Token));
        _running = running;

        string outcome;
        var completed = false;
        try
        {
            await running;
            completed = true;
            Progress = 100;
            outcome = $"Fertig: {Hosts.Count} von {_totalAddresses:N0} Adressen belegt";
        }
        catch (OperationCanceledException)
        {
            outcome = "Scan abgebrochen";
        }
        catch (Exception e)
        {
            outcome = "Fehler beim Scan: " + e.Message;
        }

        _timer.Stop();
        _stopwatch.Stop();
        _running = null;
        cancel.Dispose();
        foreach (var host in Hosts) host.IsScanning = false;
        IsScanning = false;
        CompareWithEarlierScans(options.Range, completed);
        UpdateStatistics();
        UpdateElapsed();
        StatusText = outcome;
    }

    private void CompareWithEarlierScans(IpRangeSet range, bool completed)
    {
        var seen = Hosts.Select(h => new SeenDevice(h.IpKey, h.Mac, h.Name, h.Vendor)).ToList();
        var comparison = _inventory.Compare(range, seen);

        foreach (var host in Hosts) host.IsNew = comparison.NewIps.Contains(host.IpKey);

        if (completed)
        {
            // Only a finished scan can tell that a device is really gone.
            foreach (var device in comparison.Missing) MissingDevices.Add(new MissingDeviceViewModel(device, _inventory.CustomNameFor(device.Mac, device.Ip)));
            _inventory.Record(range, seen, DateTime.UtcNow);
            _inventory.Save();
        }

        ChangeSummary = DescribeChanges(comparison.NewIps.Count, MissingDevices.Count, comparison.HadHistory, completed);
        Raise(nameof(CanExport));
    }

    public static string DescribeChanges(int newCount, int missingCount, bool hadHistory, bool completed)
    {
        var news = newCount == 1 ? "1 Gerät neu" : $"{newCount} Geräte neu";
        if (!completed) return newCount > 0 ? $"{news} (Scan abgebrochen, verschwundene Geräte nicht geprüft)" : "";
        if (!hadHistory) return "Erster Scan dieses Bereichs: Die Geräte sind jetzt bekannt.";
        if (newCount == 0 && missingCount == 0) return "Keine Änderungen seit dem letzten Scan.";

        var gone = missingCount == 1 ? "1 verschwunden" : $"{missingCount} verschwunden";
        return $"Seit dem letzten Scan: {news}, {gone}";
    }

    private bool TryBuildOptions(out ScanOptions options, out string error)
    {
        options = null!;
        if (!IpRangeSet.TryParse(RangeText, out var range, out error)) return false;

        var ports = Array.Empty<int>();
        if (ScanPorts && !PortList.TryParse(PortsText, out ports, out error))
        {
            error = "Einstellungen: " + error;
            return false;
        }

        if (!TryParseTimeout(TimeoutText, out var timeout))
        {
            error = $"Timeout in den Einstellungen bitte als {TimeoutRangeText} angeben.";
            return false;
        }

        options = new ScanOptions(range, ports, FindShares, timeout);
        return true;
    }

    private void Apply(ScanEvent e)
    {
        if (e is HostFoundEvent found)
        {
            var created = new HostViewModel(found.Ip, found.PingMs, found.IsThisPc, () => RemoteCommands.SshUserOrDefault(_sshUser), OnCustomNameChanged);
            created.LoadCustomName(_inventory.CustomNameFor("", found.Ip));
            _hostsByIp[found.Ip] = created;
            Hosts.Add(created);
            Raise(nameof(ShowEmptyHint));
            Raise(nameof(CanExport));
            return;
        }

        if (!_hostsByIp.TryGetValue(e.Ip, out var host)) return;

        switch (e)
        {
            case HostMacEvent mac:
                host.Mac = mac.Mac;
                host.Vendor = MacVendors.Lookup(mac.Mac);
                host.LoadCustomName(_inventory.CustomNameFor(mac.Mac, host.IpKey));
                break;
            case HostNameEvent name:
                if (name.Name is not null) host.Name = name.Name;
                if (name.Workgroup is not null) host.Workgroup = name.Workgroup;
                break;
            case PortOpenEvent port:
                host.AddPort(port.Port);
                break;
            case PortWebEvent web:
                host.SetWeb(web.Port, web.Info);
                break;
            case SharesEvent shares:
                host.SetShares(shares.Result);
                break;
            case HostFinishedEvent:
                host.IsScanning = false;
                break;
        }
    }

    private void UpdateLiveState()
    {
        UpdateStatistics();
        UpdateElapsed();

        if (_scanner is null || _totalAddresses == 0) return;
        var state = _scanner.Progress;

        if (state.Phase == ScanPhase.Discovery)
        {
            Progress = 50.0 * state.Checked / _totalAddresses;
            StatusText = state.Checked >= _totalAddresses
                ? "Schritt 1 von 2: Prüfe ARP-Tabelle…"
                : $"Schritt 1 von 2: Prüfe Adressen ({state.Checked:N0} von {_totalAddresses:N0})";
        }
        else
        {
            Progress = state.Found == 0 ? 100 : 50.0 + 50.0 * state.Finished / state.Found;
            StatusText = $"Schritt 2 von 2: Prüfe Ports und Dienste ({state.Finished} von {state.Found} Geräten)";
        }

        if (_search.Length > 0) _hostsView.Refresh();
    }

    private void UpdateElapsed() => ElapsedText = _stopwatch.Elapsed.ToString(@"m\:ss");

    private void UpdateStatistics()
    {
        var found = Hosts.Count;
        FoundText = $"{found:N0} / {_totalAddresses:N0}";
        FreeText = $"{_totalAddresses - found:N0} frei";

        HostsWithPorts = Hosts.Count(h => h.Ports.Count > 0);
        var openPorts = Hosts.Sum(h => h.Ports.Count);
        OpenPortsText = openPorts == 1 ? "1 offener Port" : $"{openPorts:N0} offene Ports";

        WebCount = Hosts.Sum(h => h.WebPorts.Count);
        var webHosts = Hosts.Count(h => h.WebPorts.Count > 0);
        WebHostsText = webHosts == 1 ? "auf 1 Gerät" : $"auf {webHosts} Geräten";

        ShareCount = Hosts.Sum(h => h.VisibleShareCount);
        var shareHosts = Hosts.Count(h => h.VisibleShareCount > 0);
        var loginHosts = Hosts.Count(h => h.NeedsLogin);
        ShareHostsText = (shareHosts == 1 ? "auf 1 Gerät" : $"auf {shareHosts} Geräten")
                         + (loginHosts > 0 ? $", {loginHosts} mit Anmeldung" : "");
    }

    /// <summary>Refreshes the overview after the shares of a host changed outside of a scan.</summary>
    public void RefreshStatistics() => UpdateStatistics();
}
