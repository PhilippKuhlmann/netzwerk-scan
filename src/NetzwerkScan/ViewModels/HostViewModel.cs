using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows.Input;
using NetzwerkScan.Core;

namespace NetzwerkScan.ViewModels;

public sealed class PortViewModel : ObservableObject
{
    private readonly string _ip;
    private readonly Func<string> _sshUser;
    private WebInfo? _web;

    public PortViewModel(string ip, int port, Func<string> sshUser)
    {
        _ip = ip;
        _sshUser = sshUser;
        Port = port;
        ServiceName = ServiceCatalog.Name(port);
        OpenCommand = new RelayCommand(Open);
    }

    public int Port { get; }
    public string ServiceName { get; }
    public ICommand OpenCommand { get; }

    public bool IsWeb => _web is not null;
    public bool IsSsh => !IsWeb && Port == RemoteCommands.SshPort;
    public bool IsRdp => !IsWeb && Port == RemoteCommands.RdpPort;
    public bool IsClickable => IsWeb || IsSsh || IsRdp;

    public string Url
    {
        get
        {
            if (_web is null) return "";
            var isDefaultPort = (_web.Scheme == "http" && Port == 80) || (_web.Scheme == "https" && Port == 443);
            return isDefaultPort ? $"{_web.Scheme}://{_ip}/" : $"{_web.Scheme}://{_ip}:{Port}/";
        }
    }

    public string ChipText
    {
        get
        {
            var label = ServiceName.Length > 0 ? $"{Port} {ServiceName}" : Port.ToString();
            return IsClickable ? label + " ↗" : label;
        }
    }

    public string WebTitle
    {
        get
        {
            if (_web?.Title is { } title) return title;
            if (_web?.Server is { } server) return server;
            return ServiceName.Length > 0 ? ServiceName : "Weboberfläche";
        }
    }

    public string ToolTipText
    {
        get
        {
            if (IsWeb) return $"Im Browser öffnen: {Url}\n{WebTitle}";
            return Port switch
            {
                RemoteCommands.RdpPort => $"Remotedesktop öffnen: {_ip}",
                RemoteCommands.SshPort => $"SSH-Verbindung öffnen: ssh {RemoteCommands.SshTarget(_ip, _sshUser())}",
                _ => ServiceName.Length > 0 ? $"Port {Port}: {ServiceName}" : $"Port {Port}",
            };
        }
    }

    public void SetWeb(WebInfo info)
    {
        _web = info;
        Raise(nameof(IsWeb));
        Raise(nameof(IsSsh));
        Raise(nameof(IsRdp));
        Raise(nameof(IsClickable));
        Raise(nameof(Url));
        Raise(nameof(ChipText));
        Raise(nameof(WebTitle));
        Raise(nameof(ToolTipText));
    }

    private void Open()
    {
        if (IsWeb) Process.Start(new ProcessStartInfo(Url) { UseShellExecute = true });
        else if (Port == RemoteCommands.RdpPort) Process.Start(RemoteCommands.Rdp(_ip));
        else if (Port == RemoteCommands.SshPort) Process.Start(RemoteCommands.Ssh(_ip, _sshUser()));
    }
}

public sealed class ShareViewModel
{
    public ShareViewModel(string ip, ShareEntry share)
    {
        Name = share.Name;
        Remark = share.Remark;
        CanOpen = share.Kind == ShareKind.Disk;
        // The trailing backslash makes the shell treat this as a folder under all circumstances.
        Path = $@"\\{ip}\{share.Name}\";
        Detail = (share.Kind, share.IsAdministrative) switch
        {
            (ShareKind.Printer, _) => "Drucker",
            (ShareKind.Device, _) => "Gerät",
            (_, true) => "Administrativ",
            _ => "Ordner",
        };
        if (share.Remark.Length > 0) Detail += " · " + share.Remark;
        IsAdministrative = share.IsAdministrative;
        OpenCommand = new RelayCommand(() => Process.Start(new ProcessStartInfo(Path) { UseShellExecute = true }));
    }

    public string Name { get; }
    public string Remark { get; }
    public string Path { get; }
    public string Detail { get; }
    public bool CanOpen { get; }
    public bool IsAdministrative { get; }
    public ICommand OpenCommand { get; }
}

public sealed class HostViewModel : ObservableObject
{
    private string _name = "";
    private string _workgroup = "";
    private string _mac = "";
    private string _vendor = "";
    private string _shareMessage = "";
    private string _sharesSummary = "";
    private bool _needsLogin;
    private bool _isScanning = true;
    private bool _isNew;
    private string _customName = "";
    private readonly Func<string> _sshUser;
    private readonly Action<HostViewModel>? _customNameChanged;

    public HostViewModel(uint ip, long? pingMs, bool isThisPc, Func<string> sshUser, Action<HostViewModel>? customNameChanged = null)
    {
        _sshUser = sshUser;
        _customNameChanged = customNameChanged;
        IpKey = ip;
        Ip = Ipv4.ToText(ip);
        IsThisPc = isThisPc;
        PingText = pingMs is null ? "–" : pingMs == 0 ? "<1 ms" : $"{pingMs} ms";
    }

    public uint IpKey { get; }
    public string Ip { get; }
    public string PingText { get; }
    public bool IsThisPc { get; }

    /// <summary>Not there at earlier scans of this address.</summary>
    public bool IsNew { get => _isNew; set => Set(ref _isNew, value); }

    public ObservableCollection<PortViewModel> Ports { get; } = new();
    public ObservableCollection<PortViewModel> WebPorts { get; } = new();
    public ObservableCollection<ShareViewModel> Shares { get; } = new();

    public string Name { get => _name; set { if (Set(ref _name, value)) Raise(nameof(DisplayName)); } }

    /// <summary>The name the user gave this device. Typed into directly, so it can have a trailing space for a moment.</summary>
    public string CustomName
    {
        get => _customName;
        set
        {
            if (!Set(ref _customName, value)) return;
            Raise(nameof(DisplayName));
            _customNameChanged?.Invoke(this);
        }
    }

    public void LoadCustomName(string name)
    {
        if (Set(ref _customName, name, nameof(CustomName))) Raise(nameof(DisplayName));
    }

    /// <summary>
    /// The user's own name, otherwise the host name without the domain, which would only repeat in every row.
    /// The details show the full name.
    /// </summary>
    public string DisplayName =>
        _customName.Trim() is { Length: > 0 } custom ? custom
        : _name.Length > 0 ? _name.Split('.')[0]
        : IsThisPc ? "Dieser PC"
        : "";

    public string ExportName =>
        _customName.Trim() is { Length: > 0 } custom ? custom
        : _name.Length > 0 ? _name
        : DisplayName;

    public string Workgroup { get => _workgroup; set { if (Set(ref _workgroup, value)) Raise(nameof(Subtitle)); } }
    public string Mac { get => _mac; set { if (Set(ref _mac, value)) Raise(nameof(Subtitle)); } }

    public string Vendor
    {
        get => _vendor;
        set
        {
            if (!Set(ref _vendor, value)) return;
            Raise(nameof(Subtitle));
            Raise(nameof(VendorShort));
            Raise(nameof(VendorToolTip));
        }
    }

    public string VendorShort => MacVendors.ShortName(_vendor);
    public string? VendorToolTip => _vendor.Length > 0 ? _vendor : null;

    public string Subtitle =>
        string.Join(" · ", new[] { IsThisPc ? "Dieser PC" : "", _mac, _vendor, _workgroup }.Where(s => s.Length > 0));

    public bool IsScanning
    {
        get => _isScanning;
        set
        {
            if (Set(ref _isScanning, value)) Raise(nameof(ShowNoWebHint));
        }
    }

    public bool ShowNoWebHint => !_isScanning && WebPorts.Count == 0;
    public bool HasSmb => Ports.Any(p => p.Port is 445 or 139);
    public bool NeedsLogin { get => _needsLogin; private set => Set(ref _needsLogin, value); }
    public string ShareMessage { get => _shareMessage; private set => Set(ref _shareMessage, value); }
    public string SharesSummary { get => _sharesSummary; private set => Set(ref _sharesSummary, value); }
    public int VisibleShareCount => Shares.Count(s => !s.IsAdministrative);

    public void AddPort(int port)
    {
        if (Ports.Any(p => p.Port == port)) return;

        var index = 0;
        while (index < Ports.Count && Ports[index].Port < port) index++;
        Ports.Insert(index, new PortViewModel(Ip, port, _sshUser));
        Raise(nameof(HasSmb));
    }

    public void SetWeb(int portNumber, WebInfo info)
    {
        var port = Ports.FirstOrDefault(p => p.Port == portNumber);
        if (port is null) return;

        port.SetWeb(info);
        var index = 0;
        while (index < WebPorts.Count && WebPorts[index].Port < portNumber) index++;
        WebPorts.Insert(index, port);
        Raise(nameof(ShowNoWebHint));
    }

    public void SetShares(ShareResult result)
    {
        Shares.Clear();
        foreach (var share in result.Shares) Shares.Add(new ShareViewModel(Ip, share));

        NeedsLogin = result.Status == ShareStatus.NeedsLogin;
        ShareMessage = result.Status == ShareStatus.Ok && Shares.Count == 0 ? "Keine Freigaben sichtbar." : result.Message;
        SharesSummary = NeedsLogin ? "Anmeldung nötig"
            : VisibleShareCount > 0 ? VisibleShareCount.ToString()
            : Shares.Count > 0 ? "nur administrativ"
            : "";
        Raise(nameof(VisibleShareCount));
    }

    public bool Matches(string search) =>
        (_isNew && search.Equals("neu", StringComparison.OrdinalIgnoreCase))
        || Ip.Contains(search, StringComparison.OrdinalIgnoreCase)
        || _name.Contains(search, StringComparison.OrdinalIgnoreCase)
        || _customName.Contains(search, StringComparison.OrdinalIgnoreCase)
        || _mac.Contains(search, StringComparison.OrdinalIgnoreCase)
        || _vendor.Contains(search, StringComparison.OrdinalIgnoreCase)
        || Ports.Any(p => p.ChipText.Contains(search, StringComparison.OrdinalIgnoreCase)
                          || (p.IsWeb && p.WebTitle.Contains(search, StringComparison.OrdinalIgnoreCase)))
        || Shares.Any(s => s.Name.Contains(search, StringComparison.OrdinalIgnoreCase));
}
