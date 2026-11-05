using System.Windows.Input;
using NetzwerkScan.Core;

namespace NetzwerkScan.ViewModels;

public sealed class PortOptionViewModel : ObservableObject
{
    private readonly Action _changed;
    private bool _isChecked;

    public PortOptionViewModel(PortInfo info, Action changed)
    {
        Info = info;
        _changed = changed;
    }

    public PortInfo Info { get; }
    public int Port => Info.Port;
    public string Description => Info.Description;

    public bool IsChecked
    {
        get => _isChecked;
        set
        {
            if (Set(ref _isChecked, value)) _changed();
        }
    }
}

public sealed record PortGroupViewModel(string Name, IReadOnlyList<PortOptionViewModel> Options);

public sealed class MissingDeviceViewModel
{
    public MissingDeviceViewModel(KnownDevice device, string customName = "", Action<MissingDeviceViewModel>? wake = null)
    {
        IpKey = device.Ip;
        Ip = Ipv4.ToText(device.Ip);
        Name = customName.Length > 0 ? customName : device.Name;
        Mac = device.Mac;
        Vendor = device.Vendor;

        Label = customName.Length > 0 ? customName
            : device.Name.Length > 0 ? DeviceNames.Short(device.Name)
            : MacVendors.ShortName(device.Vendor);
        Text = Label.Length > 0 ? $"{Ip} · {Label}" : Ip;

        var lastSeen = $"Zuletzt gesehen: {device.LastSeenUtc.ToLocalTime():dd.MM.yyyy HH:mm}";
        CanWake = wake is not null && NeighborTable.IsRealMac(device.Mac);
        ToolTipText = CanWake ? $"{lastSeen}\nKlicken, um es per Wake-on-LAN zu wecken" : lastSeen;
        Detail = string.Join(" · ", new[] { Mac, MacVendors.ShortName(Vendor), lastSeen }.Where(s => s.Length > 0));
        WakeCommand = new RelayCommand(() => wake?.Invoke(this));
    }

    public uint IpKey { get; }
    public string Ip { get; }
    public string Name { get; }
    public string Mac { get; }
    public string Vendor { get; }
    public string Label { get; }
    public string Text { get; }
    public string Detail { get; }
    public string ToolTipText { get; }
    public bool CanWake { get; }
    public ICommand WakeCommand { get; }
}
