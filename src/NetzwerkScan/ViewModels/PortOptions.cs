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
    public MissingDeviceViewModel(KnownDevice device)
    {
        Ip = Ipv4.ToText(device.Ip);
        Name = device.Name;
        Mac = device.Mac;
        Vendor = device.Vendor;

        var label = device.Name.Length > 0 ? device.Name.Split('.')[0] : MacVendors.ShortName(device.Vendor);
        Text = label.Length > 0 ? $"{Ip} · {label}" : Ip;
        ToolTipText = $"Zuletzt gesehen: {device.LastSeenUtc.ToLocalTime():dd.MM.yyyy HH:mm}";
    }

    public string Ip { get; }
    public string Name { get; }
    public string Mac { get; }
    public string Vendor { get; }
    public string Text { get; }
    public string ToolTipText { get; }
}
