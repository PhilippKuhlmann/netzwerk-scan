using System.Windows;
using NetzwerkScan.ViewModels;

namespace NetzwerkScan;

public partial class WakeWindow : Window
{
    public WakeWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;

        var devices = viewModel.LoadWakeCandidates();
        DeviceList.ItemsSource = devices;
        if (devices.Count == 0) EmptyHint.Visibility = Visibility.Visible;

        SourceInitialized += (_, _) => ThemeManager.ApplyTitleBar(this);
    }
}
