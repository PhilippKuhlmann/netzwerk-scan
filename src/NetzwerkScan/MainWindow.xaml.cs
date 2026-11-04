using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using Microsoft.Win32;
using NetzwerkScan.Core;
using NetzwerkScan.ViewModels;

namespace NetzwerkScan;

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel = new(((App)Application.Current).Settings);
    private object? _adapterBeforeDropDown;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _viewModel;
        SourceInitialized += (_, _) => ThemeManager.ApplyTitleBar(this);
        Loaded += async (_, _) => await UpdateIfAvailableAsync();
    }

    /// <summary>Runs after the window is up, so that a slow or missing connection doesn't delay the start.</summary>
    private async Task UpdateIfAvailableAsync()
    {
        if (AppUpdater.InstallPath is null) return;

        _ = AppUpdater.CleanUpAsync();
        if (await AppUpdater.CheckAsync() is not { } update) return;

        // The check can take a moment. Whatever was started in the meantime must not get lost to a restart.
        if (_viewModel.IsScanning || _viewModel.Hosts.Count > 0 || OwnedWindows.Count > 0)
        {
            _viewModel.ShowNotice($"Update auf Version {update.Version} wird beim nächsten Start installiert.");
            return;
        }

        if (AppUpdater.FindInstallObstacle() is { } obstacle)
        {
            _viewModel.ShowNotice($"Update auf Version {update.Version} ist verfügbar, aber nicht möglich: {obstacle}");
            return;
        }

        var dialog = new UpdateWindow(update) { Owner = this };
        dialog.ShowDialog();

        if (dialog.Installed)
        {
            try
            {
                AppUpdater.RestartOrRollBack();
                Application.Current.Shutdown();
            }
            catch (UpdateException e)
            {
                _viewModel.ShowNotice(e.Message);
            }
        }
        else if (dialog.Error is not null)
        {
            _viewModel.ShowNotice(dialog.Error);
        }
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog
        {
            Title = "Ergebnis exportieren",
            Filter = "CSV-Datei (*.csv)|*.csv",
            FileName = $"netzwerk-scan-{DateTime.Now:yyyy-MM-dd-HHmm}.csv",
        };
        if (dialog.ShowDialog(this) != true) return;

        File.WriteAllText(dialog.FileName, _viewModel.BuildCsv(), CsvExport.FileEncoding);
        _viewModel.ShowNotice($"Exportiert nach {dialog.FileName}");
    }

    private void AdapterCombo_DropDownOpened(object? sender, EventArgs e) =>
        _adapterBeforeDropDown = AdapterCombo.SelectedItem;

    /// <summary>Picking another network adapter starts its scan right away.</summary>
    private void AdapterCombo_DropDownClosed(object? sender, EventArgs e)
    {
        if (AdapterCombo.SelectedItem is AdapterOption { Adapter: not null } option
            && !ReferenceEquals(option, _adapterBeforeDropDown))
        {
            _ = _viewModel.StartScanAsync();
        }
    }

    private void Settings_Click(object sender, RoutedEventArgs e) =>
        new SettingsWindow(_viewModel) { Owner = this }.ShowDialog();

    private void CopyIp_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel.SelectedHost is not { } host) return;
        try
        {
            Clipboard.SetText(host.Ip);
        }
        catch (COMException)
        {
            // Another program is holding the clipboard open. Trying again is all the user can do too.
        }
    }

    private void Login_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel.SelectedHost is not { } host) return;

        var dialog = new CredentialsDialog(host) { Owner = this };
        if (dialog.ShowDialog() == true) _viewModel.RefreshStatistics();
    }
}
