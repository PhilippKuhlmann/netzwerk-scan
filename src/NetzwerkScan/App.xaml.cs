using System.Windows;
using NetzwerkScan.Core;

namespace NetzwerkScan;

public partial class App : Application
{
    public AppSettings Settings { get; private set; } = new();

    protected override void OnStartup(StartupEventArgs e)
    {
        // Share queries use a blocking Windows API, so they need threads available without ramp-up delay.
        ThreadPool.GetMinThreads(out _, out var ioThreads);
        ThreadPool.SetMinThreads(32, ioThreads);

        // For example no default browser, or a share that disappeared: worth a message, not a crash.
        DispatcherUnhandledException += (_, args) =>
        {
            MessageBox.Show(args.Exception.Message, "Netzwerk-Scan", MessageBoxButton.OK, MessageBoxImage.Warning);
            args.Handled = true;
        };

        Settings = AppSettings.Load();
        ThemeManager.Initialize(ThemeManager.ParseMode(Settings.Theme));
        _ = Task.Run(MacVendors.Preload);

        base.OnStartup(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        ThemeManager.Shutdown();
        SmbShares.CloseConnections();
        base.OnExit(e);
    }
}
