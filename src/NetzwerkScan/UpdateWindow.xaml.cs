using System.Windows;
using NetzwerkScan.Core;

namespace NetzwerkScan;

public partial class UpdateWindow : Window
{
    private readonly UpdateInfo _update;
    private readonly CancellationTokenSource _cancel = new();

    public UpdateWindow(UpdateInfo update)
    {
        InitializeComponent();
        _update = update;
        Heading.Text = $"Update auf Version {update.Version}";
        SourceInitialized += (_, _) => ThemeManager.ApplyTitleBar(this);
        Loaded += async (_, _) => await InstallAsync();
        Closed += (_, _) => _cancel.Cancel();
    }

    public bool Installed { get; private set; }
    public string? Error { get; private set; }

    private async Task InstallAsync()
    {
        try
        {
            await AppUpdater.InstallAsync(_update, new Progress<double>(v => Bar.Value = v), _cancel.Token);
            Installed = true;
        }
        catch (UpdateException e)
        {
            Error = e.Message;
        }
        catch (OperationCanceledException)
        {
            // Skipped by the user. Next start asks again.
        }

        if (IsLoaded) Close();
    }
}
