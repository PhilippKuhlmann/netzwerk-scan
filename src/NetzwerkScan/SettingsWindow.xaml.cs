using System.Windows;
using NetzwerkScan.ViewModels;

namespace NetzwerkScan;

/// <summary>Changes apply as they are made. Closing the window, in whatever way, stores them.</summary>
public partial class SettingsWindow : Window
{
    public SettingsWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        SourceInitialized += (_, _) => ThemeManager.ApplyTitleBar(this);
        Closed += (_, _) => viewModel.SaveSettings();
    }
}
