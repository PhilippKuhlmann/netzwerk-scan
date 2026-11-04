using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Microsoft.Win32;

namespace NetzwerkScan;

public enum AppTheme { System, Light, Dark }

/// <summary>Switches between light and dark, and follows Windows when set to do so.</summary>
public static class ThemeManager
{
    private const string PersonalizeKey = @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";
    private const string AppsUseLightTheme = "AppsUseLightTheme";
    private const int DwmUseImmersiveDarkMode = 20;

    private static bool? _appliedDark;

    public static AppTheme Mode { get; private set; } = AppTheme.System;

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr window, int attribute, ref int value, int size);

    public static void Initialize(AppTheme mode)
    {
        Mode = mode;
        Apply();
        SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
    }

    public static void Shutdown() => SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;

    public static void SetMode(AppTheme mode)
    {
        if (mode == Mode) return;
        Mode = mode;
        Apply();
    }

    public static AppTheme ParseMode(string? text) =>
        Enum.TryParse<AppTheme>(text?.Trim(), ignoreCase: true, out var mode) && Enum.IsDefined(mode) && !int.TryParse(text, out _)
            ? mode
            : AppTheme.System;

    /// <summary>Colors the title bar to match. WPF can't reach it, so this goes through the window manager.</summary>
    public static void ApplyTitleBar(Window window)
    {
        var handle = new WindowInteropHelper(window).Handle;
        if (handle == IntPtr.Zero) return;

        var useDark = _appliedDark == true ? 1 : 0;
        // Older Windows versions don't know this attribute and report an error. They keep a light title bar.
        _ = DwmSetWindowAttribute(handle, DwmUseImmersiveDarkMode, ref useDark, sizeof(int));
    }

    private static void Apply()
    {
        var dark = Mode == AppTheme.Dark || (Mode == AppTheme.System && WindowsUsesDarkMode());
        if (dark == _appliedDark) return;
        _appliedDark = dark;

        var application = Application.Current;
        application.Resources.MergedDictionaries[0] = new ResourceDictionary
        {
            Source = new Uri($"pack://application:,,,/Themes/{(dark ? "Dark" : "Light")}.xaml"),
        };

        foreach (Window window in application.Windows) ApplyTitleBar(window);
    }

    private static bool WindowsUsesDarkMode()
    {
        using var key = Registry.CurrentUser.OpenSubKey(PersonalizeKey);
        return key?.GetValue(AppsUseLightTheme) is int value && value == 0;
    }

    private static void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        // The event arrives on a system thread. Windows reports a theme change as category General.
        if (e.Category == UserPreferenceCategory.General && Mode == AppTheme.System)
        {
            Application.Current?.Dispatcher.BeginInvoke(Apply);
        }
    }
}
