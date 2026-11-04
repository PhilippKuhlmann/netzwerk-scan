using System.Windows;
using NetzwerkScan.Core;
using NetzwerkScan.ViewModels;

namespace NetzwerkScan;

public partial class CredentialsDialog : Window
{
    private readonly HostViewModel _host;

    public CredentialsDialog(HostViewModel host)
    {
        InitializeComponent();
        _host = host;
        Heading.Text = $"Bei {(host.Name.Length > 0 ? host.Name : host.Ip)} anmelden";
        Loaded += (_, _) => UserBox.Focus();
        SourceInitialized += (_, _) => ThemeManager.ApplyTitleBar(this);
    }

    private async void Login_Click(object sender, RoutedEventArgs e)
    {
        if (UserBox.Text.Trim().Length == 0)
        {
            ShowError("Bitte einen Benutzernamen eingeben.");
            return;
        }

        LoginButton.IsEnabled = false;
        ErrorText.Visibility = Visibility.Collapsed;

        var result = await SmbShares.LoginAndEnumerateAsync(_host.Ip, UserBox.Text.Trim(), PasswordInput.Password);

        LoginButton.IsEnabled = true;
        if (result.Status == ShareStatus.Ok)
        {
            _host.SetShares(result);
            DialogResult = true;
        }
        else
        {
            ShowError(result.Message);
        }
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }
}
