namespace NetzwerkScan.Core;

/// <param name="Name">Short label, shown on the port chips.</param>
/// <param name="Description">What the port is for, shown in the settings.</param>
/// <param name="IsDefault">Part of the standard selection.</param>
/// <param name="IsWeb">Typically has a user interface that opens in a browser.</param>
public sealed record PortInfo(int Port, string Name, string Description, string Category, bool IsDefault = true, bool IsWeb = false);

/// <summary>The ports the settings offer as a list. Others can still be scanned through "Weitere Ports".</summary>
public static class PortCatalog
{
    private const string Web = "Weboberflächen";
    private const string Homelab = "Server und Homelab";
    private const string SmartHome = "Smart Home und Medien";
    private const string Remote = "Fernzugriff";
    private const string Files = "Dateien und Drucker";
    private const string Network = "Netzwerk und Windows-Domäne";
    private const string Mail = "E-Mail";
    private const string Database = "Datenbanken";

    public static readonly IReadOnlyList<PortInfo> All = new PortInfo[]
    {
        new(80, "HTTP", "Webseite, unverschlüsselt", Web, IsWeb: true),
        new(81, "HTTP", "Weboberfläche auf Ausweichport", Web, IsWeb: true),
        new(443, "HTTPS", "Webseite, verschlüsselt", Web, IsWeb: true),
        new(3000, "Web", "Weboberfläche, oft Grafana", Web, IsWeb: true),
        new(4443, "HTTPS", "Weboberfläche auf Ausweichport, verschlüsselt", Web, IsWeb: true),
        new(5000, "Web", "Weboberfläche, oft Synology DSM oder AirPlay", Web, IsWeb: true),
        new(5001, "Web", "Weboberfläche, oft Synology DSM verschlüsselt", Web, IsWeb: true),
        new(7080, "HTTP", "Weboberfläche auf Ausweichport", Web, IsWeb: true),
        new(7443, "HTTPS", "Weboberfläche auf Ausweichport, verschlüsselt", Web, IsWeb: true),
        new(8000, "HTTP", "Weboberfläche auf Ausweichport", Web, IsWeb: true),
        new(8080, "HTTP", "Weboberfläche auf Ausweichport, oft Proxy oder Tomcat", Web, IsWeb: true),
        new(8081, "HTTP", "Weboberfläche auf Ausweichport", Web, IsWeb: true),
        new(8083, "HTTP", "Weboberfläche auf Ausweichport", Web, IsWeb: true),
        new(8088, "HTTP", "Weboberfläche auf Ausweichport", Web, IsWeb: true),
        new(8443, "HTTPS", "Weboberfläche auf Ausweichport, verschlüsselt", Web, IsWeb: true),
        new(8888, "HTTP", "Weboberfläche auf Ausweichport", Web, IsWeb: true),
        new(9000, "Web", "Weboberfläche, oft Portainer", Web, IsWeb: true),
        new(9090, "Web", "Weboberfläche, oft Cockpit oder Prometheus", Web, IsWeb: true),
        new(9443, "HTTPS", "Weboberfläche, oft Portainer", Web, IsWeb: true),

        new(8006, "Proxmox", "Proxmox VE, Verwaltung", Homelab, IsWeb: true),
        new(8007, "Proxmox Backup", "Proxmox Backup Server, Verwaltung", Homelab, IsWeb: true),
        new(10000, "Webmin", "Webmin, Serververwaltung im Browser", Homelab, IsWeb: true),
        new(2375, "Docker", "Docker-Schnittstelle, unverschlüsselt", Homelab),
        new(1880, "Node-RED", "Node-RED, Automatisierung", Homelab, IsWeb: true),
        new(5601, "Kibana", "Kibana, Logauswertung", Homelab, IsWeb: true),
        new(8086, "InfluxDB", "InfluxDB, Messwerte-Datenbank", Homelab, IsWeb: true),

        new(8123, "Home Assistant", "Home Assistant", SmartHome, IsWeb: true),
        new(1883, "MQTT", "MQTT, Nachrichten zwischen Smart-Home-Geräten", SmartHome),
        new(8096, "Jellyfin", "Jellyfin, Medienserver", SmartHome, IsWeb: true),
        new(8920, "Jellyfin", "Jellyfin, Medienserver verschlüsselt", SmartHome, IsWeb: true),
        new(32400, "Plex", "Plex, Medienserver", SmartHome, IsWeb: true),
        new(9091, "Transmission", "Transmission, Torrent-Programm", SmartHome, IsWeb: true),

        new(22, "SSH", "SSH, verschlüsselte Konsole", Remote),
        new(23, "Telnet", "Telnet, Konsole unverschlüsselt", Remote),
        new(3389, "RDP", "Windows-Remotedesktop", Remote),
        new(5900, "VNC", "VNC, Bildschirmfreigabe", Remote),
        new(5985, "WinRM", "Windows-Fernverwaltung", Remote),
        new(5986, "WinRM", "Windows-Fernverwaltung, verschlüsselt", Remote, IsDefault: false),

        new(445, "SMB", "Windows-Freigaben", Files),
        new(139, "NetBIOS", "Windows-Freigaben, ältere Geräte", Files),
        new(21, "FTP", "FTP, Dateiübertragung", Files),
        new(548, "AFP", "Apple-Freigaben", Files),
        new(873, "rsync", "rsync, Dateisynchronisierung", Files),
        new(2049, "NFS", "NFS, Linux- und NAS-Freigaben", Files),
        new(631, "IPP", "Netzwerkdrucker", Files),
        new(515, "LPD", "Netzwerkdrucker, ältere Geräte", Files),
        new(9100, "Drucker", "Netzwerkdrucker, Direktdruck", Files),

        new(53, "DNS", "DNS, Namensauflösung", Network),
        new(135, "RPC", "Windows-Systemdienste", Network),
        new(88, "Kerberos", "Kerberos, Anmeldung in der Windows-Domäne", Network),
        new(389, "LDAP", "LDAP, Verzeichnisdienst", Network),
        new(636, "LDAPS", "LDAP, verschlüsselt", Network),
        new(111, "RPC", "Portmapper für Linux-Dienste wie NFS", Network, IsDefault: false),

        new(25, "SMTP", "Mailversand zwischen Servern", Mail),
        new(587, "SMTP", "Mailversand aus dem Mailprogramm", Mail),
        new(465, "SMTPS", "Mailversand, verschlüsselt", Mail),
        new(143, "IMAP", "Mail abrufen", Mail),
        new(993, "IMAPS", "Mail abrufen, verschlüsselt", Mail),
        new(110, "POP3", "Mail herunterladen", Mail),
        new(995, "POP3S", "Mail herunterladen, verschlüsselt", Mail),

        new(1433, "MS SQL", "Microsoft SQL Server", Database),
        new(3306, "MySQL", "MySQL und MariaDB", Database),
        new(5432, "PostgreSQL", "PostgreSQL", Database),
        new(6379, "Redis", "Redis", Database),
        new(27017, "MongoDB", "MongoDB", Database),
        new(1521, "Oracle", "Oracle Database", Database, IsDefault: false),
        new(11211, "Memcached", "Memcached", Database, IsDefault: false),
    };

    private static readonly Dictionary<int, PortInfo> ByPort = All.ToDictionary(p => p.Port);

    public static IEnumerable<int> DefaultPorts => All.Where(p => p.IsDefault).Select(p => p.Port);

    public static IEnumerable<int> WebPorts => All.Where(p => p.IsWeb).Select(p => p.Port);

    public static string DefaultPortsText => Compose(DefaultPorts, "");

    public static PortInfo? Find(int port) => ByPort.GetValueOrDefault(port);

    /// <summary>Writes a selection as one port list, the form in which settings store it and scans read it.</summary>
    public static string Compose(IEnumerable<int> listedPorts, string? extraPorts) =>
        string.Join(",", listedPorts.Order().Select(p => p.ToString()).Concat(PortList.Tokens(extraPorts)));

    /// <summary>Divides a port list into what the list can show as ticks, and the rest for "Weitere Ports".</summary>
    public static (HashSet<int> Listed, string Extra) Split(string? ports)
    {
        var listed = new HashSet<int>();
        var extra = new List<string>();
        foreach (var token in PortList.Tokens(ports))
        {
            if (int.TryParse(token, out var port) && ByPort.ContainsKey(port)) listed.Add(port);
            else extra.Add(token);
        }
        return (listed, string.Join(",", extra));
    }
}
