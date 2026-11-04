# Netzwerk-Scan

Windows-Anwendung, die ein Netzwerk nach Geräten, offenen Ports und Windows-Freigaben durchsucht.

## Download

Die aktuelle `NetzwerkScan.exe` liegt unter [Releases](https://github.com/PhilippKuhlmann/netzwerk-scan/releases/latest).
Sie läuft ohne Installation und ohne Adminrechte auf Windows 10 und 11 (x64). Die EXE ist nicht signiert, Windows kann beim ersten Start also eine SmartScreen-Warnung zeigen.

## Funktionen

- **Netzwerk wählen:** Netzwerkkarte auswählen, der Scan startet sofort. Oder einen eigenen Bereich eingeben (`192.168.1.0/24`, `192.168.1.10-50`).
- **Übersicht:** belegte und freie Adressen, Geräte mit offenen Ports, Weboberflächen und Freigaben.
- **Geräte finden:** per Ping, TCP und ARP-Tabelle, damit auch Geräte auftauchen, die nicht auf Ping antworten. Mit Namen, MAC-Adresse und Hersteller (IEEE-Liste, offline enthalten).
- **Per Klick öffnen:** Weboberflächen im Browser (HTTP oder HTTPS wird erkannt, zum Beispiel Proxmox auf Port 8006), Remotedesktop auf Port 3389 und SSH auf Port 22.
- **Windows-Freigaben:** anzeigen, im Explorer öffnen, bei Bedarf mit einem Benutzerkonto anmelden.
- **Änderungen erkennen:** zeigt, welche Geräte seit dem letzten Scan neu oder verschwunden sind. Die Daten bleiben auf dem eigenen PC. Geräte werden an der MAC-Adresse erkannt, gleich nummerierte Netze an verschiedenen Standorten gelten dabei als ein Netz.
- **Export:** Ergebnis als CSV-Datei speichern, passend für Excel.
- **Einstellungen:** Ports zum Abhaken mit Erklärung, Timeout, SSH-Benutzer, helles oder dunkles Design.

Nur Netzwerke scannen, die dir gehören oder für die du die Erlaubnis hast.

## Automatische Updates

Bei jedem Start fragt die Anwendung GitHub nach einem neueren Release. Gibt es eines, wird es heruntergeladen, installiert und die Anwendung startet neu. Ohne Internet startet sie einfach normal.

Dabei überträgt sie nur die üblichen Daten einer Webanfrage und ihre Versionsnummer. Scan-Ergebnisse verlassen den PC nicht.

Die Updates sind nicht signiert. Vertrauensanker ist das GitHub-Konto dieses Repositorys: Wer es kontrolliert, bestimmt, was alle installierten Kopien beim nächsten Start ausführen.

## Selbst bauen

Voraussetzung ist das [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0).

```bash
dotnet test -c Release
```

```bash
dotnet publish src/NetzwerkScan -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -p:DebugType=none -o dist
```

Nur so gebaute Single-File-Versionen aktualisieren sich automatisch, und nur wenn ihr Ordner beschreibbar ist und keine zweite Kopie von dort läuft.

## Neue Version veröffentlichen

Version in `src/NetzwerkScan/NetzwerkScan.csproj` erhöhen, committen und ein Tag wie `v1.2.0` pushen. Der Workflow testet, baut die EXE und legt das Release an.

Die Herstellerliste aktualisierst du mit `tools/update-oui.ps1`. Sie stammt aus den öffentlichen [IEEE-Registern](https://standards-oui.ieee.org/).
