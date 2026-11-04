# Rebuilds the embedded vendor list (src\NetzwerkScan\Assets\oui.txt.gz) from the public IEEE registries.
#
#   powershell -ExecutionPolicy Bypass -File tools\update-oui.ps1
#   powershell -ExecutionPolicy Bypass -File tools\update-oui.ps1 -SourceDir C:\path\with\csv-files
#
# Output format, one line per assignment, sorted: <hex prefix of 6, 7 or 9 digits><TAB><organization>
param(
    [string]$SourceDir,
    [string]$OutFile = (Join-Path $PSScriptRoot '..\src\NetzwerkScan\Assets\oui.txt.gz')
)
$ErrorActionPreference = 'Stop'

$sources = @(
    @{ File = 'oui.csv';   Url = 'https://standards-oui.ieee.org/oui/oui.csv';     Length = 6; Minimum = 30000 },
    @{ File = 'mam.csv';   Url = 'https://standards-oui.ieee.org/oui28/mam.csv';   Length = 7; Minimum = 4000 },
    @{ File = 'oui36.csv'; Url = 'https://standards-oui.ieee.org/oui36/oui36.csv'; Length = 9; Minimum = 4000 },
    @{ File = 'iab.csv';   Url = 'https://standards-oui.ieee.org/iab/iab.csv';     Length = 9; Minimum = 4000 }
)

$tempDir = $null
if (-not $SourceDir) {
    $tempDir = Join-Path ([IO.Path]::GetTempPath()) ("oui-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    $SourceDir = $tempDir
    [Net.ServicePointManager]::SecurityProtocol = 'Tls12'
    foreach ($s in $sources) {
        Invoke-WebRequest -UseBasicParsing -Uri $s.Url -OutFile (Join-Path $SourceDir $s.File) -TimeoutSec 300 -UserAgent 'NetzwerkScan-OUI-Update/1.0'
    }
}

try {
    $entries = New-Object 'System.Collections.Generic.SortedDictionary[string,string]' ([StringComparer]::Ordinal)
    $dropped = 0
    $duplicates = 0

    foreach ($s in $sources) {
        $rows = [IO.File]::ReadAllText((Join-Path $SourceDir $s.File), [Text.Encoding]::UTF8) | ConvertFrom-Csv
        if ($rows.Count -lt $s.Minimum) {
            throw "$($s.File) has only $($rows.Count) rows, expected at least $($s.Minimum). Probably an incomplete download."
        }
        foreach ($column in 'Assignment', 'Organization Name') {
            if (-not ($rows[0].PSObject.Properties.Name -contains $column)) {
                throw "$($s.File) has no column '$column'. The file format has changed."
            }
        }
        $countBefore = $entries.Count

        foreach ($row in $rows) {
            $prefix = ([string]$row.Assignment).Trim().ToUpperInvariant()
            if ($prefix.Length -ne $s.Length -or $prefix -notmatch '^[0-9A-F]+$') {
                throw "$($s.File): unexpected assignment '$prefix'"
            }

            # Control characters would break the line format. The list comes from outside, so don't trust it.
            # A few names also arrive with HTML entities, like "R&amp;M AG".
            $decoded = [System.Net.WebUtility]::HtmlDecode([string]$row.'Organization Name')
            $name = ([regex]::Replace($decoded, '[\x00-\x1F\x7F]+', ' ') -replace '\s+', ' ').Trim()

            # These say nothing about who made the device. The registration authority owns the blocks that
            # are subdivided into MA-M and MA-S ranges, so those get their real name from the longer prefix.
            if ($name.Length -eq 0 -or $name -ieq 'Private' -or $name -like 'IEEE Registration Authority*') {
                $dropped++
                continue
            }

            # A few very old prefixes were assigned more than once. Keep a stable choice between runs.
            if ($entries.ContainsKey($prefix)) {
                $duplicates++
                if ([string]::CompareOrdinal($name, $entries[$prefix]) -ge 0) { continue }
            }
            $entries[$prefix] = $name
        }

        # Real rows without a usable name are rare, so a list that lost most of them is broken somehow.
        if ($entries.Count - $countBefore -lt $s.Minimum) {
            throw "$($s.File) gave only $($entries.Count - $countBefore) named entries, expected at least $($s.Minimum)."
        }
    }

    $builder = New-Object Text.StringBuilder
    foreach ($pair in $entries.GetEnumerator()) {
        [void]$builder.Append($pair.Key).Append("`t").Append($pair.Value).Append("`n")
    }
    $bytes = (New-Object Text.UTF8Encoding $false).GetBytes($builder.ToString())

    $outPath = [IO.Path]::GetFullPath($OutFile)
    New-Item -ItemType Directory -Force -Path (Split-Path $outPath) | Out-Null
    $tmp = "$outPath.tmp"
    $file = [IO.File]::Create($tmp)
    try {
        $gzip = New-Object IO.Compression.GZipStream $file, ([IO.Compression.CompressionLevel]::Optimal)
        $gzip.Write($bytes, 0, $bytes.Length)
        $gzip.Dispose()
    } finally {
        $file.Dispose()
    }
    Move-Item -Force $tmp $outPath

    "Eintraege: $($entries.Count), ohne Namen verworfen: $dropped, doppelt: $duplicates"
    "Datei: $outPath ($([math]::Round((Get-Item $outPath).Length / 1KB)) KB, entpackt $([math]::Round($bytes.Length / 1MB, 1)) MB)"
}
finally {
    if ($tempDir) { Remove-Item -Recurse -Force $tempDir }
}
