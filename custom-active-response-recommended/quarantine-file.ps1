param(
    [ValidateSet("add", "delete")]
    [string]$Action = "",

    [string]$TargetPath = "",

    [string]$QuarantineDir = "C:\Program Files (x86)\ossec-agent\active-response\quarantine",

    [switch]$RestoreOnDelete
)

# Active Response: przenosi podejrzany plik do lokalnej kwarantanny.
# Skrypt celowo nie przywraca pliku przy akcji delete, bo timeout Wazuha
# nie powinien automatycznie oddawac potencjalnego malware na pierwotne miejsce.
$ErrorActionPreference = "Stop"
$ScriptName = "quarantine-file.ps1"
$AgentRoot = "C:\Program Files (x86)\ossec-agent"
$LogFile = Join-Path $AgentRoot "active-response\active-responses.log"

function Write-Log {
    param([string]$Message)
    try {
        $dir = Split-Path -Parent $LogFile
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
        $ts = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
        Add-Content -LiteralPath $LogFile -Value "$ts $ScriptName $Message" -Encoding UTF8
    }
    catch {
        # Active Response should not fail only because logging failed.
    }
}

function Read-WazuhPayload {
    if (-not [Console]::IsInputRedirected) {
        return $null
    }

    $raw = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }

    try {
        return $raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Log "stdin was not valid JSON: $($_.Exception.Message)"
        return $null
    }
}

function Get-PropertyValue {
    param([object]$Object, [string[]]$Paths)

    foreach ($path in $Paths) {
        $current = $Object
        foreach ($part in ($path -split "\.")) {
            if ($null -eq $current) {
                break
            }
            $prop = $current.PSObject.Properties[$part]
            if ($null -eq $prop) {
                $current = $null
                break
            }
            $current = $prop.Value
        }
        if ($null -ne $current -and "$current" -ne "") {
            return "$current"
        }
    }

    return $null
}

function Get-AlertFilePath {
    param([object]$Payload)

    # Najczestsze pola z alertow FIM/Sysmon/Windows, w ktorych Wazuh trzyma sciezke pliku.
    return Get-PropertyValue -Object $Payload -Paths @(
        "parameters.alert.syscheck.path",
        "parameters.alert.data.syscheck.path",
        "parameters.alert.data.path",
        "parameters.alert.data.file",
        "parameters.alert.data.win.eventdata.targetFilename",
        "parameters.alert.win.eventdata.targetFilename"
    )
}

function Convert-ToSafeName {
    param([string]$Text)
    return ($Text -replace "[:\\\/\*\?`"<>|]", "_")
}

function Test-BlockedPath {
    param([string]$Path)

    # Nie ruszamy katalogow systemowych ani samego agenta, nawet jesli alert wskaze taki plik.
    $full = [IO.Path]::GetFullPath($Path)
    $blockedRoots = @(
        [Environment]::GetFolderPath("Windows"),
        [Environment]::GetFolderPath("System"),
        [Environment]::GetFolderPath("SystemX86"),
        $AgentRoot
    ) | Where-Object { $_ }

    foreach ($root in $blockedRoots) {
        $rootFull = [IO.Path]::GetFullPath($root)
        if ($full.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

try {
    $payload = Read-WazuhPayload

    if ([string]::IsNullOrWhiteSpace($Action)) {
        $Action = Get-PropertyValue -Object $payload -Paths @("command", "parameters.command")
    }
    if ([string]::IsNullOrWhiteSpace($Action)) {
        $Action = "add"
    }

    if ([string]::IsNullOrWhiteSpace($TargetPath)) {
        $TargetPath = Get-AlertFilePath -Payload $payload
    }

    Write-Log "started action=$Action target=$TargetPath"

    if ($Action -eq "delete") {
        # By default timeout cleanup must not restore malware. Use -RestoreOnDelete only in lab workflows.
        if (-not $RestoreOnDelete) {
            Write-Log "delete ignored restore_on_delete=false"
            exit 0
        }

        Write-Log "restore_on_delete requested but no quarantine id was provided"
        exit 0
    }

    if ($Action -ne "add") {
        Write-Log "unsupported action=$Action"
        exit 1
    }

    if ([string]::IsNullOrWhiteSpace($TargetPath)) {
        Write-Log "no target file found in arguments or Wazuh payload"
        exit 0
    }

    if (-not (Test-Path -LiteralPath $TargetPath -PathType Leaf)) {
        Write-Log "target file not found path=$TargetPath"
        exit 0
    }

    if (Test-BlockedPath -Path $TargetPath) {
        Write-Log "refusing to quarantine protected path=$TargetPath"
        exit 0
    }

    if (-not (Test-Path -LiteralPath $QuarantineDir)) {
        New-Item -Path $QuarantineDir -ItemType Directory -Force | Out-Null
    }

    $fullPath = [IO.Path]::GetFullPath($TargetPath)
    $hash = Get-FileHash -LiteralPath $fullPath -Algorithm SHA256
    $id = "{0}_{1}_{2}" -f (Get-Date -Format "yyyyMMddHHmmss"), $hash.Hash.Substring(0, 12), (Convert-ToSafeName -Text ([IO.Path]::GetFileName($fullPath)))
    $dest = Join-Path $QuarantineDir $id
    $meta = "$dest.json"

    $metadata = [ordered]@{
        original_path = $fullPath
        quarantine_path = $dest
        sha256 = $hash.Hash
        size = (Get-Item -LiteralPath $fullPath).Length
        quarantined_at = (Get-Date).ToString("o")
        source = "wazuh-active-response"
    }

    Move-Item -LiteralPath $fullPath -Destination $dest -Force
    $metadata | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $meta -Encoding UTF8

    Write-Log "quarantined original=$fullPath dest=$dest sha256=$($hash.Hash)"
    exit 0
}
catch {
    Write-Log "error $($_.Exception.Message)"
    exit 1
}
