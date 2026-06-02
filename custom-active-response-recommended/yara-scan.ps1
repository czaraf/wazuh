param(
    [ValidateSet("add", "delete")]
    [string]$Action = "",

    [string]$TargetPath = "",

    [string]$YaraExe = "",

    [string]$RulesPath = "",

    [switch]$QuarantineOnMatch
)

# Active Response: uruchamia YARA na pliku wskazanym przez alert.
# Domyslnie tylko loguje wynik; kwarantanna jest wlaczana jawnie przez -QuarantineOnMatch.
$ErrorActionPreference = "Stop"
$ScriptName = "yara-scan.ps1"
$AgentRoot = "C:\Program Files (x86)\ossec-agent"
$LogFile = Join-Path $AgentRoot "active-response\active-responses.log"
$QuarantineDir = Join-Path $AgentRoot "active-response\quarantine"

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
    catch {}
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
    return Get-PropertyValue -Object $Payload -Paths @(
        "parameters.alert.syscheck.path",
        "parameters.alert.data.syscheck.path",
        "parameters.alert.data.path",
        "parameters.alert.data.file",
        "parameters.alert.data.win.eventdata.targetFilename",
        "parameters.alert.win.eventdata.targetFilename"
    )
}

function Resolve-YaraExe {
    param([string]$Preferred)

    # Preferujemy sciezke z parametru, potem pliki lezace obok skryptu w active-response\bin.
    $candidates = @(
        $Preferred,
        (Join-Path $PSScriptRoot "yara64.exe"),
        (Join-Path $PSScriptRoot "yara.exe"),
        (Join-Path $AgentRoot "active-response\bin\yara64.exe"),
        (Join-Path $AgentRoot "active-response\bin\yara.exe")
    ) | Where-Object { $_ }

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }

    return $null
}

function Resolve-RulesPath {
    param([string]$Preferred)

    # Reguly YARA trzymaj w katalogu yara-rules obok skryptu albo przekaz -RulesPath.
    $candidates = @(
        $Preferred,
        (Join-Path $PSScriptRoot "yara-rules"),
        (Join-Path $AgentRoot "active-response\bin\yara-rules")
    ) | Where-Object { $_ }

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    return $null
}

function Move-ToQuarantine {
    param([string]$Path)

    # Prosta kwarantanna lokalna: plik + metadane JSON z hashem i sciezka pierwotna.
    if (-not (Test-Path -LiteralPath $QuarantineDir)) {
        New-Item -Path $QuarantineDir -ItemType Directory -Force | Out-Null
    }

    $fullPath = [IO.Path]::GetFullPath($Path)
    $hash = Get-FileHash -LiteralPath $fullPath -Algorithm SHA256
    $safeName = ([IO.Path]::GetFileName($fullPath) -replace "[:\\\/\*\?`"<>|]", "_")
    $dest = Join-Path $QuarantineDir ("yara_{0}_{1}_{2}" -f (Get-Date -Format "yyyyMMddHHmmss"), $hash.Hash.Substring(0, 12), $safeName)

    Move-Item -LiteralPath $fullPath -Destination $dest -Force
    [ordered]@{
        original_path = $fullPath
        quarantine_path = $dest
        sha256 = $hash.Hash
        quarantined_at = (Get-Date).ToString("o")
        reason = "yara-match"
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath "$dest.json" -Encoding UTF8

    return $dest
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

    Write-Log "started action=$Action target=$TargetPath quarantine_on_match=$QuarantineOnMatch"

    if ($Action -eq "delete") {
        Write-Log "delete ignored"
        exit 0
    }

    if ($Action -ne "add") {
        Write-Log "unsupported action=$Action"
        exit 1
    }

    if ([string]::IsNullOrWhiteSpace($TargetPath) -or -not (Test-Path -LiteralPath $TargetPath -PathType Leaf)) {
        Write-Log "target file not found path=$TargetPath"
        exit 0
    }

    $resolvedYara = Resolve-YaraExe -Preferred $YaraExe
    if ([string]::IsNullOrWhiteSpace($resolvedYara)) {
        Write-Log "yara executable not found"
        exit 1
    }

    $resolvedRules = Resolve-RulesPath -Preferred $RulesPath
    if ([string]::IsNullOrWhiteSpace($resolvedRules)) {
        Write-Log "yara rules path not found"
        exit 1
    }

    # Different YARA builds/wrappers are not always used consistently in playbooks,
    # so match detection is based on non-empty stdout/stderr output first.
    $output = & $resolvedYara -r $resolvedRules $TargetPath 2>&1
    $code = $LASTEXITCODE
    $joined = ($output | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) -join " | "

    if (-not [string]::IsNullOrWhiteSpace($joined)) {
        Write-Log "yara match target=$TargetPath result=$joined"
        if ($QuarantineOnMatch) {
            $dest = Move-ToQuarantine -Path $TargetPath
            Write-Log "matched file quarantined dest=$dest"
        }
        exit 0
    }

    if ($code -eq 0) {
        Write-Log "no yara match target=$TargetPath"
        exit 0
    }

    Write-Log "yara failed exitcode=$code"
    exit 1
}
catch {
    Write-Log "error $($_.Exception.Message)"
    exit 1
}
