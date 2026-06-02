param(
    [ValidateSet("add", "delete")]
    [string]$Action = "",

    [string]$CaseId = "",

    [string]$OutputRoot = "C:\Program Files (x86)\ossec-agent\active-response\forensics",

    [switch]$NoArchive
)

# Active Response: zbiera lekki pakiet dowodowy bez zmiany konfiguracji hosta.
# Nie izoluje, nie usuwa plikow i nie zatrzymuje procesow.
$ErrorActionPreference = "Stop"
$ScriptName = "collect-forensics.ps1"
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

function Write-JsonFile {
    param([string]$Path, [object]$Value, [int]$Depth = 6)
    # Kazdy etap kolekcji ma byc odporny na blad pojedynczego zrodla danych.
    try {
        $Value | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $Path -Encoding UTF8
    }
    catch {
        "error: $($_.Exception.Message)" | Set-Content -LiteralPath $Path -Encoding UTF8
    }
}

function Write-TextCommand {
    param([string]$Path, [scriptblock]$Command)
    try {
        & $Command | Out-String -Width 4096 | Set-Content -LiteralPath $Path -Encoding UTF8
    }
    catch {
        "error: $($_.Exception.Message)" | Set-Content -LiteralPath $Path -Encoding UTF8
    }
}

try {
    $payload = Read-WazuhPayload

    if ([string]::IsNullOrWhiteSpace($Action)) {
        $Action = Get-PropertyValue -Object $payload -Paths @("command", "parameters.command")
    }
    if ([string]::IsNullOrWhiteSpace($Action)) {
        $Action = "add"
    }

    if ($Action -eq "delete") {
        Write-Log "delete ignored"
        exit 0
    }
    if ($Action -ne "add") {
        Write-Log "unsupported action=$Action"
        exit 1
    }

    if ([string]::IsNullOrWhiteSpace($CaseId)) {
        $ruleId = Get-PropertyValue -Object $payload -Paths @("parameters.alert.rule.id", "parameters.alert.rule.id")
        $CaseId = "wazuh_{0}_{1}" -f (Get-Date -Format "yyyyMMddHHmmss"), ($ruleId -replace "[^0-9A-Za-z_-]", "")
    }
    $CaseId = $CaseId -replace "[^0-9A-Za-z_.-]", "_"

    $caseDir = Join-Path $OutputRoot $CaseId
    New-Item -Path $caseDir -ItemType Directory -Force | Out-Null

    Write-Log "started case=$CaseId dir=$caseDir"

    Write-JsonFile -Path (Join-Path $caseDir "wazuh-payload.json") -Value $payload -Depth 20

    # Snapshot systemu i artefaktow triage. To ma byc szybkie i bezpieczne dla endpointa.
    Write-JsonFile -Path (Join-Path $caseDir "system.json") -Value ([ordered]@{
        collected_at = (Get-Date).ToString("o")
        computer_name = $env:COMPUTERNAME
        user_name = $env:USERNAME
        os = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, LastBootUpTime)
        bios = (Get-CimInstance Win32_BIOS | Select-Object SerialNumber, SMBIOSBIOSVersion)
    }) -Depth 8

    Write-JsonFile -Path (Join-Path $caseDir "processes.json") -Value (
        Get-CimInstance Win32_Process |
            Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, CreationDate
    ) -Depth 5

    Write-JsonFile -Path (Join-Path $caseDir "services.json") -Value (
        Get-CimInstance Win32_Service |
            Select-Object Name, DisplayName, State, StartMode, PathName, StartName
    ) -Depth 5

    Write-JsonFile -Path (Join-Path $caseDir "tcp-connections.json") -Value (
        Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
    ) -Depth 5

    Write-JsonFile -Path (Join-Path $caseDir "udp-endpoints.json") -Value (
        Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
            Select-Object LocalAddress, LocalPort, OwningProcess
    ) -Depth 5

    Write-JsonFile -Path (Join-Path $caseDir "scheduled-tasks.json") -Value (
        Get-ScheduledTask -ErrorAction SilentlyContinue |
            Select-Object TaskName, TaskPath, State, Author, Description
    ) -Depth 5

    Write-JsonFile -Path (Join-Path $caseDir "local-users.json") -Value (
        Get-LocalUser -ErrorAction SilentlyContinue |
            Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet
    ) -Depth 5

    Write-TextCommand -Path (Join-Path $caseDir "ipconfig.txt") -Command { ipconfig.exe /all }
    Write-TextCommand -Path (Join-Path $caseDir "netstat.txt") -Command { netstat.exe -ano }
    Write-TextCommand -Path (Join-Path $caseDir "route-print.txt") -Command { route.exe print }
    Write-TextCommand -Path (Join-Path $caseDir "dns-cache.txt") -Command { Get-DnsClientCache -ErrorAction SilentlyContinue }

    $startupRoots = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    # Klasyczne Run/RunOnce to szybki pierwszy widok na persistence w Windows.
    $startup = foreach ($root in $startupRoots) {
        if (Test-Path -LiteralPath $root) {
            Get-ItemProperty -LiteralPath $root | Select-Object *, @{Name="RegistryPath"; Expression={ $root }}
        }
    }
    Write-JsonFile -Path (Join-Path $caseDir "autoruns-runkeys.json") -Value $startup -Depth 5

    if (-not $NoArchive) {
        $zip = "$caseDir.zip"
        Compress-Archive -LiteralPath (Join-Path $caseDir "*") -DestinationPath $zip -Force
        Write-Log "forensics archive created path=$zip"
    }

    Write-Log "finished case=$CaseId"
    exit 0
}
catch {
    Write-Log "error $($_.Exception.Message)"
    exit 1
}
