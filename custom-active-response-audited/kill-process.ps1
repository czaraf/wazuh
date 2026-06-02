param(
    [ValidateSet("add", "delete")]
    [string]$Action = "",

    [int]$ProcessId = 0,

    [string]$WhitelistFile = ""
)

$ErrorActionPreference = "Stop"
$ScriptName = "kill-process.ps1"
$AgentRoot = "C:\Program Files (x86)\ossec-agent"
$LogFile = Join-Path $AgentRoot "active-response\active-responses.log"

function Write-Log {
    param([string]$Message)

    # Wazuh zbiera ten plik; nie przerywamy reakcji, jezeli logowanie zawiedzie.
    try {
        $dir = Split-Path -Parent $LogFile
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
        $ts = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
        Add-Content -LiteralPath $LogFile -Value "$ts $ScriptName $Message" -Encoding UTF8
    }
    catch {
        # Celowo puste: blad logowania nie powinien blokowac Active Response.
    }
}

function Read-WazuhPayload {
    # Wazuh custom Active Response zwykle przekazuje JSON przez stdin.
    # Zostawiamy tez obsluge parametrow CLI, zeby skrypt dalo sie testowac recznie.
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
    param(
        [object]$Object,
        [string[]]$Paths
    )

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
            return $current
        }
    }

    return $null
}

function Convert-ToProcessId {
    param([object]$Value)

    if ($null -eq $Value) {
        return 0
    }

    $text = "$Value".Trim()
    if ($text -match "^0x[0-9a-fA-F]+$") {
        return [Convert]::ToInt32($text, 16)
    }

    $pidValue = 0
    if ([int]::TryParse($text, [ref]$pidValue)) {
        return $pidValue
    }

    return 0
}

function Get-Whitelist {
    param([string]$Path)

    $defaultList = @(
        "powershell", "pwsh", "cmd", "explorer", "services", "svchost",
        "wmiprvse", "mmc", "lsass", "csrss", "wininit", "winlogon",
        "spoolsv", "wazuhsvc"
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = Join-Path $PSScriptRoot "kill-process-whitelist"
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Log "whitelist file not found, using built-in defaults path=$Path"
        return $defaultList
    }

    $items = Get-Content -LiteralPath $Path -ErrorAction Stop |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith("#") } |
        ForEach-Object { $_.ToLowerInvariant() -replace "\.exe$", "" }

    if (@($items).Count -eq 0) {
        Write-Log "whitelist file empty, using built-in defaults path=$Path"
        return $defaultList
    }

    return @($items)
}

try {
    $payload = Read-WazuhPayload

    if ([string]::IsNullOrWhiteSpace($Action)) {
        $Action = Get-PropertyValue -Object $payload -Paths @("command", "parameters.command")
    }
    if ([string]::IsNullOrWhiteSpace($Action)) {
        $Action = "add"
    }

    if ($ProcessId -le 0) {
        $ProcessId = Convert-ToProcessId (Get-PropertyValue -Object $payload -Paths @(
            "parameters.alert.data.win.eventdata.processId",
            "parameters.alert.data.win.eventdata.ProcessId",
            "parameters.alert.data.processId",
            "parameters.alert.data.pid",
            "parameters.alert.process.id",
            "parameters.alert.process.pid",
            "parameters.alert.sysmon.processId",
            "parameters.alert.win.eventdata.processId"
        ))
    }

    Write-Log "started action=$Action pid=$ProcessId whitelist=$WhitelistFile"

    if ($Action -eq "delete") {
        # Dla kill-process nie ma operacji cofania; timeout Wazuha moze wywolac delete.
        Write-Log "delete action ignored"
        exit 0
    }

    if ($Action -ne "add") {
        Write-Log "unsupported action=$Action"
        exit 1
    }

    if ($ProcessId -le 0) {
        Write-Log "no process id found in arguments or Wazuh payload"
        exit 0
    }

    if ($ProcessId -eq $PID) {
        Write-Log "refusing to kill current PowerShell process pid=$ProcessId"
        exit 0
    }

    $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $proc) {
        Write-Log "pid=$ProcessId not found"
        exit 0
    }

    $allowed = Get-Whitelist -Path $WhitelistFile
    $procName = $proc.ProcessName.ToLowerInvariant()
    if ($allowed -contains $procName) {
        Write-Log "pid=$ProcessId name=$($proc.ProcessName) whitelisted"
        exit 0
    }

    # Zamykamy tylko konkretny PID z alertu, a nie wszystkie procesy o tej nazwie.
    Stop-Process -Id $ProcessId -Force -ErrorAction Stop
    Write-Log "killed pid=$ProcessId name=$($proc.ProcessName)"

    Write-Log "finished action=$Action"
    exit 0
}
catch {
    Write-Log "error $($_.Exception.Message)"
    exit 1
}
