param(
    [ValidateSet("add", "delete")]
    [string]$Action = "",

    [int]$DelaySeconds = 30,

    [string]$Reason = "Wazuh Active Response requested host shutdown"
)

$ErrorActionPreference = "Stop"
$ScriptName = "shutdown-host.ps1"
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
        # Logowanie jest pomocnicze; nie powinno zmieniac wyniku reakcji.
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

try {
    $payload = Read-WazuhPayload

    if ([string]::IsNullOrWhiteSpace($Action)) {
        $Action = Get-PropertyValue -Object $payload -Paths @("command", "parameters.command")
    }
    if ([string]::IsNullOrWhiteSpace($Action)) {
        $Action = "add"
    }

    Write-Log "started action=$Action delay=$DelaySeconds"

    if ($Action -eq "delete") {
        # Jezeli kiedys wlaczysz timeout dla tej reakcji, delete anuluje pending shutdown.
        shutdown.exe /a | Out-Null
        Write-Log "pending shutdown aborted"
        exit 0
    }

    if ($Action -ne "add") {
        Write-Log "unsupported action=$Action"
        exit 1
    }

    if ($DelaySeconds -lt 0) {
        $DelaySeconds = 0
    }

    # shutdown.exe daje czytelny komentarz w logach systemowych i wspiera opoznienie.
    $safeReason = $Reason
    if ($safeReason.Length -gt 512) {
        $safeReason = $safeReason.Substring(0, 512)
    }

    shutdown.exe /s /f /t $DelaySeconds /d p:4:1 /c $safeReason | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "shutdown.exe failed with exit code $LASTEXITCODE"
    }

    Write-Log "shutdown scheduled delay=$DelaySeconds"
    exit 0
}
catch {
    Write-Log "error $($_.Exception.Message)"
    exit 1
}
