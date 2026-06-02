param(
    [ValidateSet("add", "delete")]
    [string]$Action = "",

    [string]$AllowedRemoteAddress = $env:WAZUH_MANAGER_IP
)

$ErrorActionPreference = "Stop"
$ScriptName = "isolate-host.ps1"
$AgentRoot = "C:\Program Files (x86)\ossec-agent"
$LogFile = Join-Path $AgentRoot "active-response\active-responses.log"
$StateDir = Join-Path $AgentRoot "active-response\state"
$StateFile = Join-Path $StateDir "isolate-host-firewall-state.json"
$RulePrefix = "Wazuh-Isolation"

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
        # Brak logu nie moze zatrzymac reakcji na incydent.
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

function Save-FirewallState {
    if (-not (Test-Path -LiteralPath $StateDir)) {
        New-Item -Path $StateDir -ItemType Directory -Force | Out-Null
    }

    if (Test-Path -LiteralPath $StateFile) {
        Write-Log "state file already exists, keeping previous firewall baseline"
        return
    }

    # Zapisujemy tylko ustawienia, ktore modyfikujemy, aby delete mogl je odtworzyc.
    $profiles = Get-NetFirewallProfile -Profile Domain,Private,Public |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

    $profiles | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $StateFile -Encoding UTF8
    Write-Log "firewall state saved path=$StateFile"
}

function Restore-FirewallState {
    if (-not (Test-Path -LiteralPath $StateFile)) {
        Write-Log "state file missing, restoring conservative defaults"
        Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow | Out-Null
        return
    }

    $profiles = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json -ErrorAction Stop
    foreach ($profile in @($profiles)) {
        Set-NetFirewallProfile `
            -Profile $profile.Name `
            -Enabled ([bool]$profile.Enabled) `
            -DefaultInboundAction $profile.DefaultInboundAction `
            -DefaultOutboundAction $profile.DefaultOutboundAction | Out-Null
    }

    Remove-Item -LiteralPath $StateFile -Force -ErrorAction SilentlyContinue
    Write-Log "firewall state restored"
}

function Remove-IsolationRules {
    Get-NetFirewallRule -DisplayName "$RulePrefix*" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

function Add-AllowRule {
    param(
        [string]$Name,
        [string]$Direction,
        [string]$Program = "",
        [string]$RemoteAddress = ""
    )

    if (Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue) {
        return
    }

    $params = @{
        DisplayName = $Name
        Direction = $Direction
        Action = "Allow"
        Enabled = "True"
        Profile = "Any"
    }

    if (-not [string]::IsNullOrWhiteSpace($Program)) {
        $params.Program = $Program
    }
    if (-not [string]::IsNullOrWhiteSpace($RemoteAddress)) {
        $params.RemoteAddress = $RemoteAddress
    }

    New-NetFirewallRule @params | Out-Null
}

try {
    $payload = Read-WazuhPayload

    if ([string]::IsNullOrWhiteSpace($Action)) {
        $Action = Get-PropertyValue -Object $payload -Paths @("command", "parameters.command")
    }
    if ([string]::IsNullOrWhiteSpace($Action)) {
        $Action = "add"
    }

    Write-Log "started action=$Action allowed_remote=$AllowedRemoteAddress"

    if ($Action -eq "add") {
        Save-FirewallState
        Remove-IsolationRules

        # Nie dodajemy reguly "block all", bo w Windows reguly block maja priorytet
        # nad allow. Izolacja opiera sie na DefaultOutboundAction=Block.
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block | Out-Null

        Add-AllowRule -Name "$RulePrefix-Allow-Loopback-Out" -Direction Outbound -RemoteAddress "127.0.0.1,::1"

        $wazuhSvc = Join-Path $AgentRoot "wazuh-agent.exe"
        if (Test-Path -LiteralPath $wazuhSvc) {
            Add-AllowRule -Name "$RulePrefix-Allow-Wazuh-Agent-Out" -Direction Outbound -Program $wazuhSvc -RemoteAddress $AllowedRemoteAddress
        }

        Write-Log "host isolated"
        exit 0
    }

    if ($Action -eq "delete") {
        Remove-IsolationRules
        Restore-FirewallState
        Write-Log "host de-isolated"
        exit 0
    }

    Write-Log "unsupported action=$Action"
    exit 1
}
catch {
    Write-Log "error $($_.Exception.Message)"
    exit 1
}
