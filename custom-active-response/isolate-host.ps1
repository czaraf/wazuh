param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("add","delete")]
    [string]$Action,

    [string]$SrcIP = ""
)

$LogFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts isolate-host.ps1 $Message"
}

try {
    Write-Log "started action=$Action srcip=$SrcIP"

    $ruleNameV4In  = "Wazuh-Isolation-In-V4"
    $ruleNameV4Out = "Wazuh-Isolation-Out-V4"
    $ruleNameV6In  = "Wazuh-Isolation-In-V6"
    $ruleNameV6Out = "Wazuh-Isolation-Out-V6"

    if ($Action -eq "add") {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block | Out-Null

        if (-not (Get-NetFirewallRule -DisplayName $ruleNameV4In -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleNameV4In -Direction Inbound -Action Block -Enabled True -Profile Any -Protocol Any | Out-Null
        }
        if (-not (Get-NetFirewallRule -DisplayName $ruleNameV4Out -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleNameV4Out -Direction Outbound -Action Block -Enabled True -Profile Any -Protocol Any | Out-Null
        }
        if (-not (Get-NetFirewallRule -DisplayName $ruleNameV6In -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleNameV6In -Direction Inbound -Action Block -Enabled True -Profile Any -Protocol Any | Out-Null
        }
        if (-not (Get-NetFirewallRule -DisplayName $ruleNameV6Out -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleNameV6Out -Direction Outbound -Action Block -Enabled True -Profile Any -Protocol Any | Out-Null
        }

        Write-Log "host isolated"
    }
    elseif ($Action -eq "delete") {
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Allow -DefaultOutboundAction Allow | Out-Null

        Get-NetFirewallRule -DisplayName $ruleNameV4In,$ruleNameV4Out,$ruleNameV6In,$ruleNameV6Out -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

        Write-Log "host de-isolated"
    }

    Write-Log "finished action=$Action"
    exit 0
}
catch {
    Write-Log "error $($_.Exception.Message)"
    exit 1
}
