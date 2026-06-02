param(
    [ValidateSet("add","delete")]
    [string]$Action = "add"
)

$LogFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts shutdown-host.ps1 $Message"
}

try {
    Write-Log "started action=$Action"

    if ($Action -eq "add") {
        Stop-Computer -Force
    }

    Write-Log "finished action=$Action"
    exit 0
}
catch {
    Write-Log "error $($_.Exception.Message)"
    exit 1
}