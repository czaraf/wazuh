param(
    [ValidateSet("add","delete")]
    [string]$Action = "add",
    [int]$ProcessId = 0,
    [string]$WhitelistFile = "C:\Program Files (x86)\ossec-agent\active-response\bin\kill-process-whitelist.txt"
)

$LogFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$ts kill-process.ps1 $Message"
}

function Get-Whitelist {
    param([string]$Path)
    if (Test-Path $Path) {
        Get-Content $Path | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ }
    } else {
        @("powershell","pwsh","cmd","explorer","services","svchost")
    }
}

try {
    Write-Log "started action=$Action pid=$ProcessId whitelist=$WhitelistFile"

    if ($Action -eq "add" -and $ProcessId -gt 0) {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($null -eq $proc) {
            Write-Log "pid=$ProcessId not found"
            exit 0
        }

        $allowed = Get-Whitelist -Path $WhitelistFile
        $procName = $proc.ProcessName.ToLower()
        if ($allowed -contains $procName) {
            Write-Log "pid=$ProcessId name=$($proc.ProcessName) whitelisted"
            exit 0
        }

        Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
        Write-Log "killed pid=$ProcessId name=$($proc.ProcessName)"
    }

    Write-Log "finished action=$Action"
    exit 0
}
catch {
    Write-Log "error $($_.Exception.Message)"
    exit 1
}