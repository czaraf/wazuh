param(
    [ValidateSet("add", "delete")]
    [string]$Action = "",

    [string]$UserName = "",

    [string]$AllowListFile = "",

    [string]$ProtectedNamePattern = "^(administrator|admin|krbtgt|guest|wazuh|svc_|service_|sql_|backup_|aad_|azuread)",

    [switch]$EnableOnDelete
)

# Active Response: wylacza konto AD wskazane w alercie.
# Uruchamiaj tylko na zaufanym agencie administracyjnym z RSAT ActiveDirectory
# i uprawnieniami delegowanymi do disable account.
$ErrorActionPreference = "Stop"
$ScriptName = "disable-ad-account.ps1"
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

function Normalize-UserName {
    param([string]$Value)

    # Alerty moga zawierac DOMAIN\user albo user@domain; AD cmdlet potrzebuje samAccountName/identity.
    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ""
    }

    $name = $Value.Trim()
    if ($name -match "\\") {
        $name = ($name -split "\\")[-1]
    }
    if ($name -match "@") {
        $name = ($name -split "@")[0]
    }

    return ($name -replace "[`"`']", "")
}

function Get-AlertUserName {
    param([object]$Payload)

    return Get-PropertyValue -Object $Payload -Paths @(
        "parameters.alert.data.win.eventdata.targetUserName",
        "parameters.alert.data.win.eventdata.subjectUserName",
        "parameters.alert.data.win.eventdata.user",
        "parameters.alert.data.dstuser",
        "parameters.alert.data.srcuser",
        "parameters.alert.data.user",
        "parameters.alert.syscheck.uname",
        "parameters.alert.user.name"
    )
}

function Get-AllowList {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = Join-Path $PSScriptRoot "disable-ad-account-allowlist"
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    return @(Get-Content -LiteralPath $Path |
        ForEach-Object { $_.Trim().ToLowerInvariant() } |
        Where-Object { $_ -and -not $_.StartsWith("#") })
}

function Test-ProtectedAccount {
    param([string]$Name)

    # Ochrona przed wylaczeniem kont wbudowanych, maszynowych i typowych kont uslugowych.
    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $true
    }
    if ($Name.EndsWith("$")) {
        return $true
    }
    if ($Name -match $ProtectedNamePattern) {
        return $true
    }

    $allowList = Get-AllowList -Path $AllowListFile
    return ($allowList -contains $Name.ToLowerInvariant())
}

try {
    $payload = Read-WazuhPayload

    if ([string]::IsNullOrWhiteSpace($Action)) {
        $Action = Get-PropertyValue -Object $payload -Paths @("command", "parameters.command")
    }
    if ([string]::IsNullOrWhiteSpace($Action)) {
        $Action = "add"
    }

    if ([string]::IsNullOrWhiteSpace($UserName)) {
        $UserName = Get-AlertUserName -Payload $payload
    }
    $UserName = Normalize-UserName -Value $UserName

    Write-Log "started action=$Action user=$UserName"

    if ([string]::IsNullOrWhiteSpace($UserName)) {
        Write-Log "no username found in arguments or Wazuh payload"
        exit 0
    }

    if (Test-ProtectedAccount -Name $UserName) {
        Write-Log "protected account ignored user=$UserName"
        exit 0
    }

    Import-Module ActiveDirectory -ErrorAction Stop
    $adUser = Get-ADUser -Identity $UserName -Properties Enabled, SamAccountName, DistinguishedName -ErrorAction Stop

    if ($Action -eq "delete") {
        if (-not $EnableOnDelete) {
            Write-Log "delete ignored enable_on_delete=false user=$UserName"
            exit 0
        }

        Enable-ADAccount -Identity $adUser.DistinguishedName -ErrorAction Stop
        Write-Log "enabled ad account user=$($adUser.SamAccountName)"
        exit 0
    }

    if ($Action -ne "add") {
        Write-Log "unsupported action=$Action"
        exit 1
    }

    if (-not $adUser.Enabled) {
        Write-Log "account already disabled user=$($adUser.SamAccountName)"
        exit 0
    }

    Disable-ADAccount -Identity $adUser.DistinguishedName -ErrorAction Stop
    Write-Log "disabled ad account user=$($adUser.SamAccountName)"
    exit 0
}
catch {
    Write-Log "error $($_.Exception.Message)"
    exit 1
}
