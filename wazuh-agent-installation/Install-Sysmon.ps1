#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Idempotentna instalacja Sysmon z konfiguracja SwiftOnSecurity.
.DESCRIPTION
    Skrypt instaluje lub aktualizuje Sysmon, zabezpiecza katalog instalacyjny,
    weryfikuje podpis Sysmon64.exe, opcjonalnie sprawdza hashe pobranych plikow
    i dodaje kanal Sysmon do ossec.conf agenta Wazuh.
.NOTES
    Wymaga uprawnien administratora.
    Wazuh Agent powinien byc zainstalowany przed uruchomieniem tego skryptu.
#>

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$SysmonDir = "C:\Sysmon",

    [ValidateNotNullOrEmpty()]
    [string]$SysmonZipUrl = "https://download.sysinternals.com/files/Sysmon.zip",

    [ValidateNotNullOrEmpty()]
    [string]$SysmonConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml",

    [string]$ExpectedSysmonZipSha256 = "",
    [string]$ExpectedConfigSha256 = "",

    [ValidateNotNullOrEmpty()]
    [string]$WazuhAgentDir = "${env:ProgramFiles(x86)}\ossec-agent",

    [switch]$KeepDownloads,
    [switch]$SkipSignatureCheck
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$SYSMON_ZIP = Join-Path $SysmonDir "Sysmon.zip"
$SYSMON_EXE = Join-Path $SysmonDir "Sysmon64.exe"
$SYSMON_CFG = Join-Path $SysmonDir "sysmonconfig.xml"
$SYSMON_SVC = "Sysmon64"
$OSSEC_CONF = Join-Path $WazuhAgentDir "ossec.conf"
$WAZUH_SVC = "WazuhSvc"
$SYSMON_EVENTCHANNEL = "Microsoft-Windows-Sysmon/Operational"

function Write-Done {
    param([string]$Message)
    Write-Host "[" -NoNewline
    Write-Host "DONE" -ForegroundColor Green -NoNewline
    Write-Host "] $Message"
}

function Write-Skip {
    param([string]$Message)
    Write-Host "[" -NoNewline
    Write-Host "SKIP" -ForegroundColor Yellow -NoNewline
    Write-Host "] $Message"
}

function Write-Step {
    param([string]$Message)
    Write-Host "`n>>> $Message" -ForegroundColor Cyan
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Test-Administrator {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-DirectoryIfMissing {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
        Write-Done "Katalog utworzony: $Path"
    } else {
        Write-Skip "Katalog juz istnieje: $Path"
    }
}

function Set-SecureDirectoryAcl {
    param([string]$Path)

    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)

    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow

    foreach ($sidString in @("S-1-5-18", "S-1-5-32-544")) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidString)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $rights, $inheritance, $propagation, $allow)
        $acl.AddAccessRule($rule)
    }

    Set-Acl -LiteralPath $Path -AclObject $acl
    Write-Done "ACL katalogu ograniczone do SYSTEM i Administrators."
}

function Receive-FileIfMissing {
    param(
        [string]$Uri,
        [string]$Destination
    )

    if (Test-Path -LiteralPath $Destination) {
        Write-Skip "Plik juz istnieje: $Destination - pomijam pobieranie."
        return $false
    }

    $destinationDir = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $destinationDir)) {
        New-Item -ItemType Directory -Force -Path $destinationDir | Out-Null
    }

    $partial = "$Destination.download"
    if (Test-Path -LiteralPath $partial) {
        Remove-Item -LiteralPath $partial -Force
    }

    Write-Host "    Pobieranie z: $Uri"
    Invoke-WebRequest -Uri $Uri -OutFile $partial -UseBasicParsing
    Move-Item -LiteralPath $partial -Destination $Destination -Force
    Write-Done "Plik pobrany: $Destination"
    return $true
}

function Assert-FileHashSha256 {
    param(
        [string]$Path,
        [string]$ExpectedSha256,
        [string]$Label
    )

    if ([string]::IsNullOrWhiteSpace($ExpectedSha256)) {
        Write-Warn "Brak oczekiwanego SHA256 dla: $Label. Weryfikacja hash zostala pominieta."
        return
    }

    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actual -ne $ExpectedSha256) {
        throw "Nieprawidlowy SHA256 dla '$Path'. Oczekiwano $ExpectedSha256, otrzymano $actual."
    }

    Write-Done "Hash SHA256 poprawny: $Label"
}

function Assert-AuthenticodeSignature {
    param(
        [string]$Path,
        [string]$ExpectedSubjectContains
    )

    if ($SkipSignatureCheck) {
        Write-Warn "Pominieto weryfikacje podpisu Authenticode dla: $Path"
        return
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid') {
        throw "Podpis Authenticode dla '$Path' nie jest poprawny. Status: $($signature.Status)."
    }

    if ($ExpectedSubjectContains -and $signature.SignerCertificate.Subject -notlike "*$ExpectedSubjectContains*") {
        throw "Podpis '$Path' jest poprawny, ale wystawca nie zawiera '$ExpectedSubjectContains'. Wystawca: $($signature.SignerCertificate.Subject)"
    }

    Write-Done "Podpis Authenticode poprawny: $($signature.SignerCertificate.Subject)"
}

function Assert-XmlFile {
    param(
        [string]$Path,
        [string]$Label
    )

    $xml = New-Object System.Xml.XmlDocument
    $xml.PreserveWhitespace = $true
    $xml.Load($Path)
    Write-Done "XML poprawny: $Label"
}

function Test-SysmonService {
    return $null -ne (Get-Service -Name $SYSMON_SVC -ErrorAction SilentlyContinue)
}

function Invoke-Sysmon {
    param([string[]]$Arguments)

    $output = & $SYSMON_EXE @Arguments 2>&1
    $exitCode = $LASTEXITCODE

    if ($output) {
        foreach ($line in $output) {
            Write-Host "    $line"
        }
    }

    if ($exitCode -ne 0) {
        throw "Sysmon64.exe zakonczyl dzialanie bledem. Kod: $exitCode. Argumenty: $($Arguments -join ' ')"
    }
}

function Start-ServiceIfNeeded {
    param([string]$Name)

    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) {
        throw "Usluga $Name nie istnieje."
    }

    if ($svc.Status -eq 'Running') {
        Write-Skip "Usluga $Name juz dziala (Status: $($svc.Status))."
        return
    }

    Start-Service -Name $Name
    $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    Write-Done "Usluga $Name uruchomiona."
}

function New-Backup {
    param([string]$Path)

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupPath = "$Path.bak-$timestamp"
    Copy-Item -LiteralPath $Path -Destination $backupPath -Force
    Write-Done "Utworzono backup: $backupPath"
    return $backupPath
}

function Get-OssecXml {
    param([string]$Path)

    $xml = New-Object System.Xml.XmlDocument
    $xml.PreserveWhitespace = $true
    $xml.Load($Path)
    return $xml
}

function Save-XmlDocument {
    param(
        [System.Xml.XmlDocument]$Xml,
        [string]$Path
    )

    $tempPath = "$Path.tmp"
    $Xml.Save($tempPath)
    Move-Item -LiteralPath $tempPath -Destination $Path -Force
}

function Test-SysmonLocalfileExists {
    param([System.Xml.XmlDocument]$Xml)

    $localfiles = $Xml.SelectNodes('/ossec_config/localfile')
    foreach ($localfile in $localfiles) {
        $location = $localfile.SelectSingleNode('location')
        $format = $localfile.SelectSingleNode('log_format')
        if ($location -and $format -and
            $location.InnerText -eq $SYSMON_EVENTCHANNEL -and
            $format.InnerText -eq 'eventchannel') {
            return $true
        }
    }

    return $false
}

function Add-SysmonLocalfileToOssec {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Warn "Plik $Path nie istnieje - czy Wazuh Agent jest zainstalowany?"
        Write-Skip "Pomijam konfiguracje Wazuh."
        return $false
    }

    $xml = Get-OssecXml -Path $Path
    $root = $xml.SelectSingleNode('/ossec_config')
    if (-not $root) {
        throw "Nie znaleziono elementu /ossec_config w $Path."
    }

    if (Test-SysmonLocalfileExists -Xml $xml) {
        Write-Skip "Wpis Sysmon/Operational juz istnieje w ossec.conf - brak zmian."
        return $false
    }

    New-Backup -Path $Path | Out-Null

    $localfile = $xml.CreateElement('localfile')
    $location = $xml.CreateElement('location')
    $logFormat = $xml.CreateElement('log_format')

    $location.InnerText = $SYSMON_EVENTCHANNEL
    $logFormat.InnerText = 'eventchannel'

    [void]$localfile.AppendChild($location)
    [void]$localfile.AppendChild($logFormat)
    [void]$root.AppendChild($localfile)

    Save-XmlDocument -Xml $xml -Path $Path
    Write-Done "Wpis Sysmon dodany do ossec.conf."
    return $true
}

function Restart-WazuhIfNeeded {
    param([bool]$Changed)

    if (-not $Changed) {
        Write-Skip "ossec.conf nie byl modyfikowany - pomijam restart WazuhSvc."
        return
    }

    $wazuhSvc = Get-Service -Name $WAZUH_SVC -ErrorAction SilentlyContinue
    if (-not $wazuhSvc) {
        Write-Warn "Usluga $WAZUH_SVC nie istnieje - pomijam restart."
        return
    }

    Restart-Service -Name $WAZUH_SVC -Force
    $wazuhSvc = Get-Service -Name $WAZUH_SVC
    $wazuhSvc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    Write-Done "WazuhSvc zrestartowany pomyslnie (Status: $($wazuhSvc.Status))."
}

Write-Step "Sprawdzanie uprawnien administratora..."
if (-not (Test-Administrator)) {
    throw "Skrypt musi byc uruchomiony jako Administrator."
}
Write-Done "Uprawnienia administratora potwierdzone."

Write-Step "Sprawdzanie katalogu $SysmonDir..."
New-DirectoryIfMissing -Path $SysmonDir
Set-SecureDirectoryAcl -Path $SysmonDir

Write-Step "Sprawdzanie pliku Sysmon.zip..."
$downloadedZip = Receive-FileIfMissing -Uri $SysmonZipUrl -Destination $SYSMON_ZIP
Assert-FileHashSha256 -Path $SYSMON_ZIP -ExpectedSha256 $ExpectedSysmonZipSha256 -Label "Sysmon.zip"

Write-Step "Sprawdzanie Sysmon64.exe..."
if (Test-Path -LiteralPath $SYSMON_EXE) {
    Write-Skip "Sysmon64.exe juz istnieje - pomijam rozpakowywanie."
} else {
    Expand-Archive -Path $SYSMON_ZIP -DestinationPath $SysmonDir -Force
    Write-Done "Archiwum rozpakowane do: $SysmonDir"
}
Assert-AuthenticodeSignature -Path $SYSMON_EXE -ExpectedSubjectContains "Microsoft"

Write-Step "Sprawdzanie pliku konfiguracyjnego sysmonconfig.xml..."
$downloadedConfig = Receive-FileIfMissing -Uri $SysmonConfigUrl -Destination $SYSMON_CFG
Assert-FileHashSha256 -Path $SYSMON_CFG -ExpectedSha256 $ExpectedConfigSha256 -Label "sysmonconfig.xml"
Assert-XmlFile -Path $SYSMON_CFG -Label "sysmonconfig.xml"

Write-Step "Instalacja lub aktualizacja konfiguracji Sysmon..."
if (Test-SysmonService) {
    Write-Skip "Usluga Sysmon64 juz zainstalowana - aktualizuje konfiguracje."
    Invoke-Sysmon -Arguments @("-c", $SYSMON_CFG)
    Write-Done "Konfiguracja Sysmon zaktualizowana (-c)."
} else {
    Write-Host "    Instalowanie Sysmon64 z konfiguracja..."
    Invoke-Sysmon -Arguments @("-accepteula", "-i", $SYSMON_CFG)
    Start-Sleep -Seconds 3
    if (-not (Test-SysmonService)) {
        throw "Usluga Sysmon64 nie zostala zarejestrowana po instalacji."
    }
    Write-Done "Sysmon64 zainstalowany i usluga zarejestrowana."
}

Write-Step "Weryfikacja stanu uslugi Sysmon64..."
Start-ServiceIfNeeded -Name $SYSMON_SVC

Write-Step "Sprawdzanie konfiguracji Wazuh (ossec.conf)..."
$ossecChanged = Add-SysmonLocalfileToOssec -Path $OSSEC_CONF

Write-Step "Sprawdzanie czy wymagany restart Wazuh..."
Restart-WazuhIfNeeded -Changed $ossecChanged

Write-Step "Sprzatanie pobranych plikow..."
if (-not $KeepDownloads) {
    if ($downloadedZip -and (Test-Path -LiteralPath $SYSMON_ZIP)) {
        Remove-Item -LiteralPath $SYSMON_ZIP -Force
        Write-Done "Pobrany Sysmon.zip usuniety."
    }
    if (-not $downloadedZip -and -not $downloadedConfig) {
        Write-Skip "Brak pobranych plikow do sprzatniecia."
    }
} else {
    Write-Skip "KeepDownloads ustawiony - zostawiam pobrane pliki."
}

$finalSysmon = Get-Service -Name $SYSMON_SVC -ErrorAction SilentlyContinue
$finalWazuh = Get-Service -Name $WAZUH_SVC -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=======================================" -ForegroundColor Green
Write-Host "  Sysmon zainstalowany i dziala!" -ForegroundColor Green
Write-Host "  Sysmon64 : $($finalSysmon.Status)"
if ($finalWazuh) {
    Write-Host "  WazuhSvc  : $($finalWazuh.Status)"
}
Write-Host "  Katalog   : $SysmonDir"
Write-Host "  Config    : $SYSMON_CFG"
Write-Host "  Eventy    : eventvwr -> Applications and Services Logs"
Write-Host "              -> Microsoft -> Windows -> Sysmon -> Operational"
Write-Host "=======================================" -ForegroundColor Green
