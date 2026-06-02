#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Idempotentna instalacja agenta Wazuh na systemie Windows.
.DESCRIPTION
    Skrypt instaluje lub aktualizuje agenta Wazuh, ustawia adres managera
    w ossec.conf i uruchamia usluge. Pobierany instalator jest weryfikowany
    podpisem Authenticode, a opcjonalnie takze hashem SHA256.
.NOTES
    Wymaga uprawnien administratora.
    Domyslna wersja agenta: 4.14.5-1
#>

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$WazuhManager = "10.2.73.6",

    [ValidatePattern('^\d+\.\d+\.\d+(-\d+)?$')]
    [string]$AgentVersion = "4.14.5-1",

    [ValidateNotNullOrEmpty()]
    [string]$AgentDir = "${env:ProgramFiles(x86)}\ossec-agent",

    [string]$DownloadUrl = "",
    [string]$InstallerPath = "",
    [string]$ExpectedInstallerSha256 = "",
    [string]$AgentName = "",
    [string]$AgentGroup = "",
    [string]$RegistrationPassword = "",
    [switch]$KeepInstaller,
    [switch]$SkipSignatureCheck
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$InstallerName = "wazuh-agent-$AgentVersion.msi"
if ([string]::IsNullOrWhiteSpace($DownloadUrl)) {
    $DownloadUrl = "https://packages.wazuh.com/4.x/windows/$InstallerName"
}
if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
    $InstallerPath = Join-Path $env:TEMP $InstallerName
}

$OSSEC_CONF = Join-Path $AgentDir "ossec.conf"
$SERVICE_NAME = "WazuhSvc"
$LOG_DIR = Join-Path $env:ProgramData "WazuhAgentInstall"
$MSI_LOG = Join-Path $LOG_DIR "wazuh-agent-install.log"

$REGISTRY_PATHS = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

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
    }
}

function Get-InstalledWazuhVersion {
    foreach ($path in $REGISTRY_PATHS) {
        if (-not (Test-Path -LiteralPath $path)) {
            continue
        }

        $entry = Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue |
            Get-ItemProperty -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like "Wazuh Agent*" } |
            Select-Object -First 1

        if ($entry) {
            return $entry.DisplayVersion
        }
    }

    return $null
}

function Test-AgentVersionMatch {
    param(
        [string]$InstalledVersion,
        [string]$ExpectedVersion
    )

    if ([string]::IsNullOrWhiteSpace($InstalledVersion)) {
        return $false
    }

    $expectedBaseVersion = $ExpectedVersion -replace '-\d+$', ''
    return ($InstalledVersion -eq $ExpectedVersion -or $InstalledVersion -eq $expectedBaseVersion)
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
    New-DirectoryIfMissing -Path $destinationDir

    $partial = "$Destination.download"
    if (Test-Path -LiteralPath $partial) {
        Remove-Item -LiteralPath $partial -Force
    }

    Write-Host "    Pobieranie z: $Uri"
    Invoke-WebRequest -Uri $Uri -OutFile $partial -UseBasicParsing
    Move-Item -LiteralPath $partial -Destination $Destination -Force
    Write-Done "Plik pobrany do: $Destination"
    return $true
}

function Assert-FileHashSha256 {
    param(
        [string]$Path,
        [string]$ExpectedSha256
    )

    if ([string]::IsNullOrWhiteSpace($ExpectedSha256)) {
        return
    }

    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actual -ne $ExpectedSha256) {
        throw "Nieprawidlowy SHA256 dla '$Path'. Oczekiwano $ExpectedSha256, otrzymano $actual."
    }

    Write-Done "Hash SHA256 instalatora poprawny."
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

function Invoke-WazuhInstaller {
    New-DirectoryIfMissing -Path $LOG_DIR

    $msiArgs = @(
        "/i",
        $InstallerPath,
        "/qn",
        "/l*v",
        $MSI_LOG,
        "WAZUH_MANAGER=$WazuhManager"
    )

    if (-not [string]::IsNullOrWhiteSpace($AgentName)) {
        $msiArgs += "WAZUH_AGENT_NAME=$AgentName"
    }
    if (-not [string]::IsNullOrWhiteSpace($AgentGroup)) {
        $msiArgs += "WAZUH_AGENT_GROUP=$AgentGroup"
    }
    if (-not [string]::IsNullOrWhiteSpace($RegistrationPassword)) {
        $msiArgs += "WAZUH_REGISTRATION_PASSWORD=$RegistrationPassword"
    }

    Write-Host "    Instalowanie Wazuh Agent $AgentVersion (manager: $WazuhManager)..."
    Write-Host "    Log MSI: $MSI_LOG"
    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
    $successCodes = @(0, 3010, 1641)

    if ($successCodes -notcontains $proc.ExitCode) {
        throw "Instalacja MSI zakonczyla sie bledem. Kod: $($proc.ExitCode). Szczegoly w: $MSI_LOG"
    }

    if (@(3010, 1641) -contains $proc.ExitCode) {
        Write-Warn "Instalacja zakonczyla sie sukcesem, ale system zglosil wymagany restart. Kod: $($proc.ExitCode)"
    }

    Write-Done "Agent Wazuh $AgentVersion zainstalowany pomyslnie."
}

function New-Backup {
    param([string]$Path)

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupPath = "$Path.bak-$timestamp"
    Copy-Item -LiteralPath $Path -Destination $backupPath -Force
    Write-Done "Utworzono backup: $backupPath"
    return $backupPath
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

function Get-OrAddElement {
    param(
        [System.Xml.XmlDocument]$Xml,
        [System.Xml.XmlNode]$Parent,
        [string]$Name
    )

    $node = $Parent.SelectSingleNode($Name)
    if (-not $node) {
        $node = $Xml.CreateElement($Name)
        [void]$Parent.AppendChild($node)
    }

    return $node
}

function Get-OssecXml {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Plik $Path nie istnieje. Instalacja Wazuh mogla sie nie powiesc."
    }

    $xml = New-Object System.Xml.XmlDocument
    $xml.PreserveWhitespace = $true
    $xml.Load($Path)
    return $xml
}

function Get-CurrentManager {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    $xml = Get-OssecXml -Path $Path
    $address = $xml.SelectSingleNode('/ossec_config/client/server/address')
    if ($address) {
        return $address.InnerText
    }

    return $null
}

function Set-WazuhManagerInConfig {
    param(
        [string]$Path,
        [string]$Manager
    )

    $xml = Get-OssecXml -Path $Path
    $root = $xml.SelectSingleNode('/ossec_config')
    if (-not $root) {
        throw "Nie znaleziono elementu /ossec_config w $Path."
    }

    $server = $xml.SelectSingleNode('/ossec_config/client/server')
    if (-not $server) {
        $client = Get-OrAddElement -Xml $xml -Parent $root -Name "client"
        $server = Get-OrAddElement -Xml $xml -Parent $client -Name "server"
    }

    $address = Get-OrAddElement -Xml $xml -Parent $server -Name "address"
    if ($address.InnerText -eq $Manager) {
        Write-Skip "Manager juz ustawiony na: $Manager - brak zmian w ossec.conf."
        return $false
    }

    Write-Host "    Aktualny manager: '$($address.InnerText)' -> zmiana na: '$Manager'"
    New-Backup -Path $Path | Out-Null

    $svc = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    $serviceWasRunning = ($svc -and $svc.Status -eq 'Running')

    try {
        if ($serviceWasRunning) {
            Stop-Service -Name $SERVICE_NAME -Force
            Write-Host "    Usluga zatrzymana na czas edycji konfiguracji."
        }

        $address.InnerText = $Manager
        Save-XmlDocument -Xml $xml -Path $Path
        Write-Done "Adres managera zaktualizowany w ossec.conf."
    }
    finally {
        if ($serviceWasRunning) {
            Start-Service -Name $SERVICE_NAME
            (Get-Service -Name $SERVICE_NAME).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
            Write-Done "Usluga $SERVICE_NAME uruchomiona po edycji konfiguracji."
        }
    }

    return $true
}

function Start-ServiceIfNeeded {
    param([string]$Name)

    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) {
        throw "Usluga $Name nie istnieje. Instalacja mogla sie nie powiesc."
    }

    if ($svc.Status -eq 'Running') {
        Write-Skip "Usluga $Name juz dziala - pomijam uruchomienie."
        return
    }

    Start-Service -Name $Name
    $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    Write-Done "Usluga $Name uruchomiona."
}

Write-Step "Sprawdzanie uprawnien administratora..."
if (-not (Test-Administrator)) {
    throw "Skrypt musi byc uruchomiony jako Administrator."
}
Write-Done "Uprawnienia administratora potwierdzone."

Write-Step "Sprawdzanie pliku instalatora..."
$downloadedInstaller = Receive-FileIfMissing -Uri $DownloadUrl -Destination $InstallerPath
Assert-FileHashSha256 -Path $InstallerPath -ExpectedSha256 $ExpectedInstallerSha256
Assert-AuthenticodeSignature -Path $InstallerPath -ExpectedSubjectContains "Wazuh"

Write-Step "Sprawdzanie zainstalowanej wersji agenta..."
$installedVersion = Get-InstalledWazuhVersion

if (Test-AgentVersionMatch -InstalledVersion $installedVersion -ExpectedVersion $AgentVersion) {
    Write-Skip "Wazuh Agent $installedVersion jest juz zainstalowany - pomijam instalacje."
} else {
    if ($installedVersion) {
        Write-Host "    Wykryto inna wersje: $installedVersion - zostanie zastapiona lub zaktualizowana."
    }
    Invoke-WazuhInstaller
}

Write-Step "Weryfikacja adresu serwera Wazuh w ossec.conf..."
[void](Set-WazuhManagerInConfig -Path $OSSEC_CONF -Manager $WazuhManager)

Write-Step "Sprawdzanie stanu uslugi $SERVICE_NAME..."
Start-ServiceIfNeeded -Name $SERVICE_NAME

Write-Step "Sprzatanie pliku instalatora..."
if ($downloadedInstaller -and -not $KeepInstaller -and (Test-Path -LiteralPath $InstallerPath)) {
    Remove-Item -LiteralPath $InstallerPath -Force
    Write-Done "Pobrany plik instalatora usuniety."
} elseif ($KeepInstaller) {
    Write-Skip "KeepInstaller ustawiony - zostawiam instalator: $InstallerPath"
} else {
    Write-Skip "Instalator nie byl pobierany w tej sesji - brak sprzatania."
}

$finalSvc = Get-Service -Name $SERVICE_NAME
Write-Host ""
Write-Host "=======================================" -ForegroundColor Green
Write-Host "  Wazuh Agent zainstalowany i dziala!" -ForegroundColor Green
Write-Host "  Wersja       : $AgentVersion"
Write-Host "  Serwer Wazuh : $WazuhManager"
Write-Host "  Usluga       : $($finalSvc.Status)"
Write-Host "  Katalog agent: $AgentDir"
Write-Host "  Log MSI      : $MSI_LOG"
Write-Host "=======================================" -ForegroundColor Green
