#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Idempotentna instalacja agenta Wazuh na systemie Windows.
.DESCRIPTION
    Skrypt mozna uruchomic wielokrotnie - kazdy krok jest wykonywany tylko
    wtedy, gdy jest to konieczne (desired-state):
      - pobieranie MSI     -> pomijane jesli plik juz istnieje
      - instalacja agenta  -> pomijana jesli wlasciwa wersja jest juz zainstalowana
      - konfiguracja IP    -> nadpisywana jesli manager w ossec.conf jest inny
      - start uslugi       -> pomijany jesli usluga juz dziala
      - usuniecie MSI      -> wykonywane tylko jesli plik istnieje
.NOTES
    Wymaga uprawnien administratora.
    Wersja agenta : 4.14.5-1
    Dokumentacja  : https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html
#>

$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------------ Konfiguracja
$WAZUH_MANAGER  = "10.2.73.6"
$AGENT_VERSION  = "4.14.5-1"
$INSTALLER_NAME = "wazuh-agent-$AGENT_VERSION.msi"
$DOWNLOAD_URL   = "https://packages.wazuh.com/4.x/windows/$INSTALLER_NAME"
$INSTALLER_PATH = "$env:TEMP\$INSTALLER_NAME"
$AGENT_DIR      = "C:\Program Files (x86)\ossec-agent"
$OSSEC_CONF     = "$AGENT_DIR\ossec.conf"
$SERVICE_NAME   = "WazuhSvc"

$REGISTRY_PATHS = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

# ------------------------------------------------------------------ Pomocniki
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

function Get-InstalledWazuhVersion {
    foreach ($path in $REGISTRY_PATHS) {
        if (Test-Path $path) {
            $entry = Get-ChildItem $path -ErrorAction SilentlyContinue |
                     Get-ItemProperty -ErrorAction SilentlyContinue |
                     Where-Object { $_.DisplayName -like "Wazuh Agent*" } |
                     Select-Object -First 1
            if ($entry) { return $entry.DisplayVersion }
        }
    }
    return $null
}

function Get-CurrentManager {
    if (-not (Test-Path $OSSEC_CONF)) { return $null }
    $xml = [xml](Get-Content $OSSEC_CONF -Raw)
    return $xml.ossec_config.client.server.address
}

# ============================================================
# KROK 1 - Sprawdzenie uprawnien administratora
# ============================================================
Write-Step "Sprawdzanie uprawnien administratora..."
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Skrypt musi byc uruchomiony jako Administrator."
    exit 1
}
Write-Done "Uprawnienia administratora potwierdzone."

# ============================================================
# KROK 2 - Pobranie instalatora MSI (tylko jesli brak pliku)
# ============================================================
Write-Step "Sprawdzanie pliku instalatora..."
if (Test-Path $INSTALLER_PATH) {
    Write-Skip "Plik juz istnieje: $INSTALLER_PATH - pomijam pobieranie."
} else {
    Write-Host "    Pobieranie z: $DOWNLOAD_URL"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $DOWNLOAD_URL -OutFile $INSTALLER_PATH -UseBasicParsing
    Write-Done "Plik pobrany do: $INSTALLER_PATH"
}

# ============================================================
# KROK 3 - Instalacja agenta (tylko jesli nie ma wlasciwej wersji)
# ============================================================
Write-Step "Sprawdzanie zainstalowanej wersji agenta..."
$installedVersion = Get-InstalledWazuhVersion

if ($installedVersion -eq $AGENT_VERSION) {
    Write-Skip "Wazuh Agent $AGENT_VERSION jest juz zainstalowany - pomijam instalacje."
} else {
    if ($installedVersion) {
        Write-Host "    Wykryto starsza wersje: $installedVersion - zostanie zastapiona."
    }
    Write-Host "    Instalowanie Wazuh Agent $AGENT_VERSION (manager: $WAZUH_MANAGER)..."
    $msiArgs = @("/i", $INSTALLER_PATH, "/q", "WAZUH_MANAGER=$WAZUH_MANAGER")
    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        Write-Error "Instalacja MSI zakonczyla sie bledem. Kod: $($proc.ExitCode)"
        exit 1
    }
    Write-Done "Agent Wazuh $AGENT_VERSION zainstalowany pomyslnie."
}

# ============================================================
# KROK 4 - Weryfikacja i ewentualna korekta adresu managera
# ============================================================
Write-Step "Weryfikacja adresu serwera Wazuh w ossec.conf..."
$currentManager = Get-CurrentManager

if ($currentManager -eq $WAZUH_MANAGER) {
    Write-Skip "Manager juz ustawiony na: $WAZUH_MANAGER - brak zmian w ossec.conf."
} else {
    Write-Host "    Aktualny manager: '$currentManager' -> zmiana na: '$WAZUH_MANAGER'"
    $svc = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Stop-Service -Name $SERVICE_NAME -Force
        Write-Host "    Usluga zatrzymana na czas edycji konfiguracji."
    }
    $content = Get-Content $OSSEC_CONF -Raw
    $content = $content -replace '(<address>)[^<]*(</address>)', ('${1}' + $WAZUH_MANAGER + '${2}')
    Set-Content $OSSEC_CONF -Value $content -Encoding UTF8
    Write-Done "Adres managera zaktualizowany w ossec.conf."
}

# ============================================================
# KROK 5 - Uruchomienie uslugi (tylko jesli nie dziala)
# ============================================================
Write-Step "Sprawdzanie stanu uslugi $SERVICE_NAME..."
$svc = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue

if (-not $svc) {
    Write-Error "Usluga $SERVICE_NAME nie istnieje. Instalacja mogla sie nie powiesc."
    exit 1
}

if ($svc.Status -eq 'Running') {
    Write-Skip "Usluga $SERVICE_NAME juz dziala - pomijam uruchomienie."
} else {
    Start-Service -Name $SERVICE_NAME
    Start-Sleep -Seconds 3
    $svc.Refresh()
    if ($svc.Status -ne 'Running') {
        Write-Error "Usluga $SERVICE_NAME nie uruchomila sie. Status: $($svc.Status)"
        exit 1
    }
    Write-Done "Usluga $SERVICE_NAME uruchomiona."
}

# ============================================================
# KROK 6 - Usuniecie pliku instalatora (tylko jesli istnieje)
# ============================================================
Write-Step "Sprzatanie pliku instalatora..."
if (Test-Path $INSTALLER_PATH) {
    Remove-Item -Path $INSTALLER_PATH -Force
    Write-Done "Plik instalatora usuniety."
} else {
    Write-Skip "Plik instalatora nie istnieje - brak czego usuwac."
}

# ============================================================
# Podsumowanie
# ============================================================
$finalSvc = Get-Service -Name $SERVICE_NAME
Write-Host ""
Write-Host "=======================================" -ForegroundColor Green
Write-Host "  Wazuh Agent zainstalowany i dziala!" -ForegroundColor Green
Write-Host "  Wersja       : $AGENT_VERSION"
Write-Host "  Serwer Wazuh : $WAZUH_MANAGER"
Write-Host "  Usluga       : $($finalSvc.Status)"
Write-Host "  Katalog agent: $AGENT_DIR"
Write-Host "=======================================" -ForegroundColor Green
