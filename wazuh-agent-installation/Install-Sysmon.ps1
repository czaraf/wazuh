#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Idempotentna instalacja Sysmon z konfiguracją SwiftOnSecurity.
.DESCRIPTION
    Skrypt mozna uruchomic wielokrotnie (desired-state):
      - katalog C:\Sysmon       -> tworzony tylko jesli nie istnieje
      - Sysmon.zip              -> pobierany tylko jesli brak pliku
      - rozpakowywanie          -> pomijane jesli Sysmon64.exe juz jest
      - sysmonconfig.xml        -> pobierany tylko jesli brak pliku
      - instalacja uslugi       -> pomijana jesli Sysmon64 juz zainstalowany
      - aktualizacja konfigu    -> wykonywana jesli wersja configu jest starsza
      - wpis w ossec.conf       -> dodawany tylko jesli jeszcze nie istnieje
      - restart WazuhSvc        -> wykonywany tylko po zmianie ossec.conf
.NOTES
    Wymaga uprawnien administratora.
    Sysmon config : SwiftOnSecurity sysmonconfig-export.xml
    Agent Wazuh   : musi byc zainstalowany w C:\Program Files (x86)\ossec-agent
#>

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ------------------------------------------------------------------ Konfiguracja
$SYSMON_DIR     = "C:\Sysmon"
$SYSMON_ZIP     = "$SYSMON_DIR\Sysmon.zip"
$SYSMON_EXE     = "$SYSMON_DIR\Sysmon64.exe"
$SYSMON_CFG     = "$SYSMON_DIR\sysmonconfig.xml"
$SYSMON_SVC     = "Sysmon64"
$ZIP_URL        = "https://download.sysinternals.com/files/Sysmon.zip"
$CFG_URL        = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"

$OSSEC_CONF     = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$WAZUH_SVC      = "WazuhSvc"

# Blok localfile do dodania do ossec.conf
$LOCALFILE_BLOCK = @"

  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@

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

function Test-SysmonService {
    return $null -ne (Get-Service -Name $SYSMON_SVC -ErrorAction SilentlyContinue)
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
# KROK 2 - Utworzenie katalogu C:\Sysmon
# ============================================================
Write-Step "Sprawdzanie katalogu $SYSMON_DIR..."
if (Test-Path $SYSMON_DIR) {
    Write-Skip "Katalog juz istnieje: $SYSMON_DIR"
} else {
    New-Item -ItemType Directory -Force -Path $SYSMON_DIR | Out-Null
    Write-Done "Katalog utworzony: $SYSMON_DIR"
}

# ============================================================
# KROK 3 - Pobranie Sysmon.zip
# ============================================================
Write-Step "Sprawdzanie pliku Sysmon.zip..."
if (Test-Path $SYSMON_ZIP) {
    Write-Skip "Plik juz istnieje: $SYSMON_ZIP - pomijam pobieranie."
} else {
    Write-Host "    Pobieranie z: $ZIP_URL"
    Invoke-WebRequest -Uri $ZIP_URL -OutFile $SYSMON_ZIP -UseBasicParsing
    Write-Done "Plik pobrany: $SYSMON_ZIP"
}

# ============================================================
# KROK 4 - Rozpakowanie archiwum
# ============================================================
Write-Step "Sprawdzanie Sysmon64.exe..."
if (Test-Path $SYSMON_EXE) {
    Write-Skip "Sysmon64.exe juz istnieje - pomijam rozpakowywanie."
} else {
    Write-Host "    Rozpakowywanie $SYSMON_ZIP..."
    Expand-Archive -Path $SYSMON_ZIP -DestinationPath $SYSMON_DIR -Force
    Write-Done "Archiwum rozpakowane do: $SYSMON_DIR"
}

# ============================================================
# KROK 5 - Pobranie konfiguracji SwiftOnSecurity
# ============================================================
Write-Step "Sprawdzanie pliku konfiguracyjnego sysmonconfig.xml..."
if (Test-Path $SYSMON_CFG) {
    Write-Skip "sysmonconfig.xml juz istnieje - pomijam pobieranie."
} else {
    Write-Host "    Pobieranie konfigu SwiftOnSecurity..."
    Invoke-WebRequest -Uri $CFG_URL -OutFile $SYSMON_CFG -UseBasicParsing
    Write-Done "Konfiguracja pobrana: $SYSMON_CFG"
}

# ============================================================
# KROK 6 - Instalacja lub aktualizacja konfiguracji Sysmon
# ============================================================
Write-Step "Sprawdzanie uslugi Sysmon64..."
$ossecChanged = $false

if (Test-SysmonService) {
    Write-Skip "Usluga Sysmon64 juz zainstalowana - aktualizuje konfiguracje..."
    & $SYSMON_EXE -c $SYSMON_CFG | Out-Null
    Write-Done "Konfiguracja Sysmon zaktualizowana (-c)."
} else {
    Write-Host "    Instalowanie Sysmon64 z konfigurem SwiftOnSecurity..."
    & $SYSMON_EXE -accepteula -i $SYSMON_CFG | Out-Null

    # Poczekaj az usluga wstanie
    Start-Sleep -Seconds 3
    if (-not (Test-SysmonService)) {
        Write-Error "Usluga Sysmon64 nie zostala zarejestrowana po instalacji."
        exit 1
    }
    Write-Done "Sysmon64 zainstalowany i usluga zarejestrowana."
}

# ============================================================
# KROK 7 - Weryfikacja ze usluga Sysmon64 dziala
# ============================================================
Write-Step "Weryfikacja stanu uslugi Sysmon64..."
$sysmonSvc = Get-Service -Name $SYSMON_SVC -ErrorAction SilentlyContinue
if ($sysmonSvc.Status -ne 'Running') {
    Write-Host "    Usluga nie dziala, uruchamiam..."
    Start-Service -Name $SYSMON_SVC
    Start-Sleep -Seconds 2
    $sysmonSvc.Refresh()
    if ($sysmonSvc.Status -ne 'Running') {
        Write-Error "Usluga Sysmon64 nie uruchomila sie. Status: $($sysmonSvc.Status)"
        exit 1
    }
    Write-Done "Usluga Sysmon64 uruchomiona."
} else {
    Write-Skip "Usluga Sysmon64 juz dziala (Status: $($sysmonSvc.Status))."
}

# ============================================================
# KROK 8 - Dodanie wpisu Sysmon do ossec.conf (Wazuh)
# ============================================================
Write-Step "Sprawdzanie konfiguracji Wazuh (ossec.conf)..."

if (-not (Test-Path $OSSEC_CONF)) {
    Write-Host "    UWAGA: Plik $OSSEC_CONF nie istnieje - czy Wazuh Agent jest zainstalowany?" -ForegroundColor Yellow
    Write-Skip "Pomijam konfiguracje Wazuh."
} else {
    $confContent = Get-Content $OSSEC_CONF -Raw

    if ($confContent -match 'Microsoft-Windows-Sysmon') {
        Write-Skip "Wpis Sysmon/Operational juz istnieje w ossec.conf - brak zmian."
    } else {
        Write-Host "    Dodawanie wpisu Sysmon do ossec.conf..."

        # Wstaw blok localfile przed zamykajacym </ossec_config>
        $newContent = $confContent -replace '</ossec_config>', ($LOCALFILE_BLOCK + "`n</ossec_config>")
        Set-Content $OSSEC_CONF -Value $newContent -Encoding UTF8
        $ossecChanged = $true
        Write-Done "Wpis Sysmon dodany do ossec.conf."
    }
}

# ============================================================
# KROK 9 - Restart WazuhSvc (tylko jesli zmieniono ossec.conf)
# ============================================================
Write-Step "Sprawdzanie czy wymagany restart Wazuh..."
if (-not $ossecChanged) {
    Write-Skip "ossec.conf nie byl modyfikowany - pomijam restart WazuhSvc."
} else {
    $wazuhSvc = Get-Service -Name $WAZUH_SVC -ErrorAction SilentlyContinue
    if (-not $wazuhSvc) {
        Write-Host "    UWAGA: Usluga WazuhSvc nie istnieje - pomijam restart." -ForegroundColor Yellow
    } else {
        Write-Host "    Restartowanie WazuhSvc aby wczytac nowy ossec.conf..."
        Restart-Service -Name $WAZUH_SVC -Force
        Start-Sleep -Seconds 3
        $wazuhSvc.Refresh()
        if ($wazuhSvc.Status -ne 'Running') {
            Write-Error "WazuhSvc nie uruchomil sie po restarcie. Status: $($wazuhSvc.Status)"
            exit 1
        }
        Write-Done "WazuhSvc zrestartowany pomyslnie (Status: $($wazuhSvc.Status))."
    }
}

# ============================================================
# Podsumowanie
# ============================================================
$finalSysmon = Get-Service -Name $SYSMON_SVC -ErrorAction SilentlyContinue
$finalWazuh  = Get-Service -Name $WAZUH_SVC  -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=======================================" -ForegroundColor Green
Write-Host "  Sysmon zainstalowany i dziala!" -ForegroundColor Green
Write-Host "  Sysmon64 : $($finalSysmon.Status)"
if ($finalWazuh) {
Write-Host "  WazuhSvc  : $($finalWazuh.Status)"
}
Write-Host "  Katalog   : $SYSMON_DIR"
Write-Host "  Config    : SwiftOnSecurity sysmonconfig-export.xml"
Write-Host "  Eventy    : eventvwr -> Applications and Services Logs"
Write-Host "              -> Microsoft -> Windows -> Sysmon -> Operational"
Write-Host "=======================================" -ForegroundColor Green
