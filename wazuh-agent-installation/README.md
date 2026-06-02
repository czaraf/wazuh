# Instalacja Wazuh Agent + Sysmon

Skrypty instaluja agenta Wazuh oraz Sysmon na Windows. Sa przygotowane do
wielokrotnego uruchamiania: pomijaja kroki, ktore sa juz w oczekiwanym stanie,
oraz robia backup `ossec.conf` przed modyfikacja.

## Wymagania

- PowerShell uruchomiony jako Administrator.
- Dostep do internetu dla pobrania MSI Wazuh, Sysmon.zip i konfiguracji Sysmon.
- Wazuh Agent powinien byc instalowany przed Sysmonem.
- Przy wdrozeniu produkcyjnym zalecane jest podanie hashy SHA256 pobieranych
  plikow albo hostowanie ich w zaufanym repozytorium wewnetrznym.

## Szybkie uruchomienie

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Install-WazuhAgent.ps1
powershell.exe -ExecutionPolicy Bypass -File .\Install-Sysmon.ps1
```

## Przyklad z parametrami

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Install-WazuhAgent.ps1 `
  -WazuhManager "10.2.73.6" `
  -AgentVersion "4.14.5-1" `
  -AgentGroup "windows-workstations" `
  -KeepInstaller

powershell.exe -ExecutionPolicy Bypass -File .\Install-Sysmon.ps1 `
  -SysmonConfigUrl "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/<COMMIT_SHA>/sysmonconfig-export.xml" `
  -ExpectedConfigSha256 "<SHA256_CONFIG>" `
  -ExpectedSysmonZipSha256 "<SHA256_SYSMON_ZIP>"
```

`<COMMIT_SHA>` zastap konkretnym commitem z repozytorium SwiftOnSecurity.
Nie zaleca sie produkcyjnego wdrozenia konfiguracji z ruchomej galezi `master`
bez weryfikacji hash.

## Co robia skrypty

`Install-WazuhAgent.ps1`:

- pobiera wskazana wersje MSI Wazuh Agent,
- weryfikuje podpis Authenticode MSI i opcjonalny hash SHA256,
- instaluje MSI w trybie cichym z logiem w
  `C:\ProgramData\WazuhAgentInstall\wazuh-agent-install.log`,
- akceptuje kody sukcesu MSI `0`, `3010` i `1641`,
- ustawia adres managera w `ossec.conf` przez parser XML,
- robi backup `ossec.conf` przed zmiana,
- uruchamia `WazuhSvc`.

`Install-Sysmon.ps1`:

- tworzy `C:\Sysmon`,
- ogranicza ACL katalogu do `SYSTEM` i `Administrators`,
- pobiera i rozpakowuje Sysmon.zip,
- weryfikuje podpis Authenticode `Sysmon64.exe`,
- pobiera i waliduje XML konfiguracji Sysmon,
- instaluje albo aktualizuje konfiguracje Sysmon,
- dodaje kanal `Microsoft-Windows-Sysmon/Operational` do `ossec.conf`,
- restartuje `WazuhSvc` tylko wtedy, gdy `ossec.conf` zostal zmieniony.

## Najwazniejsze parametry

`Install-WazuhAgent.ps1`:

- `-WazuhManager` - IP albo hostname managera Wazuh.
- `-AgentVersion` - wersja MSI, np. `4.14.5-1`.
- `-AgentName` - opcjonalna nazwa agenta.
- `-AgentGroup` - opcjonalna grupa agenta.
- `-RegistrationPassword` - opcjonalne haslo rejestracji.
- `-ExpectedInstallerSha256` - oczekiwany SHA256 MSI.
- `-InstallerPath` - lokalna sciezka do MSI, przydatna offline.
- `-DownloadUrl` - alternatywny URL MSI.
- `-KeepInstaller` - zostawia pobrany MSI.
- `-SkipSignatureCheck` - awaryjne pominiecie podpisu, niezalecane.

`Install-Sysmon.ps1`:

- `-SysmonDir` - katalog instalacji Sysmon, domyslnie `C:\Sysmon`.
- `-SysmonZipUrl` - URL do Sysmon.zip.
- `-SysmonConfigUrl` - URL do konfiguracji Sysmon.
- `-ExpectedSysmonZipSha256` - oczekiwany SHA256 Sysmon.zip.
- `-ExpectedConfigSha256` - oczekiwany SHA256 konfiguracji XML.
- `-WazuhAgentDir` - katalog agenta Wazuh.
- `-KeepDownloads` - zostawia pobrane pliki.
- `-SkipSignatureCheck` - awaryjne pominiecie podpisu, niezalecane.

## Weryfikacja po instalacji

```powershell
Get-Service WazuhSvc
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

W Wazuh sprawdz, czy agent jest aktywny i czy pojawiaja sie zdarzenia z kanalu
Sysmon. Po instalacji MSI szczegoly sa w logu:

```powershell
Get-Content "C:\ProgramData\WazuhAgentInstall\wazuh-agent-install.log" -Tail 80
```

## Rollback

Backupi `ossec.conf` sa tworzone obok pliku, np.
`C:\Program Files (x86)\ossec-agent\ossec.conf.bak-YYYYMMDD-HHMMSS`.

Przywrocenie konfiguracji Wazuh:

```powershell
Stop-Service WazuhSvc
Copy-Item "C:\Program Files (x86)\ossec-agent\ossec.conf.bak-YYYYMMDD-HHMMSS" `
  "C:\Program Files (x86)\ossec-agent\ossec.conf" -Force
Start-Service WazuhSvc
```

Odinstalowanie Sysmon:

```powershell
C:\Sysmon\Sysmon64.exe -u
```

Odinstalowanie Wazuh Agent wykonaj standardowo przez systemowy mechanizm
aplikacji albo przez MSI zgodnie z procedura organizacji.
