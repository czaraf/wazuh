# Recommended Wazuh Active Response scripts

Ten folder zawiera cztery reakcje dla agentow Windows. Kazda reakcja ma plik `.cmd`
do podpiecia w Wazuh oraz odpowiadajacy mu skrypt `.ps1`.

## Zawartosc

- `quarantine-file.cmd` / `quarantine-file.ps1` - przenosi podejrzany plik do lokalnej kwarantanny i zapisuje metadane JSON.
- `yara-scan.cmd` / `yara-scan.ps1` - uruchamia YARA na pliku z alertu FIM/Sysmon i opcjonalnie przenosi plik do kwarantanny po dopasowaniu.
- `collect-forensics.cmd` / `collect-forensics.ps1` - zbiera lekki pakiet dowodowy: procesy, polaczenia, uslugi, zadania, run keys, ipconfig, netstat, route.
- `disable-ad-account.cmd` / `disable-ad-account.ps1` - wylacza konto AD wskazane w alercie. Uzywaj tylko na agencie administracyjnym z modulem RSAT ActiveDirectory.
- `disable-ad-account-allowlist` - konta, ktorych skrypt AD nigdy nie powinien wylaczac.

## Wdrozenie

Skopiuj pliki do:

```text
C:\Program Files (x86)\ossec-agent\active-response\bin\
```

`yara-scan.ps1` oczekuje `yara64.exe` albo `yara.exe` w tym samym katalogu oraz reguly w `yara-rules`.
Mozesz tez przekazac `-YaraExe` i `-RulesPath` przy testach recznych.

## Przykladowy ossec.conf

```xml
<command>
  <name>quarantine-file</name>
  <executable>quarantine-file.cmd</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<command>
  <name>yara-scan</name>
  <executable>yara-scan.cmd</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<command>
  <name>collect-forensics</name>
  <executable>collect-forensics.cmd</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<command>
  <name>disable-ad-account</name>
  <executable>disable-ad-account.cmd</executable>
  <timeout_allowed>no</timeout_allowed>
</command>
```

Przyklady reakcji:

```xml
<active-response>
  <disabled>no</disabled>
  <command>yara-scan</command>
  <location>local</location>
  <rules_id>550,554</rules_id>
</active-response>

<active-response>
  <disabled>no</disabled>
  <command>quarantine-file</command>
  <location>local</location>
  <rules_id>100750,100751,100904</rules_id>
</active-response>

<active-response>
  <disabled>no</disabled>
  <command>collect-forensics</command>
  <location>local</location>
  <rules_id>100900,100901,100902,100903,100904,100750,100751</rules_id>
</active-response>

<!-- Uruchamiaj tylko na zdefiniowanym agencie administracyjnym, nie na wszystkich endpointach. -->
<active-response>
  <disabled>no</disabled>
  <command>disable-ad-account</command>
  <location>defined-agent</location>
  <agent_id>001</agent_id>
  <rules_id>100660,100735,100736</rules_id>
</active-response>
```

## Uwagi bezpieczenstwa

- `quarantine-file` ignoruje `delete`, bo timeout Wazuha nie powinien automatycznie przywracac malware.
- `yara-scan` sam nie usuwa pliku, chyba ze uruchomisz skrypt recznie z `-QuarantineOnMatch` albo dopiszesz ten argument w wrapperze.
- `collect-forensics` nie izoluje hosta i nie zmienia konfiguracji systemu.
- `disable-ad-account` ignoruje konta z allowlisty, konta maszynowe i nazwy pasujace do wzorca kont chronionych/uslugowych.
