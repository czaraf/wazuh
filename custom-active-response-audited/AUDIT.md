# Audyt skryptow Active Response

## Najwazniejsze zmiany

- Skrypty PowerShell obsluguja teraz dwa tryby wejscia: parametry CLI oraz JSON ze stdin, typowy dla Wazuh Custom Active Response.
- Wrappery `.cmd` uruchamiaja plik `.ps1` z katalogu, w ktorym same leza (`%~dp0`), zamiast zakladac sciezke absolutna.
- Logowanie jest odporne na brak katalogu logow i nie przerywa samej reakcji.
- `kill-process.ps1` ignoruje akcje `delete`, waliduje PID, chroni proces biezacego PowerShella i uzywa whitelisty bez rozbieznosci `.txt`.
- `isolate-host.ps1` zapisuje poprzednie ustawienia profili firewalla i przy `delete` odtwarza je, zamiast ustawic na sztywno `Allow`.
- `isolate-host.ps1` nie tworzy reguly `block all`, bo w Windows reguly blokujace maja pierwszenstwo nad zezwalajacymi. Izolacja jest realizowana przez domyslna polityke outbound block.
- `shutdown-host.ps1` korzysta z `shutdown.exe`, zapisuje powod w systemie i pozwala anulowac oczekujace zamkniecie przy akcji `delete`.

## Uwagi wdrozeniowe

- Skopiuj zawartosc folderu do `C:\Program Files (x86)\ossec-agent\active-response\bin\`.
- Jezeli chcesz utrzymac lacznosc agenta Wazuh podczas izolacji, ustaw zmienna srodowiskowa `WAZUH_MANAGER_IP` na adres managera albo przekaz `-AllowedRemoteAddress`.
- W `ossec.conf` warto ujednolicic `isolate-host`: jezeli wdrazasz wrapper, ustaw `<executable>isolate-host.cmd</executable>`; jezeli budujesz `.exe`, zachowaj `.exe`.
- `shutdown-host` jest reakcja destrukcyjna operacyjnie. Zostawiaj ja tylko dla reguly o bardzo wysokiej pewnosci, np. potwierdzone aktywne C2.
