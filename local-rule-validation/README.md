# Walidacja `local_rules.xml`

Ten katalog zawiera oddzielny zestaw skryptow do kontrolowanego testowania reguł z `wazuh/local_rules.xml`.

## Model testu

Skrypty endpointowe PowerShell generuja unikalny `RunId`. Dla reguł opartych o `win.eventdata.commandLine` uruchamiaja bezpieczny proces `powershell.exe`, ktory tylko wypisuje marker z dopasowanym ciagiem. Sysmon powinien zapisac podejrzany command line, ale endpoint nie wykonuje operacji typu czyszczenie logow, modyfikacja rejestru, usuwanie backupow ani uruchamianie narzedzi ofensywnych.

Reguly oparte o Windows Security Event ID, USB/PNP albo realna instalacje uslugi sa oznaczane jako wymagajace natywnego zrodla logow lub osobnego testu kontrolowanego.

## Przygotowanie

Na maszynach Windows testy command-line wymagaja:

- zainstalowanego Sysmon,
- zbierania `Microsoft-Windows-Sysmon/Operational` przez agenta Wazuh,
- załadowanego `local_rules.xml` na managerze Wazuh,
- restartu managera po zmianie reguł.

Wygeneruj manifest i wrappery po zmianie XML-a:

```powershell
cd C:\Users\rfk\Documents\Reguły Wazuh\wazuh\local-rule-validation
.\New-LocalRuleValidationSuite.ps1
```

## Uruchomienie na endpoincie

Wszystkie reguly po kolei:

```powershell
cd C:\Users\rfk\Documents\Reguły Wazuh\wazuh\local-rule-validation\endpoint
.\Invoke-AllLocalRuleTests.ps1
```

Pojedyncza regula:

```powershell
.\rules\Invoke-Rule100750.ps1
```

Wyniki endpointu trafia do:

- `endpoint\output\endpoint-summary.json`
- `endpoint\output\endpoint-results.jsonl`
- `endpoint\output\endpoint-run.log`

## Sprawdzenie na serwerze Wazuh

Skopiuj na serwer Wazuh:

- `local_rule_tests.json`
- `endpoint\output\endpoint-results.jsonl`
- `server\check-local-rule-results.sh`

Uruchom:

```bash
chmod +x ./check-local-rule-results.sh
./check-local-rule-results.sh --run-id 'TU_WKLEJ_RUN_ID' --manifest ./local_rule_tests.json --endpoint-results ./endpoint-results.jsonl
```

Raport zostanie zapisany jako JSON i CSV w `./validation-results`.
