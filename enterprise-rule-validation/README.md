# Walidacja `enterprise_rules.xml`

Ten katalog zawiera zestaw skryptów do kontrolowanego testowania reguł z `wazuh/enterprise_rules.xml`.

## Model testu

Skrypty endpointowe PowerShell generują unikalny `RunId` i dla reguł opartych o `win.eventdata.commandLine` uruchamiają bezpieczny proces `powershell.exe`, który tylko wypisuje marker z dopasowanym ciągiem. Dzięki temu Sysmon powinien zapisać podejrzany command line, ale endpoint nie wykonuje operacji typu czyszczenie logów, modyfikacja rejestru, usuwanie shadow copies ani instalacja usług.

Reguły oparte o DNS, web, Office 365, Linux, FIM, Security Event ID albo korelacje bez bezpiecznego dziecka są oznaczane jako wymagające realnego źródła logów lub walidacji po stronie managera.

## Przygotowanie

Na maszynach Windows testy command-line wymagają:

- zainstalowanego Sysmona,
- zbierania `Microsoft-Windows-Sysmon/Operational` przez agenta Wazuh,
- załadowanego `enterprise_rules.xml` na managerze Wazuh,
- restartu managera po zmianie reguł.

Wygeneruj manifest i wrappery po zmianie XML-a:

```powershell
cd C:\Users\rfk\Documents\Reguły Wazuh\wazuh\enterprise-rule-validation
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\New-EnterpriseRuleValidationSuite.ps1
```

## Uruchomienie na endpoincie

Wszystkie reguły po kolei:

```powershell
cd C:\Users\rfk\Documents\Reguły Wazuh\wazuh\enterprise-rule-validation\endpoint
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-AllEnterpriseRuleTests.ps1
```

Pojedyncza reguła:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\rules\Invoke-Rule100750.ps1
```

Wyniki endpointu trafią do:

- `endpoint\output\endpoint-summary.json`
- `endpoint\output\endpoint-results.jsonl`
- `endpoint\output\endpoint-run.log`

## Sprawdzenie na serwerze Wazuh

Skopiuj na serwer Wazuh:

- `enterprise_rule_tests.json`
- `endpoint\output\endpoint-results.jsonl`
- `server\check-enterprise-rule-results.sh`

Uruchom:

```bash
chmod +x ./check-enterprise-rule-results.sh
./check-enterprise-rule-results.sh --run-id 'TU_WKLEJ_RUN_ID' --manifest ./enterprise_rule_tests.json --endpoint-results ./endpoint-results.jsonl
```

Raport zostanie zapisany jako JSON i CSV w `./validation-results`.
