# Walidacja `enterprise_rules.xml`

Ten katalog zawiera zestaw skryptow do kontrolowanego testowania reguł z `wazuh/enterprise_rules.xml`.

## Model testu

Skrypty endpointowe PowerShell generuja unikalny `RunId` i dla reguł opartych o `win.eventdata.commandLine` uruchamiaja bezpieczny proces `powershell.exe`, ktory tylko wypisuje marker z dopasowanym ciagiem. Dzięki temu Sysmon powinien zapisac podejrzany command line, ale endpoint nie wykonuje operacji typu czyszczenie logow, modyfikacja rejestru, usuwanie shadow copies ani instalacja uslug.

Reguly oparte o DNS, web, Office 365, Linux, FIM, Security Event ID albo korelacje bez bezpiecznego dziecka sa oznaczane jako wymagajace realnego zrodla logow lub walidacji po stronie managera.

## Przygotowanie

Na maszynach Windows testy command-line wymagaja:

- zainstalowanego Sysmon,
- zbierania `Microsoft-Windows-Sysmon/Operational` przez agenta Wazuh,
- załadowanego `enterprise_rules.xml` na managerze Wazuh,
- restartu managera po zmianie reguł.

Wygeneruj manifest i wrappery po zmianie XML-a:

```powershell
cd C:\Users\rfk\Documents\Reguły Wazuh\wazuh\rule-validation
.\New-EnterpriseRuleValidationSuite.ps1
```

## Uruchomienie na endpoincie

Wszystkie reguly po kolei:

```powershell
cd C:\Users\rfk\Documents\Reguły Wazuh\wazuh\rule-validation\endpoint
.\Invoke-AllEnterpriseRuleTests.ps1
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

- `enterprise_rule_tests.json`
- `endpoint\output\endpoint-results.jsonl`
- `server\check-enterprise-rule-results.sh`

Uruchom:

```bash
chmod +x ./check-enterprise-rule-results.sh
./check-enterprise-rule-results.sh --run-id 'TU_WKLEJ_RUN_ID' --manifest ./enterprise_rule_tests.json --endpoint-results ./endpoint-results.jsonl
```

Raport zostanie zapisany jako JSON i CSV w `./validation-results`.
