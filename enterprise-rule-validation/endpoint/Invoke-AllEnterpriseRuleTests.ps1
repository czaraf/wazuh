param(
    [string]$RunId,
    [string]$OutDir = (Join-Path $PSScriptRoot 'output'),
    [int]$DelaySeconds = 2,
    [switch]$NoExecute
)

$ErrorActionPreference = 'Stop'

if (-not $RunId) {
    $RunId = 'WAZUH-RULE-VALIDATION-{0}-{1}' -f (Get-Date -Format 'yyyyMMddHHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
}

$SuiteRoot = Split-Path -Parent $PSScriptRoot
$ManifestPath = Join-Path $SuiteRoot 'enterprise_rule_tests.json'
if (-not (Test-Path -LiteralPath $ManifestPath)) {
    throw "Manifest not found: $ManifestPath. Run ..\New-EnterpriseRuleValidationSuite.ps1 first."
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$RunLog = Join-Path $OutDir 'endpoint-run.log'
$StartedAt = Get-Date

Add-Content -LiteralPath $RunLog -Value ("[{0}] START run_id={1} host={2}" -f $StartedAt.ToString('o'), $RunId, $env:COMPUTERNAME) -Encoding UTF8

$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$runner = Join-Path $PSScriptRoot 'Invoke-EnterpriseRuleTest.ps1'

foreach ($rule in ($manifest.rules | Sort-Object { [int]$_.id })) {
    Add-Content -LiteralPath $RunLog -Value ("[{0}] INVOKE rule={1} method={2}" -f (Get-Date).ToString('o'), $rule.id, $rule.endpoint_method) -Encoding UTF8
    $params = @{
        RuleId = [string]$rule.id
        RunId = $RunId
        OutDir = $OutDir
        DelaySeconds = $DelaySeconds
        Quiet = $true
    }
    if ($NoExecute) { $params.NoExecute = $true }
    & $runner @params
}

$FinishedAt = Get-Date
$summary = [ordered]@{
    run_id = $RunId
    host = $env:COMPUTERNAME
    started_at = $StartedAt.ToString('o')
    finished_at = $FinishedAt.ToString('o')
    endpoint_results = (Join-Path $OutDir 'endpoint-results.jsonl')
    endpoint_log = $RunLog
    server_check_hint = './check-enterprise-rule-results.sh --run-id "{0}" --manifest ./enterprise_rule_tests.json --endpoint-results ./endpoint-results.jsonl' -f $RunId
}

$summaryPath = Join-Path $OutDir 'endpoint-summary.json'
$summary | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
Add-Content -LiteralPath $RunLog -Value ("[{0}] FINISH run_id={1}" -f $FinishedAt.ToString('o'), $RunId) -Encoding UTF8

Write-Host "RunId: $RunId"
Write-Host "Summary: $summaryPath"
Write-Host "Results: $($summary.endpoint_results)"
Write-Host "Copy enterprise_rule_tests.json and endpoint-results.jsonl to the Wazuh server, then run:"
Write-Host $summary.server_check_hint
