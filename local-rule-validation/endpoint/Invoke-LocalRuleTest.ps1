param(
    [Parameter(Mandatory = $true)]
    [string]$RuleId,
    [string]$RunId,
    [string]$OutDir = (Join-Path $PSScriptRoot 'output'),
    [int]$DelaySeconds = 2,
    [switch]$NoExecute,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

$SuiteRoot = Split-Path -Parent $PSScriptRoot
$ManifestPath = Join-Path $SuiteRoot 'local_rule_tests.json'
if (-not (Test-Path -LiteralPath $ManifestPath)) {
    throw "Manifest not found: $ManifestPath. Run New-LocalRuleValidationSuite.ps1 first."
}

if (-not $RunId) {
    $RunId = 'WAZUH-RULE-VALIDATION-{0}-{1}' -f (Get-Date -Format 'yyyyMMddHHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$ResultPath = Join-Path $OutDir 'endpoint-results.jsonl'
$LogPath = Join-Path $OutDir 'endpoint-run.log'

$Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
$RuleIndex = @{}
foreach ($rule in $Manifest.rules) {
    $RuleIndex[[string]$rule.id] = $rule
}

function Write-EndpointResult {
    param([hashtable]$Result)
    $Result.timestamp = (Get-Date).ToString('o')
    $Result.run_id = $RunId
    $Result.host = $env:COMPUTERNAME
    $Result | ConvertTo-Json -Depth 8 -Compress | Add-Content -LiteralPath $ResultPath -Encoding UTF8
    Add-Content -LiteralPath $LogPath -Value ("[{0}] rule={1} status={2} method={3} message={4}" -f $Result.timestamp, $Result.rule_id, $Result.status, $Result.endpoint_method, $Result.message) -Encoding UTF8
}

function Invoke-MarkerPowerShell {
    param(
        [string]$RuleIdToRun,
        [string]$TriggerText,
        [string]$Method
    )

    $marker = '{0} RULE_ID={1}' -f $RunId, $RuleIdToRun
    $payloadText = '{0} {1}' -f $marker, $TriggerText
    $escapedPayload = $payloadText.Replace("'", "''")
    $command = "Write-Output '$escapedPayload'"

    if ($NoExecute) {
        return "NoExecute: powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $command"
    }

    $process = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $command) -WindowStyle Hidden -PassThru -Wait
    if ($process.ExitCode -ne 0) {
        throw "PowerShell trigger exited with code $($process.ExitCode)"
    }
    Start-Sleep -Seconds $DelaySeconds
    return $payloadText
}

function Invoke-OneRule {
    param([string]$CurrentRuleId)

    if (-not $RuleIndex.ContainsKey($CurrentRuleId)) {
        throw "Rule $CurrentRuleId not found in manifest."
    }

    $rule = $RuleIndex[$CurrentRuleId]
    $method = [string]$rule.endpoint_method

    if ($method -eq 'windows_sysmon_commandline' -or $method -eq 'windows_powershell_scriptblock') {
        try {
            $payload = Invoke-MarkerPowerShell -RuleIdToRun $CurrentRuleId -TriggerText ([string]$rule.trigger_text) -Method $method
            Write-EndpointResult @{
                rule_id = $CurrentRuleId
                description = [string]$rule.description
                endpoint_method = $method
                status = 'triggered'
                expected_server_check = 'alerts.json should contain rule.id and run_id marker'
                message = 'Endpoint telemetry was generated.'
                marker_payload = $payload
            }
        }
        catch {
            Write-EndpointResult @{
                rule_id = $CurrentRuleId
                description = [string]$rule.description
                endpoint_method = $method
                status = 'error'
                expected_server_check = 'not_applicable'
                message = $_.Exception.Message
            }
        }
        return
    }

    if ($method -eq 'correlation') {
        $children = @($rule.correlation_children)
        if ($children.Count -eq 0) {
            Write-EndpointResult @{
                rule_id = $CurrentRuleId
                description = [string]$rule.description
                endpoint_method = $method
                status = 'skipped'
                expected_server_check = 'server_or_native_source_required'
                message = 'No endpoint-safe child rules are available for this correlation rule.'
            }
            return
        }

        $needed = if ($rule.frequency) { [int]$rule.frequency } else { 2 }
        for ($i = 0; $i -lt $needed; $i++) {
            foreach ($child in $children) {
                Invoke-OneRule -CurrentRuleId ([string]$child)
            }
        }
        Write-EndpointResult @{
            rule_id = $CurrentRuleId
            description = [string]$rule.description
            endpoint_method = $method
            status = 'triggered_children'
            expected_server_check = 'alerts.json should contain the correlation rule id if Wazuh correlation conditions matched'
            message = ('Triggered child rules: {0}' -f ($children -join ','))
        }
        return
    }

    Write-EndpointResult @{
        rule_id = $CurrentRuleId
        description = [string]$rule.description
        endpoint_method = $method
        status = 'skipped'
        expected_server_check = 'server_or_native_source_required'
        message = [string]$rule.notes
    }
}

Invoke-OneRule -CurrentRuleId $RuleId

if (-not $Quiet) {
    Write-Host "RunId: $RunId"
    Write-Host "Endpoint results: $ResultPath"
    Write-Host "Endpoint log: $LogPath"
}
