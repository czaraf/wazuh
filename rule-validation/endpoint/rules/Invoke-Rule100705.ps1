param(
    [string]$RunId,
    [string]$OutDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'output'),
    [switch]$NoExecute,
    [int]$DelaySeconds = 2
)

$runner = Join-Path (Split-Path -Parent $PSScriptRoot) 'Invoke-EnterpriseRuleTest.ps1'
$params = @{
    RuleId = '100705'
    OutDir = $OutDir
    DelaySeconds = $DelaySeconds
}
if ($RunId) { $params.RunId = $RunId }
if ($NoExecute) { $params.NoExecute = $true }
& $runner @params
