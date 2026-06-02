param(
    [string]$RunId,
    [string]$OutDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'output'),
    [switch]$NoExecute,
    [int]$DelaySeconds = 2
)

$runner = Join-Path (Split-Path -Parent $PSScriptRoot) 'Invoke-LocalRuleTest.ps1'
$params = @{
    RuleId = '100900'
    OutDir = $OutDir
    DelaySeconds = $DelaySeconds
}
if ($RunId) { $params.RunId = $RunId }
if ($NoExecute) { $params.NoExecute = $true }
& $runner @params
