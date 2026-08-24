[CmdletBinding()]
param([string]$SkillsDir)

$ErrorActionPreference = "Stop"
$PreviousPythonPath = $env:PYTHONPATH

try {
    $Source = $PSScriptRoot
    if (-not (Test-Path -LiteralPath (Join-Path $Source "SKILL.md") -PathType Leaf)) {
        [Console]::Error.WriteLine("install error: run this from a reviewed fixed checkout")
        exit 3
    }

    $Python = Get-Command python3 -ErrorAction SilentlyContinue
    if (-not $Python) {
        $Python = Get-Command python -ErrorAction SilentlyContinue
    }
    $UseLauncher = $false
    if (-not $Python) {
        $Python = Get-Command py -ErrorAction SilentlyContinue
        $UseLauncher = [bool]$Python
    }
    if (-not $Python) {
        [Console]::Error.WriteLine("install error: Python 3.9 or newer is required")
        exit 3
    }

    $env:PYTHONPATH = (Join-Path $Source "src")
    if ($PreviousPythonPath) {
        $env:PYTHONPATH += [IO.Path]::PathSeparator + $PreviousPythonPath
    }
    $Arguments = @("-m", "skill_auditor.installer", "--source", $Source)
    if ($SkillsDir) {
        $Arguments += @("--skills-dir", $SkillsDir)
    }
    if ($UseLauncher) {
        $Arguments = @("-3") + $Arguments
    }
    & $Python.Source @Arguments
    if ($LASTEXITCODE -eq 0) {
        exit 0
    }
    exit 3
} catch {
    [Console]::Error.WriteLine("install error: installation failed")
    exit 3
} finally {
    $env:PYTHONPATH = $PreviousPythonPath
}
