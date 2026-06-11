[CmdletBinding()]
param(
    [string]$SkillsDir,
    [string]$Repository = "https://github.com/22WELTYANG/skill-auditor"
)

$ErrorActionPreference = "Stop"
$SkillName = "skill-auditor"
$Cleanup = $null

try {
    $Source = $PSScriptRoot
    if (-not (Test-Path -LiteralPath (Join-Path $Source "SKILL.md") -PathType Leaf)) {
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
            throw "git is required when install.ps1 is not run from a local checkout"
        }
        $Cleanup = Join-Path ([IO.Path]::GetTempPath()) ("skill-auditor-" + [guid]::NewGuid())
        git clone --depth 1 $Repository $Cleanup | Out-Null
        $Source = $Cleanup
    }

    if ($SkillsDir) {
        $Targets = @([IO.Path]::GetFullPath($SkillsDir))
    } else {
        $Targets = @(
            (Join-Path $HOME ".claude\skills"),
            (Join-Path $HOME ".codex\skills"),
            (Join-Path $HOME ".agents\skills")
        )
        if (Test-Path -LiteralPath (Join-Path $HOME ".cursor") -PathType Container) {
            $Targets += Join-Path $HOME ".cursor\skills"
        }
    }

    foreach ($Parent in $Targets) {
        New-Item -ItemType Directory -Force -Path $Parent | Out-Null
        $Destination = Join-Path ([IO.Path]::GetFullPath($Parent)) $SkillName
        $Staging = Join-Path $Parent (".$SkillName.staging-" + [guid]::NewGuid())
        $Backup = Join-Path $Parent (".$SkillName.backup-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $Staging | Out-Null
        foreach ($Item in @("SKILL.md", "scripts", "src", "rules", "references", "pyproject.toml")) {
            Copy-Item -LiteralPath (Join-Path $Source $Item) -Destination $Staging -Recurse -Force
        }
        if (Test-Path -LiteralPath $Destination) {
            Move-Item -LiteralPath $Destination -Destination $Backup
        }
        try {
            Move-Item -LiteralPath $Staging -Destination $Destination
            if (Test-Path -LiteralPath $Backup) {
                Remove-Item -LiteralPath $Backup -Recurse -Force
            }
        } catch {
            if ((Test-Path -LiteralPath $Backup) -and -not (Test-Path -LiteralPath $Destination)) {
                Move-Item -LiteralPath $Backup -Destination $Destination
            }
            throw
        }
        Write-Host "Installed to $Destination"
    }
} finally {
    if ($Cleanup -and (Test-Path -LiteralPath $Cleanup)) {
        Remove-Item -LiteralPath $Cleanup -Recurse -Force
    }
}

