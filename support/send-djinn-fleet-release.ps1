#Requires -Version 7.4
# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string[]] $Device,
    [Parameter(Mandatory)] [string] $ReleaseDirectory,
    [Parameter(Mandatory)] [string] $OperatorPublicKey,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]*$')]
    [string] $ArtifactName = 'djinn-custodian.elf',
    [ValidatePattern('^[a-z_][a-z0-9_-]*$')]
    [string] $User = 'djinn-updates',
    [string] $Publisher = (Join-Path $env:LOCALAPPDATA 'Djinn/bin/luggage-ssh-publish.exe')
)

$ErrorActionPreference = 'Stop'
$manifest = Join-Path $ReleaseDirectory 'luggage.json'
$artifact = Join-Path $ReleaseDirectory $ArtifactName
foreach ($path in $Publisher, $OperatorPublicKey, $manifest, "$manifest.sig", $artifact) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing $path" }
}
$failed = $false
foreach ($target in $Device) {
    try {
        if ($target -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*$') { throw 'Expected an SSH host alias.' }
        $agentLine = (ssh.exe -G $target 2>$null | Select-String '^identityagent ').Line
        if (!$agentLine) { throw 'The target has no configured Djinn SSH agent.' }
        $agent = $agentLine.Substring(14)
        $s = @('-T', '-o', "User=$User", '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'IdentitiesOnly=yes',
            '-o', "IdentityAgent=$agent", '-i', $OperatorPublicKey, $target)
        $response = & $Publisher $manifest $artifact | ssh.exe @s
        if ($LASTEXITCODE -ne 0) { throw "Publication exited with $LASTEXITCODE." }
        $publication = $response | ConvertFrom-Json
        if ($publication.status -ne 'published' -or $publication.manifest_blake3 -notmatch '^[a-f0-9]{64}$') {
            throw 'The receiver did not confirm publication.'
        }
        $response = $publication.manifest_blake3 | ssh.exe @s
        if ($LASTEXITCODE -ne 0) { throw "Installation exited with $LASTEXITCODE." }
        $installed = $response | ConvertFrom-Json
        if ($installed.status -ne 'installed' -or $installed.manifest_blake3 -ne $publication.manifest_blake3 -or
            $installed.version -ne $publication.version) {
            throw 'The installation receipt differs from the publication.'
        }
        [pscustomobject]@{
            Device = $target
            Version = $installed.version
            ManifestBlake3 = $installed.manifest_blake3
            Status = $installed.status
        }
    } catch {
        $failed = $true
        Write-Error "$target $($_.Exception.Message)" -ErrorAction Continue
    }
}
if ($failed) { exit 1 }
