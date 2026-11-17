# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0
# Run in a local O-PC terminal so OpenSSH can prompt for the passphrase.

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $PublicKeyPath
)

$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $PublicKeyPath) {
    throw 'The destination already has an operator public key.'
}
$agent = (ssh.exe -G T-PC 2>$null | Select-String '^identityagent ').Line
if (!$agent) { throw 'T-PC has no configured Djinn SSH agent.' }
$env:SSH_AUTH_SOCK = $agent.Substring(14)
$identities = ssh-add.exe -L
if ($LASTEXITCODE -ne 0) { throw 'Open Djinn before enrolling an operator key.' }
$comment = 'djinn-fleet-updates@O-PC'
if ($identities -match " $([regex]::Escape($comment))$") {
    throw 'Djinn already holds the fleet update key. Export its public half instead.'
}

$keyDirectory = Join-Path $env:LOCALAPPDATA 'Merely/release-keys/djinn-fleet'
$scratch = Join-Path $env:LOCALAPPDATA ("Temp/djinn-operator-" + [guid]::NewGuid().ToString('N'))
$key = Join-Path $scratch 'operator'
New-Item -ItemType Directory -Path $scratch | Out-Null
try {
    Set-Acl -LiteralPath $scratch -AclObject (Get-Acl -LiteralPath $keyDirectory)
    if (!(Get-Acl -LiteralPath $scratch).AreAccessRulesProtected) {
        throw 'Could not protect the operator staging directory.'
    }
    Write-Host 'Enter a local passphrase twice to protect the temporary operator key.'
    ssh-keygen.exe -q -t ed25519 -C $comment -f $key
    if ($LASTEXITCODE -ne 0) { throw 'OpenSSH could not create the operator key.' }
    ssh-keygen.exe -y -P '' -f $key *> $null
    if ($LASTEXITCODE -eq 0) { throw 'Use a passphrase for the temporary key.' }
    Write-Host 'Enter that passphrase again to import the key into Djinn.'
    ssh-add.exe $key
    if ($LASTEXITCODE -ne 0) { throw 'Djinn could not import the operator key.' }
    ssh-add.exe -T "$key.pub"
    if ($LASTEXITCODE -ne 0) { throw 'Djinn could not sign with the operator key.' }
    Copy-Item -LiteralPath "$key.pub" -Destination $PublicKeyPath
    ssh-keygen.exe -lf $PublicKeyPath
    Write-Host 'The operator key is in Djinn. You can close this window.'
} finally {
    foreach ($file in $key, "$key.pub") {
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file }
    }
    if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch }
}
