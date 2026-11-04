# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0
# Update the existing custodian without adopting a vault or changing grants.
# Run elevated after reviewing the receiving build and this script.
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$ExpectedSha256
)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'An elevated Windows process is required to update the installed custodian.'
}
$source = (Resolve-Path -LiteralPath $Binary).Path
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $ExpectedSha256) {
    throw 'Receiving binary hash differs from the reviewed build.'
}
$programRoot = Join-Path $env:ProgramFiles 'Merely\djinn-custodian'
$exe = Join-Path $programRoot 'djinn-custodian.exe'
$root = 'C:\ProgramData\djinn-custodian'
$config = Join-Path $root 'custodian.json'
$service = Get-CimInstance Win32_Service -Filter "Name='djinn-custodian'"
$expectedCommand = '"' + $exe + '" --config "' + $config + '"'
if (-not $service -or $service.PathName -ne $expectedCommand) {
    throw 'Installed service command differs from the expected existing service.'
}
$before = [IO.File]::ReadAllBytes($config)
$policy = [Text.Encoding]::UTF8.GetString($before) | ConvertFrom-Json
$policy | Add-Member -NotePropertyName max_unlocked_seconds -NotePropertyValue 604800 -Force
$updated = $policy | ConvertTo-Json -Depth 32
$backup = Join-Path $root 'week-policy-backup'
if (-not (Test-Path -LiteralPath $backup)) { New-Item -ItemType Directory -Path $backup | Out-Null }
if ((Get-Item -LiteralPath $backup).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    throw 'Backup directory is a reparse point.'
}
$oldHash = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$oldExe = Join-Path $backup ('custodian-' + $oldHash + '.exe')
if (-not (Test-Path -LiteralPath $oldExe)) { Copy-Item -LiteralPath $exe -Destination $oldExe }
$configHash = (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash
$oldConfig = Join-Path $backup ('policy-' + $configHash + '.json')
if (-not (Test-Path -LiteralPath $oldConfig)) { [IO.File]::WriteAllBytes($oldConfig, $before) }
if ((Get-FileHash -LiteralPath $oldExe -Algorithm SHA256).Hash -ne $oldHash -or
    (Get-FileHash -LiteralPath $oldConfig -Algorithm SHA256).Hash -ne $configHash) {
    throw 'Existing backup does not match the installed files.'
}
$task = Get-ScheduledTask | Where-Object {
    $_.Actions | Where-Object { $_.Execute -eq $exe -and $_.Arguments -match '^consent\b' }
}
$wasRunning = $service.State -eq 'Running'
try {
    if ($wasRunning) { Stop-Service -Name djinn-custodian }
    foreach ($entry in $task) { Stop-ScheduledTask -TaskName $entry.TaskName -TaskPath $entry.TaskPath }
    # Only the installed helper may still hold the executable open.
    Get-CimInstance Win32_Process -Filter "Name='djinn-custodian.exe'" | Where-Object {
        $_.ExecutablePath -eq $exe -and $_.CommandLine -match '\sconsent(?:\s|$)'
    } | ForEach-Object { Stop-Process -Id $_.ProcessId }
    Copy-Item -LiteralPath $source -Destination $exe -Force
    $staged = Join-Path $root ('week-policy-' + [guid]::NewGuid().ToString('N') + '.tmp')
    [IO.File]::WriteAllText($staged, $updated, (New-Object Text.UTF8Encoding($false)))
    [IO.File]::Replace($staged, $config, $null)
    if ($wasRunning) { Start-Service -Name djinn-custodian }
    foreach ($entry in $task) { Start-ScheduledTask -TaskName $entry.TaskName -TaskPath $entry.TaskPath }
    if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne $ExpectedSha256) {
        throw 'Installed executable hash mismatch.'
    }
    if ($wasRunning -and (Get-Service djinn-custodian).Status -ne 'Running') {
        throw 'Custodian did not return to Running.'
    }
    $receipt = @{ updated_utc = [DateTime]::UtcNow.ToString('o'); binary_sha256 = $ExpectedSha256;
        max_unlocked_seconds = 604800; previous_binary_sha256 = $oldHash; grants = 'preserved';
        vault = 'not-migrated'; qualification = 'installed-awaiting-unlock' }
    $receiptPath = Join-Path $backup ('installed-' + [guid]::NewGuid().ToString('N') + '.json')
    $receipt | ConvertTo-Json | Set-Content -LiteralPath $receiptPath -Encoding UTF8
    Write-Host 'Installed one-week maximum unlock policy. Unlock the resident once after this service restart.'
} catch {
    $failure = $_
    Stop-Service -Name djinn-custodian -ErrorAction SilentlyContinue
    foreach ($entry in $task) { Stop-ScheduledTask -TaskName $entry.TaskName -TaskPath $entry.TaskPath }
    Get-CimInstance Win32_Process -Filter "Name='djinn-custodian.exe'" | Where-Object {
        $_.ExecutablePath -eq $exe -and $_.CommandLine -match '\sconsent(?:\s|$)'
    } | ForEach-Object { Stop-Process -Id $_.ProcessId }
    Copy-Item -LiteralPath $oldExe -Destination $exe -Force
    [IO.File]::WriteAllBytes($config, $before)
    if ($wasRunning) { Start-Service -Name djinn-custodian }
    foreach ($entry in $task) { Start-ScheduledTask -TaskName $entry.TaskName -TaskPath $entry.TaskPath }
    throw $failure
}
