# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0
# Update the existing custodian without adopting a vault or changing grants.
# Run elevated after reviewing the receiving build and this script.
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$ExpectedSha256,
    [string]$ResultFile
)
$ErrorActionPreference = 'Stop'
$phase = 'preflight'
$rolledBack = $false
function Write-UpdateResult([string]$status, [string]$message, [int]$line) {
    if (-not $ResultFile) { return }
    $result = @{status=$status;phase=$phase;error=$message;line=$line;rolled_back=$rolledBack;
        expected_binary_sha256=$ExpectedSha256;utc=[DateTime]::UtcNow.ToString('o')}
    $stream = [IO.File]::Open($ResultFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json))
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
}
trap {
    Write-UpdateResult 'failed' $_.Exception.Message $_.InvocationInfo.ScriptLineNumber
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
if ($ResultFile -and (-not [IO.Path]::IsPathRooted($ResultFile) -or
    (Test-Path -LiteralPath $ResultFile) -or -not (Test-Path -LiteralPath (Split-Path -Parent $ResultFile)))) {
    throw 'Result path must be new, absolute, and under an existing private directory.'
}
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
if ($service.State -ne 'Running') {
    throw 'Restore the known working service before attempting an update from a stopped baseline.'
}
$before = [IO.File]::ReadAllBytes($config)
$policy = [Text.Encoding]::UTF8.GetString($before) | ConvertFrom-Json
$policy | Add-Member -NotePropertyName max_unlocked_seconds -NotePropertyValue 604800 -Force
$updated = $policy | ConvertTo-Json -Depth 32
$backup = Join-Path $root 'week-policy-backup'
$phase = 'backup'
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
$task = @(Get-ScheduledTask -TaskName 'djinn-custodian-consent')
if (-not ($task.Actions | Where-Object { $_.Execute -eq $exe -and $_.Arguments -match '^consent\b' })) {
    throw 'Installed consent task differs from the expected existing helper.'
}
function Wait-InstalledImageExit {
    Get-CimInstance Win32_Process -Filter "Name='djinn-custodian.exe'" | Where-Object {
        $_.ExecutablePath -eq $exe
    } | ForEach-Object {
        $process = Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue
        if ($process) {
            if ($_.CommandLine -match '\sconsent(?:\s|$)') {
                Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
            }
            if (-not $process.WaitForExit(10000)) { throw 'Installed custodian image is still in use after stop.' }
        }
    }
}
$wasRunning = $service.State -eq 'Running'
try {
    $phase = 'stop'
    if ($wasRunning) { Stop-Service -Name djinn-custodian }
    foreach ($entry in $task) { Stop-ScheduledTask -TaskName $entry.TaskName -TaskPath $entry.TaskPath }
    Wait-InstalledImageExit
    $phase = 'copy'
    Copy-Item -LiteralPath $source -Destination $exe -Force
    $phase = 'policy'
    $staged = Join-Path $root ('week-policy-' + [guid]::NewGuid().ToString('N') + '.tmp')
    [IO.File]::WriteAllText($staged, $updated, (New-Object Text.UTF8Encoding($false)))
    # Windows PowerShell 5 binds $null to an empty string for this overload.
    # A real create-new backup path both avoids that binding and retains the
    # exact replaced policy under the protected backup directory.
    $atomicBackup = Join-Path $backup ('policy-atomic-' + [guid]::NewGuid().ToString('N') + '.json')
    [IO.File]::Replace($staged, $config, $atomicBackup)
    $phase = 'restart'
    if ($wasRunning) { Start-Service -Name djinn-custodian }
    foreach ($entry in $task) { Start-ScheduledTask -TaskName $entry.TaskName -TaskPath $entry.TaskPath }
    $phase = 'verify'
    if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne $ExpectedSha256) {
        throw 'Installed executable hash mismatch.'
    }
    if ($wasRunning -and (Get-Service djinn-custodian).Status -ne 'Running') {
        throw 'Custodian did not return to Running.'
    }
    $phase = 'readiness'
    $readyUntil = [DateTime]::UtcNow.AddSeconds(15)
    do {
        if ((Get-Service djinn-custodian).Status -ne 'Running') {
            throw 'Custodian stopped after initial startup; restoring the known working files.'
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $readyUntil)
    if ((Get-Content -Raw -LiteralPath $config | ConvertFrom-Json).max_unlocked_seconds -ne 604800) {
        throw 'Installed duration policy mismatch.'
    }
    $phase = 'receipt'
    $receipt = @{ updated_utc = [DateTime]::UtcNow.ToString('o'); binary_sha256 = $ExpectedSha256;
        max_unlocked_seconds = 604800; previous_binary_sha256 = $oldHash; grants = 'preserved';
        vault = 'not-migrated'; qualification = 'installed-awaiting-unlock' }
    $receiptPath = Join-Path $backup ('installed-' + [guid]::NewGuid().ToString('N') + '.json')
    $receipt | ConvertTo-Json | Set-Content -LiteralPath $receiptPath -Encoding UTF8
    Write-UpdateResult 'updated' '' 0
    Write-Host 'Installed one-week maximum unlock policy. Unlock the resident once after this service restart.'
} catch {
    $failure = $_
    Stop-Service -Name djinn-custodian -ErrorAction SilentlyContinue
    foreach ($entry in $task) { Stop-ScheduledTask -TaskName $entry.TaskName -TaskPath $entry.TaskPath }
    Wait-InstalledImageExit
    Copy-Item -LiteralPath $oldExe -Destination $exe -Force
    [IO.File]::WriteAllBytes($config, $before)
    if ($wasRunning) { Start-Service -Name djinn-custodian }
    foreach ($entry in $task) { Start-ScheduledTask -TaskName $entry.TaskName -TaskPath $entry.TaskPath }
    $rolledBack = $true
    throw $failure
}
