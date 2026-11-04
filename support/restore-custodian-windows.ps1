# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0
# Restore the known working service/policy after a failed receiving update.
param(
    [Parameter(Mandatory = $true)][string]$BinarySha256,
    [Parameter(Mandatory = $true)][string]$ResultFile
)
$ErrorActionPreference = 'Stop'
$phase = 'preflight'
function Write-RestoreResult([string]$status, [string]$message) {
    $record = @{status=$status;phase=$phase;error=$message;binary_sha256=$BinarySha256;utc=[DateTime]::UtcNow.ToString('o')}
    $bytes = [Text.Encoding]::UTF8.GetBytes(($record | ConvertTo-Json))
    $stream = [IO.File]::Open($ResultFile,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write)
    try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}
trap { Write-RestoreResult 'failed' $_.Exception.Message; [Console]::Error.WriteLine($_.Exception.Message); exit 1 }
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Native administrator elevation is required.' }
if ($BinarySha256 -notmatch '^[0-9A-Fa-f]{64}$' -or -not [IO.Path]::IsPathRooted($ResultFile) -or (Test-Path -LiteralPath $ResultFile)) {
    throw 'Expected binary hash and a new absolute result path are required.'
}
$exe = Join-Path $env:ProgramFiles 'Merely\djinn-custodian\djinn-custodian.exe'
$root = 'C:\ProgramData\djinn-custodian'
$config = Join-Path $root 'custodian.json'
$backup = Join-Path $root 'week-policy-backup'
$oldExe = Join-Path $backup ('custodian-' + $BinarySha256 + '.exe')
if ((Get-FileHash -LiteralPath $oldExe -Algorithm SHA256).Hash -ne $BinarySha256) { throw 'Backup executable hash mismatch.' }
$service = Get-CimInstance Win32_Service -Filter "Name='djinn-custodian'"
if ($service.PathName -ne ('"' + $exe + '" --config "' + $config + '"')) { throw 'Unexpected installed service command.' }
$current = Get-Content -Raw -LiteralPath $config | ConvertFrom-Json
$current.PSObject.Properties.Remove('max_unlocked_seconds')
$expectedPolicy = $current | ConvertTo-Json -Depth 32 -Compress
$candidates = @(Get-ChildItem -LiteralPath $backup -File | Where-Object { $_.Name -match '^policy-[0-9A-Fa-f]{64}\.json$' } | Where-Object {
    $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    $validName = $_.BaseName.Substring(7) -eq $hash
    $policy = Get-Content -Raw -LiteralPath $_.FullName | ConvertFrom-Json
    $validName -and -not $policy.PSObject.Properties['max_unlocked_seconds'] -and (($policy | ConvertTo-Json -Depth 32 -Compress) -eq $expectedPolicy)
})
if ($candidates.Count -ne 1) { throw 'An unambiguous matching original policy is required before restoration.' }
$task = Get-ScheduledTask -TaskName 'djinn-custodian-consent'
if (-not ($task.Actions | Where-Object { $_.Execute -eq $exe -and $_.Arguments -match '^consent\b' })) { throw 'Unexpected installed consent helper.' }
$phase = 'stop'
Stop-Service -Name djinn-custodian -ErrorAction SilentlyContinue
Stop-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath
Get-CimInstance Win32_Process -Filter "Name='djinn-custodian.exe'" | Where-Object { $_.ExecutablePath -eq $exe } | ForEach-Object {
    $process = Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue
    if ($process) {
        if ($_.CommandLine -match '\sconsent(?:\s|$)') { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        if (-not $process.WaitForExit(10000)) { throw 'Installed image is still in use after stop.' }
    }
}
$phase = 'restore'
Copy-Item -LiteralPath $oldExe -Destination $exe -Force
$staged = Join-Path $root ('restore-policy-' + [guid]::NewGuid().ToString('N') + '.tmp')
Copy-Item -LiteralPath $candidates[0].FullName -Destination $staged
$failedPolicy = Join-Path $backup ('policy-failed-' + [guid]::NewGuid().ToString('N') + '.json')
[IO.File]::Replace($staged,$config,$failedPolicy)
$phase = 'restart'
Start-Service -Name djinn-custodian
Start-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath
$phase = 'readiness'
$until = [DateTime]::UtcNow.AddSeconds(10)
do {
    if ((Get-Service djinn-custodian).Status -ne 'Running') { throw 'Restored service did not remain running.' }
    Start-Sleep -Milliseconds 250
} while ([DateTime]::UtcNow -lt $until)
if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne $BinarySha256) { throw 'Restored binary hash mismatch.' }
if ((Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $candidates[0].FullName -Algorithm SHA256).Hash) {
    throw 'Restored policy bytes mismatch.'
}
Write-RestoreResult 'restored' ''
