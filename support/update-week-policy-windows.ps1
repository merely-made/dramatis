# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0
# Update existing custody; optional explicit remote-approval activation.
# Run elevated after reviewing the receiving build and this script.
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$ExpectedSha256,
    [string]$ResultFile,
    [string]$RemotePolicy,
    [string]$ExpectedRemotePolicySha256,
    [string]$ApprovalHelper,
    [string]$ExpectedHelperSha256
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
$enableRemote = [bool]$RemotePolicy
if (@($RemotePolicy,$ExpectedRemotePolicySha256,$ApprovalHelper,$ExpectedHelperSha256 | Where-Object { $_ }).Count -notin @(0,4)) {
    throw 'Remote activation requires the policy, helper, and both reviewed hashes.'
}
if ($enableRemote) {
    if ((Get-FileHash -LiteralPath $RemotePolicy -Algorithm SHA256).Hash -ne $ExpectedRemotePolicySha256 -or
        (Get-FileHash -LiteralPath $ApprovalHelper -Algorithm SHA256).Hash -ne $ExpectedHelperSha256) {
        throw 'Remote activation input differs from the reviewed package.'
    }
    $remote = Get-Content -Raw -LiteralPath $RemotePolicy | ConvertFrom-Json
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
if ($enableRemote) {
    if ($policy.remote_approval -or @($policy.principals | Where-Object { $_.name -eq 'approval-bridge' }).Count) {
        throw 'Remote approval is already configured; use an explicit policy update rather than resetting enrollment.'
    }
    if ($policy.vault.profile -and $policy.vault.profile -ne $remote.profile) {
        throw 'Remote policy profile differs from the existing fixed vault profile.'
    }
    $policy.vault | Add-Member -NotePropertyName profile -NotePropertyValue $remote.profile -Force
    $policy | Add-Member -NotePropertyName remote_approval -NotePropertyValue $remote -Force
    $helperExe = Join-Path $programRoot 'djinn-approval.exe'
    $approvalPrincipal = @{
        name='approval-bridge'; match=@{'windows-image'=@{sid=$policy.owner.windows_sid;image=$helperExe}}
        grants=@(@{operation='status'},@{operation='snapshot'},@{operation='remote-approval-bridge'},
            @{operation='attest';profile=@{named=$remote.profile};salts=@(@{delegation='merely.custody.remote-approval/v1'});consent='per-operation'},
            @{operation='sign';profile=@{named=$remote.profile};purpose=@{purpose='delegation';audience='merely.custody.remote-approval/v1'};consent='per-operation'})
    }
    $policy.principals = @($approvalPrincipal) + @($policy.principals)
}
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
    if ($enableRemote) {
        if (Test-Path -LiteralPath $helperExe) {
            $helperOldHash = (Get-FileHash -LiteralPath $helperExe -Algorithm SHA256).Hash
            $oldHelper = Join-Path $backup ('approval-helper-' + $helperOldHash + '.exe')
            if (-not (Test-Path -LiteralPath $oldHelper)) { Copy-Item -LiteralPath $helperExe -Destination $oldHelper }
        }
        Copy-Item -LiteralPath $ApprovalHelper -Destination $helperExe -Force
    }
    $phase = 'policy'
    $staged = Join-Path $root ('week-policy-' + [guid]::NewGuid().ToString('N') + '.tmp')
    [IO.File]::WriteAllText($staged, $updated, (New-Object Text.UTF8Encoding($false)))
    # Windows PowerShell 5 binds $null to an empty string for this overload.
    # A real create-new backup path both avoids that binding and retains the
    # exact replaced policy under the protected backup directory.
    $atomicBackup = Join-Path $backup ('policy-atomic-' + [guid]::NewGuid().ToString('N') + '.json')
    [IO.File]::Replace($staged, $config, $atomicBackup)
    & $exe validate-config --config $config
    if ($LASTEXITCODE -ne 0) { throw 'Receiving binary refused the updated policy.' }
    if ($enableRemote) {
        $phase = 'enrollment-store'
        & $exe remote-init --config $config
        if ($LASTEXITCODE -ne 0) { throw 'Could not initialize protected enrollment storage; preserving its result for inspection.' }
    }
    $phase = 'restart'
    if ($wasRunning) { Start-Service -Name djinn-custodian }
    foreach ($entry in $task) { Start-ScheduledTask -TaskName $entry.TaskName -TaskPath $entry.TaskPath }
    $phase = 'verify'
    if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne $ExpectedSha256) {
        throw 'Installed executable hash mismatch.'
    }
    if ($enableRemote -and (Get-FileHash -LiteralPath $helperExe -Algorithm SHA256).Hash -ne $ExpectedHelperSha256) {
        throw 'Installed approval helper hash mismatch.'
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
        max_unlocked_seconds = 604800; previous_binary_sha256 = $oldHash; remote_approval_enabled=$enableRemote;
        grants = $(if ($enableRemote) {'preserved-plus-explicit-approval-principal'} else {'preserved'});
        vault = 'not-migrated'; qualification = 'installed-awaiting-unlock' }
    $receiptPath = Join-Path $backup ('installed-' + [guid]::NewGuid().ToString('N') + '.json')
    $receipt | ConvertTo-Json | Set-Content -LiteralPath $receiptPath -Encoding UTF8
    Write-UpdateResult 'updated' '' 0
    Write-Host 'Updated custody policy. Unlock the resident once after this service restart.'
} catch {
    $failure = $_
    Stop-Service -Name djinn-custodian -ErrorAction SilentlyContinue
    foreach ($entry in $task) { Stop-ScheduledTask -TaskName $entry.TaskName -TaskPath $entry.TaskPath }
    Wait-InstalledImageExit
    Copy-Item -LiteralPath $oldExe -Destination $exe -Force
    if ($enableRemote -and $oldHelper) { Copy-Item -LiteralPath $oldHelper -Destination $helperExe -Force }
    [IO.File]::WriteAllBytes($config, $before)
    if ($wasRunning) { Start-Service -Name djinn-custodian }
    foreach ($entry in $task) { Start-ScheduledTask -TaskName $entry.TaskName -TaskPath $entry.TaskPath }
    $rolledBack = $true
    throw $failure
}
