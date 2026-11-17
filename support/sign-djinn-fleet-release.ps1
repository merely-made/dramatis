# Copyright 2026 Mark Alan Boykin
# SPDX-License-Identifier: MPL-2.0
# Run on O-PC under the Windows user who holds the Djinn fleet publisher key.

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Path
)

$ErrorActionPreference = 'Stop'
$file = Get-Item -LiteralPath $Path
if ($file.PSIsContainer -or (Test-Path -LiteralPath "$($file.FullName).sig")) {
    throw 'Pass a regular file without an existing detached signature.'
}

$keyDirectory = Join-Path $env:LOCALAPPDATA 'Merely/release-keys/djinn-fleet'
$key = Join-Path $keyDirectory 'publisher.key'
$unlockFile = Join-Path $keyDirectory 'unlock.dpapi'
$packager = (Get-Command cargo-packager.exe -CommandType Application).Source
$start = [Diagnostics.ProcessStartInfo]::new($packager)
$start.UseShellExecute = $false
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$password = Get-Content -LiteralPath $unlockFile -Raw | ConvertTo-SecureString
$passwordBuffer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)

try {
    $start.Environment['CARGO_PACKAGER_SIGN_PRIVATE_KEY_PASSWORD'] = (
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordBuffer)
    )
    foreach ($argument in 'signer', 'sign', '--private-key', $key, $file.FullName) {
        $start.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::Start($start)
    $output = $process.StandardOutput.BaseStream.CopyToAsync([IO.Stream]::Null)
    $errors = $process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
    $process.WaitForExit()
    [void] $output.GetAwaiter().GetResult()
    [void] $errors.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) {
        throw "cargo-packager could not sign $($file.Name) (exit $($process.ExitCode))."
    }
} finally {
    [void] $start.Environment.Remove('CARGO_PACKAGER_SIGN_PRIVATE_KEY_PASSWORD')
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordBuffer)
    $password.Dispose()
    if ($process) { $process.Dispose() }
}

Get-Item -LiteralPath "$($file.FullName).sig"
