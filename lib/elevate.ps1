param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Sid,
    [Parameter(Mandatory = $true)][string]$Interpreter,
    [Parameter(Mandatory = $true)][string]$Inner,
    [Parameter(Mandatory = $true)][string]$Out,
    [Parameter(Mandatory = $true)][string]$Launch,
    [string]$Log = $null
)

# Launcher for one CONSENTED elevation.
#
# The repair itself is `propagate.ps1`: it needs effective WRITE_DAC (and, for the
# Low integrity label, SeSecurityPrivilege). When the folder's owner is another
# machine's account, the signed-in user has neither — only an account whose
# Administrators group is ENABLED can rewrite that DACL, and that means Windows
# must ask the user first. `Start-Process -Verb RunAs` is exactly that ask: the
# UAC prompt is the audit trail, so nothing here ever bypasses it, retries it, or
# elevates without the user clicking "Yes".
#
# The elevated child writes its own JSON to `-Out`; this launcher writes what
# happened to the prompt itself to `-Launch`, so the caller can tell a cancelled
# prompt (nothing was touched) from a failed repair (something was attempted).
$ErrorActionPreference = 'Stop'
$result = [ordered]@{
    ok = $false
    canceled = $false
    stage = 'launch'
    exitCode = $null
    error = $null
}

# `Start-Process -ArgumentList` joins this array with spaces and does NOT quote
# entries, under both 5.1 and 7. A user profile such as "C:\Users\John Smith" would
# otherwise split `-File C:\Users\John Smith\...\propagate.ps1` into two arguments and
# the elevated helper would exit without a result. Quote only what needs it, so the
# common no-space path stays byte-identical to what was tested.
function Format-Argument([string]$value) {
    if ($value -match '[\s"]') {
        return '"' + ($value -replace '"', '\"') + '"'
    }
    return $value
}

$arguments = @(
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', (Format-Argument $Inner),
    '-Path', (Format-Argument $Path),
    '-Sid', (Format-Argument $Sid),
    '-Out', (Format-Argument $Out)
)
if ($Log) { $arguments += @('-Log', (Format-Argument $Log)) }

try {
    $process = Start-Process -FilePath $Interpreter -Verb RunAs -Wait -PassThru -ArgumentList $arguments
    $result.stage = 'elevated'
    $result.ok = $true
    if ($null -ne $process) { $result.exitCode = $process.ExitCode }
} catch {
    $code = -1
    try { $code = [int]$_.Exception.NativeErrorCode } catch { $code = -1 }
    # 1223 = ERROR_CANCELLED: the user declined the UAC prompt (or it timed out).
    if ($code -eq 1223 -or $_.Exception.Message -match 'cancel|取消') {
        $result.canceled = $true
        $result.stage = 'uac-cancelled'
    } else {
        $result.error = $_.Exception.Message
        $result.stage = 'uac-failed'
    }
}

[System.IO.File]::WriteAllText($Launch, ($result | ConvertTo-Json -Compress -Depth 4))
