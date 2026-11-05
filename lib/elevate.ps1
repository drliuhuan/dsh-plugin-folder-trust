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

$arguments = @(
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', $Inner,
    '-Path', $Path,
    '-Sid', $Sid,
    '-Out', $Out
)
if ($Log) { $arguments += @('-Log', $Log) }

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
