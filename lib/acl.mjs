// Windows ACL inspection and repair for the folder-trust plugin.
//
// DSH's workspace-write sandbox provisions its per-workspace write grant with
// SetNamedSecurityInfoW (workspace SID ACE + Everyone DELETE_CHILD deny + Low
// integrity label). That single call needs effective WRITE_DAC *and*
// WRITE_OWNER on the workspace root; when either is missing the call fails with
// Win32 5 and every confined shell invocation is refused before it runs.
//
// This module answers two questions for one directory, using the same token as
// the harness (no elevation):
//   probeDirectory(dir) -> which of the two rights are effectively granted
//   grantFullControl(dir) -> add a non-inherited FullControl allow ACE for the
//                            signed-in user when missing, then re-read the DACL
//
// The helpers used to run under Windows PowerShell 5.1 because the scripts called
// `DirectoryInfo.GetAccessControl()` / `SetAccessControl()`, which are .NET Framework
// extension methods that no longer exist under .NET 10 (PowerShell 7.6 reports
// "does not contain a method named 'GetAccessControl'"). They now use the `Get-Acl` /
// `Set-Acl` cmdlets instead: those are portable across 5.1 and 7, they write the DACL
// BY PATH (so an inheritable ACE still propagates into the subfolders that already
// exist), and they leave the owner and the integrity label alone. The one operation the
// framework cannot express portably — stamping the Low integrity label — stays P/Invoke
// inside the scripts, which works under either interpreter.
//
// So the interpreter is chosen rather than assumed: PowerShell 7 when it is present,
// Windows PowerShell 5.1 only as the last resort, and FOLDER_TRUST_POWERSHELL pins one
// explicitly when an operator needs to.
//
// The result is read from a JSON file rather than stdout, so the same code also runs
// under DSH's confined shell, where piped grandchild stdio is unavailable.

import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Windows PowerShell 5.1: present on every Windows 10/11, and the last resort. */
const FALLBACK_POWERSHELL = 'powershell.exe';

/** Which interpreter the helpers use; filled in on the first successful spawn. */
let resolvedInterpreter;

/**
 * Interpreter candidates, best first.
 *
 * PowerShell 7 in its installer's default locations comes first, then `pwsh.exe` from
 * PATH (a 7 installed somewhere else, or a portable one), and only then Windows
 * PowerShell 5.1. A missing file surfaces as ENOENT at spawn time, which is what moves
 * the runner down the list — no separate `where` probe and no guessing.
 * @param {object} [env] environment to read (tests).
 * @param {string} [platform] platform to assume (tests).
 * @returns {string[]} at least one entry.
 */
export function powerShellCandidates(env = process.env, platform = process.platform) {
  const pinned = env.FOLDER_TRUST_POWERSHELL;
  if (typeof pinned === 'string' && pinned.trim() !== '') return [pinned];
  if (platform !== 'win32') return ['pwsh'];
  const candidates = [];
  for (const root of [env.ProgramW6432, env.ProgramFiles, env['ProgramFiles(x86)']]) {
    if (typeof root === 'string' && root !== '') candidates.push(join(root, 'PowerShell', '7', 'pwsh.exe'));
  }
  candidates.push('pwsh.exe');
  candidates.push(FALLBACK_POWERSHELL);
  return [...new Set(candidates)];
}

/**
 * The interpreter a caller would try first, for settings surfaces and tests.
 * @param {object} [env] environment to read.
 * @param {string} [platform] platform to assume.
 * @returns {string}
 */
export function preferredPowerShell(env = process.env, platform = process.platform) {
  return resolvedInterpreter ?? powerShellCandidates(env, platform)[0];
}

/**
 * Candidates still worth trying, starting from the memoized winner.
 * @returns {string[]}
 */
function interpreterQueue() {
  const all = powerShellCandidates();
  if (resolvedInterpreter === undefined) return all;
  return [resolvedInterpreter, ...all.filter((candidate) => candidate !== resolvedInterpreter)];
}

/** Helper processes still running; killed on dispose so quitting waits for nothing. */
const activeHelpers = new Set();

/** Kill every helper this process spawned (plugin dispose / harness quit). */
export function killActiveHelpers() {
  for (const child of activeHelpers) {
    try { child.kill(); } catch { /* already gone */ }
  }
  activeHelpers.clear();
}

const PROBE_SCRIPT = String.raw`
param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = 'Stop'
$result = [ordered]@{ path = $Path; ok = $false }
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class DshFolderTrustProbe {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr attributes, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
    public static int Open(string path, uint access) {
        IntPtr handle = CreateFileW(path, access, 7u, IntPtr.Zero, 3u, 0x02000000u, IntPtr.Zero);
        if (handle == new IntPtr(-1)) return Marshal.GetLastWin32Error();
        CloseHandle(handle);
        return 0;
    }
}
'@
    $dacError = 0
    $ownerError = 0
    try { $dacError = [DshFolderTrustProbe]::Open($Path, [uint32]0x00040000) } catch { $dacError = -1 }
    try { $ownerError = [DshFolderTrustProbe]::Open($Path, [uint32]0x00080000) } catch { $ownerError = -1 }
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $acl = Get-Acl -LiteralPath $Path
    $result.sid = $identity.User.Value
    # Get-Acl returns the owner in SDDL form ("O:S-1-5-21-..."), not a bare SID.
    $result.owner = ([string]$acl.Owner) -replace '^O:', ''
    $result.writeDac = ($dacError -eq 0)
    $result.writeOwner = ($ownerError -eq 0)
    # An owner SID that still resolves locally can hand its implicit WRITE_DAC to
    # the signed-in account only if it IS that account; a SID nothing resolves
    # (a folder copied from another PC) is 'foreign' and needs an elevation.
    $result.ownerName = $result.owner
    $result.ownerKind = 'unknown'
    try {
        $ownerIdentity = New-Object System.Security.Principal.SecurityIdentifier($result.owner)
        try { $result.ownerName = $ownerIdentity.Translate([System.Security.Principal.NTAccount]).Value } catch { }
        if ($ownerIdentity.Value -eq $identity.User.Value) { $result.ownerKind = 'current' }
        elseif ($result.owner -eq 'S-1-5-18' -or $result.owner.StartsWith('S-1-5-32-')) { $result.ownerKind = 'system' }
        elseif ($result.ownerName -eq $result.owner) { $result.ownerKind = 'foreign' }
        else { $result.ownerKind = 'local-other' }
    } catch {
        $result.ownerKind = 'unknown'
    }
    $result.dacError = $dacError
    $result.ownerError = $ownerError
    $result.ok = $true
} catch {
    $result.error = $_.Exception.Message
}
[System.IO.File]::WriteAllText($Out, ($result | ConvertTo-Json -Compress))
`;

const GRANT_SCRIPT = String.raw`
param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Out)
$ErrorActionPreference = 'Stop'
$result = [ordered]@{ path = $Path; ok = $false; changed = $false; granted = $false }
try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $sid = $identity.User
    $full = [System.Security.AccessControl.FileSystemRights]'FullControl'
    $result.sid = $sid.Value

    function Get-AceSid($ace) {
        try { return $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { return $ace.IdentityReference.Value }
    }

    function Test-FullControl($acl) {
        $count = @($acl.Access | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            (Get-AceSid $_) -eq $sid.Value -and
            (([int]$_.FileSystemRights -band [int]$full) -eq [int]$full)
        }).Count
        return ($count -gt 0)
    }

    $info = New-Object System.IO.DirectoryInfo($Path)
    $acl = Get-Acl -LiteralPath $Path
    if (-not (Test-FullControl $acl)) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $full, 'Allow')
        $acl.AddAccessRule($rule)
        # Set-Acl writes by path, so Windows still runs its inherit pass into the
        # subfolders that already exist.
        Set-Acl -LiteralPath $Path -AclObject $acl
        $result.changed = $true
    }
    $after = Get-Acl -LiteralPath $Path
    $result.granted = Test-FullControl $after
    $result.ok = $true
} catch {
    $result.error = $_.Exception.Message
}
[System.IO.File]::WriteAllText($Out, ($result | ConvertTo-Json -Compress))
`;

let scriptDir;

/** Materialize the PowerShell helpers once per process. */
function ensureScripts() {
  if (scriptDir !== undefined) {
    // Re-copy the on-disk helpers on every call so editing a .ps1 takes effect
    // without reloading the harness; the embedded ones never change.
    try {
      writeFileSync(join(scriptDir, 'propagate.ps1'), readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'propagate.ps1')));
      writeFileSync(join(scriptDir, 'inspect.ps1'), readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'inspect.ps1')));
      writeFileSync(join(scriptDir, 'elevate.ps1'), readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'elevate.ps1')));
    } catch {
      // report the missing helper at call time
    }
    return scriptDir;
  }
  const dir = mkdtempSync(join(tmpdir(), 'dsh-folder-trust-'));
  writeFileSync(join(dir, 'probe.ps1'), PROBE_SCRIPT, 'utf8');
  writeFileSync(join(dir, 'grant.ps1'), GRANT_SCRIPT, 'utf8');
  try {
    writeFileSync(join(dir, 'propagate.ps1'), readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'propagate.ps1')));
    writeFileSync(join(dir, 'inspect.ps1'), readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'inspect.ps1')));
    writeFileSync(join(dir, 'elevate.ps1'), readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'elevate.ps1')));
  } catch {
    // the propagation step reports the missing helper at call time
  }
  scriptDir = dir;
  return dir;
}

/** A spawn that never started (missing interpreter) — the only error worth retrying. */
function isMissingExecutable(error) {
  return error !== null && typeof error === 'object' && error.code === 'ENOENT';
}

/** What to report when no candidate interpreter could be started at all. */
function noInterpreterError(attempts) {
  return `no PowerShell interpreter could be started (tried ${attempts.join(', ')}); install PowerShell 7 or pin FOLDER_TRUST_POWERSHELL`;
}

/**
 * The module search path Windows PowerShell 5.1 must see.
 *
 * 5.1 may not inherit the module paths a PowerShell 7 parent exports. It then
 * resolves `Microsoft.PowerShell.Security` against 7's assemblies, cannot load the
 * module, and every `Get-Acl` dies with "the member ... is already present" — the
 * fallback silently stops working on exactly the machines that have no PowerShell 7
 * of their own but run under a harness that does. Rebuild the value from the three
 * 5.1 locations instead: the user's own modules, the machine-wide modules, and
 * System32's.
 * @param {object} [env] environment to read.
 * @returns {string} a `;`-separated list of Windows PowerShell module directories.
 */
export function windowsPowerShellModulePath(env = process.env) {
  const parts = [];
  if (typeof env.USERPROFILE === 'string' && env.USERPROFILE !== '') {
    parts.push(join(env.USERPROFILE, 'Documents', 'WindowsPowerShell', 'Modules'));
  }
  if (typeof env.ProgramFiles === 'string' && env.ProgramFiles !== '') {
    parts.push(join(env.ProgramFiles, 'WindowsPowerShell', 'Modules'));
  }
  const systemRoot = env.SystemRoot ?? env.windir ?? 'C:\\Windows';
  parts.push(join(systemRoot, 'system32', 'WindowsPowerShell', 'v1.0', 'Modules'));
  return parts.join(';');
}

/**
 * Environment for one helper process: the parent's, except that Windows PowerShell
 * 5.1 gets a module path it can actually load. PowerShell 7 keeps what it inherited.
 * @param {string} interpreter the executable about to be spawned.
 * @returns {NodeJS.ProcessEnv}
 */
function helperEnvironment(interpreter) {
  const env = { ...process.env };
  if (basename(interpreter).toLowerCase() === FALLBACK_POWERSHELL) {
    env.PSModulePath = windowsPowerShellModulePath(env);
  }
  return env;
}

/**
 * Run one helper script against a directory and read its JSON result.
 * @param {'probe.ps1'|'grant.ps1'} script script file name.
 * @param {string} dir absolute directory path.
 * @returns {{ ok: boolean, result?: object, error?: string }}
 */
function runHelper(script, dir) {
  const base = ensureScripts();
  const outFile = join(base, `out-${process.pid}-${Date.now()}.json`);
  const argv = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', join(base, script), '-Path', dir, '-Out', outFile];
  const tried = [];
  try {
    for (const interpreter of interpreterQueue()) {
      tried.push(interpreter);
      const run = spawnSync(interpreter, argv, { stdio: 'ignore', windowsHide: true, timeout: 30_000, env: helperEnvironment(interpreter) });
      if (run.error !== undefined) {
        if (isMissingExecutable(run.error)) continue;
        return { ok: false, error: String(run.error.message ?? run.error) };
      }
      resolvedInterpreter = interpreter;
      if (run.status !== 0) return { ok: false, error: `${script} exited with ${String(run.status)}` };
      const parsed = JSON.parse(readFileSync(outFile, 'utf8'));
      if (typeof parsed?.error === 'string') return { ok: false, error: parsed.error };
      return { ok: true, result: parsed };
    }
    return { ok: false, error: noInterpreterError(tried) };
  } catch (error) {
    return { ok: false, error: String(error?.message ?? error) };
  } finally {
    try {
      rmSync(outFile, { force: true });
    } catch {
      // best effort
    }
  }
}

/**
 * Async helper runner: spawn + read the JSON result file, WITHOUT blocking the
 * host event loop. Every probe used to be spawnSync, which froze the harness
 * (and every session switch) for the duration of each PowerShell start.
 * @param {string} script helper file name inside the materialized script dir.
 * @param {string} dir directory argument.
 * @param {string[]} [extra] additional argv pairs before -Out.
 * @returns {Promise<{ ok: boolean, result?: object, error?: string }>}
 */
function runHelperAsync(script, dir, extra = []) {
  const base = ensureScripts();
  const outFile = join(base, `out-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}.json`);
  const argv = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', join(base, script), '-Path', dir, ...extra, '-Out', outFile];
  const queue = interpreterQueue();
  return new Promise((resolve) => {
    const tried = [];
    let index = 0;
    let settled = false;
    let timer;
    let child;
    const done = (outcome) => {
      if (settled) return;
      settled = true;
      if (child !== undefined) activeHelpers.delete(child);
      if (timer !== undefined) clearTimeout(timer);
      try { rmSync(outFile, { force: true }); } catch { /* best effort */ }
      resolve(outcome);
    };
    function attempt() {
      if (index >= queue.length) {
        done({ ok: false, error: noInterpreterError(tried) });
        return;
      }
      const interpreter = queue[index++];
      tried.push(interpreter);
      child = spawn(interpreter, argv, { stdio: 'ignore', windowsHide: true, env: helperEnvironment(interpreter) });
      activeHelpers.add(child);
      timer = setTimeout(() => { try { child.kill(); } catch { /* gone */ } }, 120_000);
      timer.unref?.();
      child.on('error', (error) => {
        // Only a missing interpreter moves down the list; anything else is a real
        // failure and must not be masked by a second attempt.
        if (settled) return;
        if (isMissingExecutable(error) && index < queue.length) {
          activeHelpers.delete(child);
          if (timer !== undefined) clearTimeout(timer);
          attempt();
          return;
        }
        done({ ok: false, error: String(error && error.message ? error.message : error) });
      });
      child.on('exit', (status) => {
        if (settled) return;
        resolvedInterpreter = interpreter;
        if (status !== 0) { done({ ok: false, error: script + ' exited with ' + String(status) }); return; }
        try {
          const parsed = JSON.parse(readFileSync(outFile, 'utf8'));
          if (typeof parsed.error === 'string' && parsed.error.length > 0) { done({ ok: false, error: parsed.error }); return; }
          done({ ok: true, result: parsed });
        } catch (error) {
          done({ ok: false, error: String(error && error.message ? error.message : error) });
        }
      });
    }
    attempt();
  });
}
/**
 * Effective rights on one directory for the signed-in user.
 * @param {string} dir absolute directory path.
 * @returns {{ state: 'ok'|'denied'|'error', writeDac: boolean, writeOwner: boolean, owner?: string, sid?: string, error?: string }}
 */
export async function probeDirectory(dir) {
  const run = await runHelperAsync('probe.ps1', dir);
  if (!run.ok) return { state: 'error', writeDac: false, writeOwner: false, error: run.error };
  const result = run.result;
  return {
    state: result.writeDac === true && result.writeOwner === true ? 'ok' : 'denied',
    writeDac: result.writeDac === true,
    writeOwner: result.writeOwner === true,
    owner: result.owner,
    ownerName: result.ownerName,
    // 'current' | 'local-other' | 'system' | 'foreign' | 'unknown'. A 'foreign'
    // owner is an account SID that does not resolve on this machine (the folder
    // was copied from another PC): the signed-in user can never inherit the
    // owner's implicit WRITE_DAC, so only an approved elevation can repair it.
    ownerKind: typeof result.ownerKind === 'string' ? result.ownerKind : 'unknown',
    sid: result.sid
  };
}
/**
 * Add the signed-in user's FullControl allow ACE when the directory does not
 * already carry it. Re-reads the DACL afterwards; never removes anything.
 * @param {string} dir absolute directory path.
 * @returns {{ ok: boolean, changed: boolean, granted: boolean, error?: string }}
 */
export async function grantFullControl(dir) {
  const run = await runHelperAsync('grant.ps1', dir);
  if (!run.ok) return { ok: false, changed: false, granted: false, error: run.error };
  const result = run.result;
  return {
    ok: result.granted === true,
    changed: result.changed === true,
    granted: result.granted === true
  };
}

/**
 * The interpreter the ELEVATED helper must run under.
 *
 * This is not `interpreterQueue()[0]` on purpose. That queue answers "what can the
 * harness spawn right now", and its entries may be a bare `pwsh.exe` (PATH lookup) or
 * a per-user portable copy such as the one a plugin installs under AppData. Both are
 * wrong across an elevation boundary: `Start-Process -Verb RunAs` needs an absolute
 * path it can hand to ShellExecute, and UAC may switch the child to a *different*
 * administrator account whose profile does not contain the signed-in user's portable
 * install. Only two locations exist for every account on every Windows install:
 *
 *   1. a machine-wide PowerShell 7 install (`%ProgramFiles%\PowerShell\7`),
 *   2. Windows PowerShell 5.1 in System32, which no Windows 10/11 lacks.
 *
 * Both interpreters are supported by the helpers (`Get-Acl`/`Set-Acl` plus P/Invoke
 * for the label), so pinning the fallback is not a downgrade. `FOLDER_TRUST_POWERSHELL`
 * still wins when an operator deliberately pins one.
 * @param {object} [env] environment to read (tests).
 * @returns {string} an absolute path, never a bare executable name.
 */
export function elevatedPowerShell(env = process.env) {
  const pinned = env.FOLDER_TRUST_POWERSHELL;
  if (typeof pinned === 'string' && pinned.trim() !== '') return pinned;
  for (const root of [env.ProgramW6432, env.ProgramFiles]) {
    if (typeof root !== 'string' || root === '') continue;
    const candidate = join(root, 'PowerShell', '7', 'pwsh.exe');
    if (existsSync(candidate)) return candidate;
  }
  // Windows PowerShell 5.1: present on every supported Windows, readable by every
  // account, and reached by an absolute path that needs no PATH search.
  const systemRoot = env.SystemRoot ?? env.windir ?? 'C:\\Windows';
  return join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
}

/**
 * Rewrite a folder's permissions through an APPROVED elevation (UAC).
 *
 * `grantFullControl()` can only succeed when the signed-in account already has
 * effective WRITE_DAC. Three situations break that: the folder is owned by an
 * account SID that no longer resolves locally (copied from another PC), it is
 * owned by SYSTEM/builtin, or its DACL explicitly denies the right. Windows only
 * lets an account whose Administrators group is enabled rewrite such a DACL, and
 * enabling that group is exactly what the UAC prompt asks the user to approve.
 *
 * The prompt is the audit trail: nothing here elevates silently, retries after a
 * refusal, or runs without a human clicking "Yes". A declined prompt leaves the
 * folder untouched and is reported as `canceled: true`.
 * @param {string} dir workspace directory.
 * @param {(line: string) => void} [onLine] progress lines from the elevated helper.
 * @param {AbortSignal} [signal] aborts the wait when the browser goes away.
 * @returns {Promise<{ok: boolean, canceled?: boolean, changed?: boolean, error?: string, propagation?: object}>}
 */
export function repairElevated(dir, onLine = () => {}, signal) {
  const base = ensureScripts();
  const stamp = `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const innerOut = join(base, `elev-${stamp}.json`);
  const launchOut = join(base, `elev-${stamp}-launch.json`);
  const logFile = join(base, `elev-${stamp}.log`);
  // Absolute and machine-wide: see elevatedPowerShell() above for why neither a bare
  // `pwsh.exe` nor a per-user portable install survives the elevation boundary.
  const interpreter = elevatedPowerShell();
  const argv = [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', join(base, 'elevate.ps1'),
    '-Path', dir,
    '-Sid', workspaceWriteSid(dir),
    '-Interpreter', interpreter,
    '-Inner', join(base, 'propagate.ps1'),
    '-Out', innerOut,
    '-Launch', launchOut,
    '-Log', logFile
  ];
  return new Promise((resolve) => {
    const child = spawn(interpreter, argv, { stdio: 'ignore', windowsHide: true, env: helperEnvironment(interpreter) });
    activeHelpers.add(child);
    let settled = false;
    let offset = 0;
    const drain = () => {
      try {
        const buffer = readFileSync(logFile);
        if (buffer.length <= offset) return;
        const text = buffer.toString('utf8', offset);
        offset = buffer.length;
        for (const raw of text.split('\n')) {
          const line = raw.trim();
          if (line.length > 0) onLine(line);
        }
      } catch {
        // the elevated helper creates its log only after the user approves
      }
    };
    const timer = setInterval(drain, 250);
    timer.unref?.();
    // A human decides at the prompt, so this cap is only a backstop for a dialog
    // that is never answered; it never shortens an approval the user is reading.
    const timeout = setTimeout(() => { try { child.kill(); } catch { /* gone */ } }, 600_000);
    timeout.unref?.();
    const cleanup = () => {
      clearInterval(timer);
      clearTimeout(timeout);
      for (const file of [innerOut, launchOut, logFile]) {
        try { rmSync(file, { force: true }); } catch { /* best effort */ }
      }
      activeHelpers.delete(child);
    };
    const finish = (outcome) => {
      if (settled) return;
      settled = true;
      drain();
      cleanup();
      resolve(outcome);
    };
    const abort = () => { try { child.kill(); } catch { /* gone */ } };
    if (signal !== undefined && typeof signal.addEventListener === 'function') {
      if (signal.aborted) abort();
      else signal.addEventListener('abort', abort, { once: true });
    }
    child.on('error', (error) => {
      finish({ ok: false, canceled: false, error: String(error && error.message ? error.message : error) });
    });
    child.on('exit', () => {
      drain();
      let launch;
      try { launch = JSON.parse(readFileSync(launchOut, 'utf8')); } catch { launch = undefined; }
      if (launch === undefined) {
        finish({
          ok: false,
          canceled: false,
          error: 'the elevated helper produced no result; the UAC prompt was dismissed or blocked by policy'
        });
        return;
      }
      if (launch.canceled === true) {
        finish({ ok: false, canceled: true, error: 'elevation was cancelled; nothing was changed' });
        return;
      }
      if (launch.ok !== true) {
        finish({ ok: false, canceled: false, error: launch.error ?? 'elevation failed' });
        return;
      }
      let propagation;
      try { propagation = JSON.parse(readFileSync(innerOut, 'utf8')); } catch { propagation = undefined; }
      if (propagation === undefined) {
        finish({ ok: false, canceled: false, error: 'the elevated helper wrote no result' });
        return;
      }
      finish({
        ok: propagation.ok === true,
        canceled: false,
        changed: true,
        propagation,
        error: propagation.ok === true ? undefined : (propagation.error ?? 'the elevated repair did not finish')
      });
    });
  });
}

/**
 * Derive DSH's workspace write SID the same way `@deepseek-ai/dsh-sandbox-windows-acl`
 * does: sha256 over the canonical (realpath) path, subauthorities 30-bit.
 * @param {string} dir workspace directory.
 * @returns {string} `S-1-4-x-y`.
 */
export function workspaceWriteSid(dir) {
  let canonical = dir;
  try {
    canonical = realpathSync.native(dir);
  } catch {
    // keep the as-spelled path; the ACE then simply does not match DSH's SID
  }
  const digest = createHash('sha256').update(canonical, 'utf8').digest();
  const bound = 2 ** 30 - 1;
  return `S-1-4-${(digest.readUInt32LE(0) % bound) + 1}-${(digest.readUInt32LE(4) % bound) + 1}`;
}

/**
 * Stamp the workspace the way the Windows sandbox expects and push the grant
 * through the whole existing subtree. Async: it never blocks the host loop.
 * @param {string} dir workspace directory.
 * @returns {Promise<object>} the helper's result.
 */
export async function propagateWorkspace(dir) {
  return propagateWorkspaceStream(dir, () => {});
}
/**
 * Read the permission state of one workspace folder: the two rights the harness
 * needs, whether the capability grant and ambient-deny already sit on the root,
 * and how many immediate child folders carry the inherited grant.
 * @param {string} dir workspace directory.
 * @returns {object} the report, or a failure with `error`.
 */
/**
 * Read the permission state of one workspace folder. Async by design: it spawns
 * one helper and never blocks the host event loop.
 * @param {string} dir workspace directory.
 * @returns {Promise<object>} the report, or a failure with `error`.
 */
export async function inspectWorkspace(dir) {
  const sid = workspaceWriteSid(dir);
  const run = await runHelperAsync('inspect.ps1', dir, ['-Sid', sid]);
  if (!run.ok) return { ok: false, error: run.error };
  return { ...run.result, ok: run.result.ok === true };
}
/**
 * True when the harness temp directory lives inside the workspace, which the ACL
 * sandbox refuses outright (`temp root must be outside the workspace`) no matter
 * what the folder's permissions are.
 * @param {string} dir absolute workspace path.
 * @param {string} [tempRoot] temp root to compare, defaults to os.tmpdir().
 * @returns {boolean}
 */
/**
 * True when the harness temp directory lives inside the workspace, which the ACL
 * sandbox refuses outright (`temp root must be outside the workspace`).
 * @param {string} dir absolute workspace path.
 * @param {string} [tempRoot] temp root to compare, defaults to os.tmpdir().
 * @returns {boolean}
 */
export function containsTempRoot(dir, tempRoot = tmpdir()) {
  const normalize = (value) => value.replaceAll('/', '\\').replace(/\\+$/, '').toLowerCase();
  const workspace = normalize(dir);
  const temp = normalize(tempRoot);
  return temp === workspace || temp.startsWith(`${workspace}\\`);
}

/**
 * Streaming variant of propagateWorkspace: spawns the helper with a log file,
 * tails it while the child runs and reports every line, so the browser can show
 * what the repair is doing and the host loop is never blocked.
 * @param {string} dir workspace directory.
 * @param {(line: string) => void} onLine progress line sink.
 * @param {AbortSignal} [signal] aborts the helper when the client goes away.
 * @returns {Promise<object>} the helper's JSON result.
 */
export function propagateWorkspaceStream(dir, onLine, signal) {
  const queue = interpreterQueue();
  const attempt = (index) => runPropagate(queue[index], dir, onLine, signal)
    .then((outcome) => (outcome?.missingInterpreter === true && index + 1 < queue.length
      ? attempt(index + 1)
      : outcome));
  return attempt(0);
}

/**
 * One propagate attempt with one interpreter; a missing executable is reported as
 * `{ missingInterpreter: true }` so the caller can move down the candidate list.
 * @param {string} interpreter PowerShell executable to spawn.
 * @param {string} dir workspace directory.
 * @param {(line: string) => void} onLine progress line sink.
 * @param {AbortSignal} [signal] aborts the helper when the client goes away.
 * @returns {Promise<object>} the helper's JSON result.
 */
function runPropagate(interpreter, dir, onLine, signal) {
  const sid = workspaceWriteSid(dir);
  const base = ensureScripts();
  const stamp = String(process.pid) + '-' + String(Date.now()) + '-' + Math.random().toString(36).slice(2, 6);
  const outFile = join(base, 'prop-' + stamp + '.json');
  const logFile = join(base, 'prop-' + stamp + '.log');
  const argv = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', join(base, 'propagate.ps1'), '-Path', dir, '-Sid', sid, '-Out', outFile, '-Log', logFile];
  return new Promise((resolve) => {
    const child = spawn(interpreter, argv, { stdio: 'ignore', windowsHide: true, env: helperEnvironment(interpreter) });
    activeHelpers.add(child);
    let offset = 0;
    let settled = false;
    const cleanup = () => {
      try { rmSync(outFile, { force: true }); } catch { /* best effort */ }
      try { rmSync(logFile, { force: true }); } catch { /* best effort */ }
      activeHelpers.delete(child);
    };
    const finish = (outcome) => {
      if (settled) return;
      settled = true;
      clearInterval(timer);
      clearTimeout(hardStop);
      cleanup();
      resolve(outcome);
    };
    const drain = () => {
      try {
        const buf = readFileSync(logFile);
        if (buf.length <= offset) return;
        const text = buf.toString('utf8', offset);
        offset = buf.length;
        for (const raw of text.split('\n')) {
          const line = raw.trim();
          if (line.length > 0) onLine(line);
        }
      } catch {
        // the log file appears after the child starts
      }
    };
    const timer = setInterval(drain, 120);
    timer.unref?.();
    const hardStop = setTimeout(() => { try { child.kill(); } catch { /* gone */ } }, 300_000);
    hardStop.unref?.();
    const abort = () => { try { child.kill(); } catch { /* gone */ } };
    if (signal !== undefined && typeof signal.addEventListener === 'function') {
      if (signal.aborted) abort();
      else signal.addEventListener('abort', abort, { once: true });
    }
    child.on('error', (error) => {
      if (isMissingExecutable(error)) {
        finish({ ok: false, missingInterpreter: true, error: String(error && error.message ? error.message : error) });
        return;
      }
      finish({ ok: false, error: String(error && error.message ? error.message : error) });
    });
    child.on('exit', (status) => {
      resolvedInterpreter = interpreter;
      drain();
      try {
        const parsed = JSON.parse(readFileSync(outFile, 'utf8'));
        if (typeof parsed.error === 'string' && parsed.ok !== true) finish({ ok: false, error: parsed.error });
        else finish({ ...parsed, ok: parsed.ok === true });
      } catch (error) {
        finish({ ok: false, error: 'propagate.ps1 exited with ' + String(status) });
      }
    });
  });
}