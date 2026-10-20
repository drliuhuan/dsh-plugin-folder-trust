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
// The work happens in a spawned Windows PowerShell 5.1 process whose stdout is
// not piped (a JSON result file is read instead), so the same code also runs
// under DSH's confined shell where piped grandchild stdio is unavailable.

import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const POWERSHELL = 'powershell.exe';

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
    $acl = (New-Object System.IO.DirectoryInfo($Path)).GetAccessControl()
    $result.sid = $identity.User.Value
    $result.owner = [string]$acl.Owner
    $result.writeDac = ($dacError -eq 0)
    $result.writeOwner = ($ownerError -eq 0)
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
    $acl = $info.GetAccessControl()
    if (-not (Test-FullControl $acl)) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $full, 'Allow')
        $acl.AddAccessRule($rule)
        $info.SetAccessControl($acl)
        $result.changed = $true
    }
    $after = (New-Object System.IO.DirectoryInfo($Path)).GetAccessControl()
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
  } catch {
    // the propagation step reports the missing helper at call time
  }
  scriptDir = dir;
  return dir;
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
  const run = spawnSync(
    POWERSHELL,
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', join(base, script), '-Path', dir, '-Out', outFile],
    { stdio: 'ignore', windowsHide: true, timeout: 30_000 }
  );
  try {
    if (run.error !== undefined) return { ok: false, error: String(run.error.message ?? run.error) };
    if (run.status !== 0) return { ok: false, error: `${script} exited with ${String(run.status)}` };
    const parsed = JSON.parse(readFileSync(outFile, 'utf8'));
    if (typeof parsed?.error === 'string') return { ok: false, error: parsed.error };
    return { ok: true, result: parsed };
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
 * (and every session switch) for the duration of each Windows PowerShell start.
 * @param {string} script helper file name inside the materialized script dir.
 * @param {string} dir directory argument.
 * @param {string[]} [extra] additional argv pairs before -Out.
 * @returns {Promise<{ ok: boolean, result?: object, error?: string }>}
 */
function runHelperAsync(script, dir, extra = []) {
  const base = ensureScripts();
  const outFile = join(base, `out-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}.json`);
  const argv = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', join(base, script), '-Path', dir, ...extra, '-Out', outFile];
  return new Promise((resolve) => {
    const child = spawn(POWERSHELL, argv, { stdio: 'ignore', windowsHide: true });
    activeHelpers.add(child);
    let settled = false;
    const done = (outcome) => {
      if (settled) return;
      settled = true;
      activeHelpers.delete(child);
      try { rmSync(outFile, { force: true }); } catch { /* best effort */ }
      resolve(outcome);
    };
    const timer = setTimeout(() => { try { child.kill(); } catch { /* gone */ } }, 120_000);
    timer.unref?.();
    child.on('error', (error) => { clearTimeout(timer); done({ ok: false, error: String(error && error.message ? error.message : error) }); });
    child.on('exit', (status) => {
      clearTimeout(timer);
      if (status !== 0) { done({ ok: false, error: script + ' exited with ' + String(status) }); return; }
      try {
        const parsed = JSON.parse(readFileSync(outFile, 'utf8'));
        if (typeof parsed.error === 'string' && parsed.error.length > 0) { done({ ok: false, error: parsed.error }); return; }
        done({ ok: true, result: parsed });
      } catch (error) {
        done({ ok: false, error: String(error && error.message ? error.message : error) });
      }
    });
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
  const sid = workspaceWriteSid(dir);
  const base = ensureScripts();
  const stamp = String(process.pid) + '-' + String(Date.now()) + '-' + Math.random().toString(36).slice(2, 6);
  const outFile = join(base, 'prop-' + stamp + '.json');
  const logFile = join(base, 'prop-' + stamp + '.log');
  const argv = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', join(base, 'propagate.ps1'), '-Path', dir, '-Sid', sid, '-Out', outFile, '-Log', logFile];
  return new Promise((resolve) => {
    const child = spawn(POWERSHELL, argv, { stdio: 'ignore', windowsHide: true });
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
    child.on('error', (error) => finish({ ok: false, error: String(error && error.message ? error.message : error) }));
    child.on('exit', (status) => {
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