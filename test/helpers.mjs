// Shared Windows ACL helpers for the folder-trust tests.
//
// Node cannot write a security descriptor, so the fixtures that matter for the
// protected-DACL regression are built with PowerShell: one Set-Acl write that sets
// the protected ("inheritance disabled") flag and the account's Modify ACE together.
// A second Set-Acl on that folder would need SeSecurityPrivilege, which is exactly the
// shape the repair has to cope with; building the fixture in one write avoids it.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

/** Run a Windows tool and fail the test when it does not succeed. */
export function run(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8', windowsHide: true });
  assert.equal(
    result.status,
    0,
    `${command} ${args.join(' ')} failed (${String(result.status)}): ${result.stderr || result.stdout || ''}`
  );
  return result;
}

/**
 * Give `dir` a protected (inheritance-disabled) DACL with one explicit ACE for the
 * signed-in account. With `Modify` the owner keeps the implicit WRITE_DAC but not
 * WRITE_OWNER — the shape a repair has to extend without elevation.
 * @param {string} dir absolute directory path.
 * @param {string} [rights] FileSystemRights name, default `Modify`.
 */
export function protectDacl(dir, rights = 'Modify') {
  const script = [
    `$acl = Get-Acl -LiteralPath '${dir}'`,
    '$acl.SetAccessRuleProtection($true, $false)',
    '$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User',
    `$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($me, [System.Security.AccessControl.FileSystemRights]'${rights}', 'Allow')))`,
    `Set-Acl -LiteralPath '${dir}' -AclObject $acl -ErrorAction Stop`
  ].join('; ');
  // PowerShell 7, not 5.1: a 5.1 child launched from the PowerShell 7 host inherits
  // 7's PSModulePath, cannot load Microsoft.PowerShell.Security, and every Get-Acl /
  // Set-Acl fails with "module could not be loaded". The plugin rebuilds the module
  // path for 5.1; the test helper simply uses the interpreter the plugin prefers.
  run('pwsh.exe', ['-NoProfile', '-NonInteractive', '-Command', script]);
}

/**
 * Strip the owner's implicit WRITE_DAC on `dir`.
 *
 * A deny for the user's own SID does not do it: Windows grants the owner
 * READ_CONTROL/WRITE_DAC through the Owner Rights SID (S-1-3-4), so a deny naming
 * that SID is what makes even the owner unable to rewrite the DACL.
 */
export function denyWriteDac(dir) {
  run('icacls', [dir, '/deny', '*S-1-3-4:(WDAC)']);
}
