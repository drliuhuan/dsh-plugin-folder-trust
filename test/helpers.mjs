// Shared Windows ACL helpers for the folder-trust tests.
//
// Node cannot write a security descriptor, so the fixtures that matter for the
// protected-DACL regression are built with the platform tools: `icacls` disables
// inheritance (which is exactly the shape `Set-Acl` used to fail on) and grants the
// signed-in account the rights a folder copied from another machine typically has.

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

let sid;

/** The signed-in account's SID; the `*SID` form keeps icacls independent of locale. */
export function currentSid() {
  if (sid !== undefined) return sid;
  const output = spawnSync('whoami', ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8', windowsHide: true }).stdout;
  const match = /"(S-1-[0-9-]+)"/.exec(output ?? '');
  assert.ok(match, `whoami did not report a SID: ${String(output)}`);
  sid = match[1];
  return sid;
}

/**
 * Give `dir` a protected (inheritance-disabled) DACL with one explicit ACE for the
 * signed-in account. With rights `(M)` the owner keeps the implicit WRITE_DAC but not
 * WRITE_OWNER — the shape a repair has to extend without elevation.
 * @param {string} dir absolute directory path.
 * @param {string} [rights] icacls rights string, default `(M)`.
 */
export function protectDacl(dir, rights = '(M)') {
  run('icacls', [dir, '/inheritance:r']);
  run('icacls', [dir, '/grant:r', `*${currentSid()}:${rights}`]);
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
