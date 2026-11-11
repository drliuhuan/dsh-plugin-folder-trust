import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  containsTempRoot,
  elevatedPowerShell,
  grantFullControl,
  inspectWorkspace,
  powerShellCandidates,
  preferredPowerShell,
  probeDirectory,
  propagateWorkspace,
  windowsPowerShellModulePath,
} from '../lib/acl.mjs';
import { denyWriteDac, protectDacl } from './helpers.mjs';

const LIB = join(dirname(fileURLToPath(import.meta.url)), '..', 'lib');
const scratch = mkdtempSync(join(tmpdir(), 'folder-trust-test-'));

test.after(() => {
  try {
    rmSync(scratch, { recursive: true, force: true });
  } catch {
    // best effort
  }
});

test('containsTempRoot recognizes the harness temp layout', () => {
  assert.equal(containsTempRoot('D:\\work', 'D:\\work\\AppData\\Local\\Temp'), true);
  assert.equal(containsTempRoot('D:\\work', 'D:\\work\\nested'), true);
  assert.equal(containsTempRoot('D:\\work', 'D:\\other'), false);
  assert.equal(containsTempRoot('D:\\work\\', 'D:\\work'), true);
});

test('probeDirectory reports the effective rights of a folder the user owns', async () => {
  const dir = mkdtempSync(join(scratch, 'own-'));
  const probe = await probeDirectory(dir);
  assert.equal(probe.state, 'ok');
  assert.equal(probe.writeDac, true);
  assert.equal(probe.writeOwner, true);
});

test('grantFullControl is idempotent and never reports a change it did not make', async () => {
  const dir = mkdtempSync(join(scratch, 'grant-'));
  const first = await probeDirectory(dir);
  assert.equal(first.state, 'ok');
  const untouched = await grantFullControl(dir);
  assert.equal(untouched.ok, true);
  assert.equal(untouched.changed, false);
  assert.equal(untouched.granted, true);
  assert.equal((await probeDirectory(dir)).state, 'ok');
});

test('grantFullControl repairs a folder whose DACL is protected (inheritance disabled)', async () => {
  // Set-Acl also writes the SACL; on an already-protected DACL that fails with
  // SeSecurityPrivilege even though the owner holds the implicit WRITE_DAC. The helper
  // must write the DACL only, preserve the protected flag, and still grant FullControl.
  const dir = mkdtempSync(join(scratch, 'protected-root-'));
  protectDacl(dir);
  const before = await probeDirectory(dir);
  assert.equal(before.writeDac, true);
  // Do not assert writeOwner=false here: an elevated CI runner holds SeRestorePrivilege,
  // and CreateFileW with BACKUP_SEMANTICS then opens the protected folder for WRITE_OWNER
  // even though its DACL grants only Modify. The regression under test is the DACL write,
  // not the probe's privilege-dependent answer.
  const granted = await grantFullControl(dir);
  assert.equal(granted.ok, true, `grant failed: ${String(granted.error)}`);
  assert.equal(granted.changed, true);
  assert.equal((await probeDirectory(dir)).state, 'ok');
  const inspected = await inspectWorkspace(dir);
  assert.equal(inspected.ok, true);
  assert.equal(inspected.protected, true);
});

test('propagateWorkspace provisions a protected root without re-enabling inheritance', async () => {
  // Steps 3 and 5 write the DACL by name; with Set-Acl that failed on a protected
  // DACL, and a fallback that cleared the flag would silently change the folder's
  // inheritance policy. The direct write keeps the flag and still sets the grant/label.
  const root = mkdtempSync(join(scratch, 'protected-root-propagate-'));
  protectDacl(root);
  const result = await propagateWorkspace(root);
  assert.equal(result.ok, true, `propagate failed: ${String(result.error)}`);
  const inspected = await inspectWorkspace(root);
  assert.equal(inspected.protected, true, 'the protected flag must survive the repair');
  assert.equal(inspected.rootGrant, true);
  assert.equal(inspected.lowLabel, 'low');
});

test('propagateWorkspace provisions a child whose DACL is protected', async () => {
  // A child with inheritance disabled never picks up the inheritance pass; step 6 has
  // to write its DACL directly. It used to fail silently there and leave the child
  // without the capability grant while the repair still reported success.
  const root = mkdtempSync(join(scratch, 'protected-child-'));
  mkdirSync(join(root, 'open-child'));
  const locked = join(root, 'protected-child');
  mkdirSync(locked);
  protectDacl(locked);
  const result = await propagateWorkspace(root);
  assert.equal(result.ok, true, `propagate failed: ${String(result.error)}`);
  assert.equal(result.childrenFailed, 0);
  assert.ok(result.childrenRepaired >= 1, 'step 6 repaired the protected child');
  const inspected = await inspectWorkspace(root);
  assert.equal(inspected.lowLabel, 'low');
  assert.equal(inspected.childDirs, 2);
  assert.equal(inspected.childDirsWithGrant, 2);
});

test('a child the account cannot rewrite is reported, not swallowed', async () => {
  const root = mkdtempSync(join(scratch, 'child-failure-'));
  const locked = join(root, 'locked');
  mkdirSync(locked);
  protectDacl(locked);
  denyWriteDac(locked);
  const result = await propagateWorkspace(root);
  assert.equal(result.ok, false, 'a partial repair must not be reported as success');
  assert.equal(result.partial, true);
  assert.equal(result.childrenFailed, 1);
  assert.match(String(result.error), /subfolder/i);
  const inspected = await inspectWorkspace(root);
  assert.equal(inspected.rootGrant, true, 'the root itself is still provisioned');
  assert.equal(inspected.childDirsWithGrant, 0);
});

test('an unknown directory is reported as an error, not as denied rights', async () => {
  const missing = join(scratch, 'does-not-exist-1587');
  const probe = await probeDirectory(missing);
  assert.notEqual(probe.state, 'ok');
});

test('PowerShell 7 is preferred, and Windows PowerShell 5.1 is only the fallback', () => {
  const env = { ProgramFiles: 'C:\\Program Files', ProgramW6432: 'C:\\Program Files', 'ProgramFiles(x86)': 'C:\\Program Files (x86)' };
  const candidates = powerShellCandidates(env, 'win32');
  assert.match(candidates[0], /Program Files\\PowerShell\\7\\pwsh\.exe$/i);
  assert.ok(candidates.includes('pwsh.exe'), 'a 7 installed outside the default location still comes before 5.1');
  assert.equal(candidates.at(-1), 'powershell.exe');
  assert.equal(new Set(candidates).size, candidates.length, 'no duplicate candidates');
  // Otherwise the same 5.1 default, never a 5.1-first order.
  assert.equal(powerShellCandidates({ ProgramFiles: undefined }, 'win32').at(-1), 'powershell.exe');
});

test('an explicit interpreter pin wins over the preference order', () => {
  const pinned = powerShellCandidates({ FOLDER_TRUST_POWERSHELL: 'D:\\tools\\pwsh-7.4\\pwsh.exe' }, 'win32');
  assert.deepEqual(pinned, ['D:\\tools\\pwsh-7.4\\pwsh.exe']);
  // A blank pin is not a pin.
  assert.notDeepEqual(powerShellCandidates({ FOLDER_TRUST_POWERSHELL: '  ' }, 'win32'), ['  ']);
  assert.ok(preferredPowerShell({ FOLDER_TRUST_POWERSHELL: 'X:\\pwsh.exe' }, 'win32').endsWith('pwsh.exe'));
});

test('the helpers use no .NET Framework-only ACL API', () => {
  // `DirectoryInfo.GetAccessControl()` / `SetAccessControl()` exist only in the .NET
  // Framework; under PowerShell 7 (net 10) the call fails with "does not contain a
  // method named 'GetAccessControl'". The scripts use the Get-Acl / Set-Acl cmdlets
  // instead, which are portable — this assertion is what keeps a rewrite from
  // quietly reintroducing the 5.1-only call.
  for (const file of ['inspect.ps1', 'propagate.ps1']) {
    const text = readFileSync(join(LIB, file), 'utf8');
    assert.doesNotMatch(text, /\.GetAccessControl\s*\(/, `${file} must not call GetAccessControl()`);
    assert.doesNotMatch(text, /\.SetAccessControl\s*\(/, `${file} must not call SetAccessControl()`);
    assert.doesNotMatch(text, /Directory\]::SetAccessControl/, `${file} must not use Directory::SetAccessControl`);
    assert.match(text, /Get-Acl -LiteralPath/, `${file} reads the DACL through Get-Acl`);
  }
});

test('the helpers write the DACL through SetNamedSecurityInfoW, not Set-Acl', () => {
  // Set-Acl also writes the SACL; on a folder whose DACL already carries the protected
  // flag that fails with SeSecurityPrivilege, even for the owner. The direct,
  // DACL-only write is what makes a protected folder repairable without elevation.
  const propagate = readFileSync(join(LIB, 'propagate.ps1'), 'utf8');
  const acl = readFileSync(join(LIB, 'acl.mjs'), 'utf8');
  for (const [name, text] of [['propagate.ps1', propagate], ['acl.mjs', acl]]) {
    assert.match(text, /SetNamedSecurityInfoW/, `${name} writes the DACL directly`);
    assert.doesNotMatch(text, /Set-Acl\s+-LiteralPath/, `${name} must not call Set-Acl -LiteralPath`);
  }
});

test('both helper scripts start with a UTF-8 BOM', () => {
  // Windows PowerShell 5.1 decodes a BOM-less UTF-8 script as ANSI, so the Chinese
  // lines in propagate.ps1 turn into garbage and the whole file stops parsing —
  // while PowerShell 7 parses it fine, which is how this shipped once undetected.
  for (const file of ['inspect.ps1', 'propagate.ps1', 'elevate.ps1']) {
    const head = readFileSync(join(LIB, file)).subarray(0, 3);
    assert.deepEqual([...head], [0xef, 0xbb, 0xbf], `${file} must carry a UTF-8 BOM`);
  }
});

test('the elevated helper runs under a machine-wide interpreter, never a PATH name', () => {
  // Across an elevation boundary a bare `pwsh.exe` has no path for ShellExecute to
  // launch, and a per-user portable install (what a plugin drops under AppData) can
  // belong to a different profile than the administrator UAC switches to. The launcher
  // must therefore name a machine-wide executable: PowerShell 7 when installed, else
  // Windows PowerShell 5.1 in System32, which every supported Windows has.
  const machine = mkdtempSync(join(scratch, 'machine-'));
  const target = join(machine, 'PowerShell', '7');
  mkdirSync(target, { recursive: true });
  writeFileSync(join(target, 'pwsh.exe'), '');

  assert.equal(elevatedPowerShell({ ProgramW6432: machine, SystemRoot: 'C:\\Windows' }), join(target, 'pwsh.exe'));
  assert.equal(elevatedPowerShell({ ProgramFiles: machine, SystemRoot: 'C:\\Windows' }), join(target, 'pwsh.exe'));

  const fallback = elevatedPowerShell({ SystemRoot: 'C:\\Windows' });
  assert.equal(fallback, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
  // The default when no environment is readable is the same System32 path.
  assert.equal(elevatedPowerShell({}), fallback);

  // An explicit operator pin still wins, even a non-default location.
  assert.equal(
    elevatedPowerShell({ FOLDER_TRUST_POWERSHELL: 'D:\\tools\\pwsh-7.4\\pwsh.exe', ProgramW6432: machine }),
    'D:\\tools\\pwsh-7.4\\pwsh.exe'
  );

  // Whatever it resolves to, it is an absolute path — never a bare executable name.
  for (const candidate of [fallback, elevatedPowerShell({ ProgramW6432: machine })]) {
    assert.match(candidate, /^[A-Za-z]:\\/, `${candidate} must be absolute`);
    assert.doesNotMatch(candidate, /(^|;|\s)pwsh(\.exe)?$/i);
  }
});

test('Windows PowerShell 5.1 gets a module path it can actually load', () => {
  // A 5.1 child that inherits a PowerShell 7 PSModulePath resolves
  // Microsoft.PowerShell.Security against 7's assemblies, fails to load it, and every
  // Get-Acl then dies with "the member ... is already present". That silently broke the
  // fallback on machines without a PowerShell 7 of their own; the helper env rebuilds
  // the value from the three 5.1 locations.
  const rebuilt = windowsPowerShellModulePath({
    USERPROFILE: 'C:\\Users\\X',
    ProgramFiles: 'C:\\Program Files',
    SystemRoot: 'C:\\Windows'
  });
  assert.equal(
    rebuilt,
    'C:\\Users\\X\\Documents\\WindowsPowerShell\\Modules;C:\\Program Files\\WindowsPowerShell\\Modules;C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules'
  );
  assert.doesNotMatch(rebuilt, /PowerShell\\7/i, 'no PowerShell 7 module directory may leak in');
  assert.doesNotMatch(windowsPowerShellModulePath({ SystemRoot: 'C:\\Windows' }), /Users/, 'no phantom profile entry');
  assert.match(windowsPowerShellModulePath({}), /WindowsPowerShell\\v1\.0\\Modules$/, 'System32 is always present');
});
