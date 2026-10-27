import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  containsTempRoot,
  grantFullControl,
  powerShellCandidates,
  preferredPowerShell,
  probeDirectory,
} from '../lib/acl.mjs';

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

test('both helper scripts start with a UTF-8 BOM', () => {
  // Windows PowerShell 5.1 decodes a BOM-less UTF-8 script as ANSI, so the Chinese
  // lines in propagate.ps1 turn into garbage and the whole file stops parsing —
  // while PowerShell 7 parses it fine, which is how this shipped once undetected.
  for (const file of ['inspect.ps1', 'propagate.ps1']) {
    const head = readFileSync(join(LIB, file)).subarray(0, 3);
    assert.deepEqual([...head], [0xef, 0xbb, 0xbf], `${file} must carry a UTF-8 BOM`);
  }
});
