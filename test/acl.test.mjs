import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { containsTempRoot, grantFullControl, probeDirectory } from '../lib/acl.mjs';

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
