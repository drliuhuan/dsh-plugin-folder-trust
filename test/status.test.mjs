import assert from 'node:assert/strict';
import test from 'node:test';

import { entryNeedsRepair, findWorkspace, issueCodes, normalizePath, ownerNeedsElevation, permissionFacts } from '../lib/status.mjs';

/** A workspace report row; override only what a case cares about. */
function row(overrides = {}, permissions = {}) {
  return {
    path: overrides.path ?? 'E:\\Games',
    title: overrides.title ?? 'Games',
    tempInside: overrides.tempInside ?? false,
    trusted: overrides.trusted ?? true,
    propagated: overrides.propagated ?? true,
    permissions: {
      ok: true,
      writeDac: true,
      writeOwner: true,
      rootGrant: true,
      lowLabel: 'low',
      childDirs: 2,
      childDirsWithGrant: 2,
      ...permissions
    }
  };
}

test('normalizePath folds separators, trailing slashes and case', () => {
  assert.equal(normalizePath('E:/Games/'), 'e:\\games');
  assert.equal(normalizePath('E:\\Games\\\\'), 'e:\\games');
  assert.equal(normalizePath(undefined), '');
  assert.equal(normalizePath(42), '');
});

test('a fully provisioned workspace has no issues and needs no repair', () => {
  const entry = row();
  assert.deepEqual(issueCodes(entry), []);
  assert.equal(entryNeedsRepair(entry), false);
});

test('a protected DACL is exposed but is not an issue by itself', () => {
  // The repair writes the DACL directly, so inheritance being disabled is a fact, not a
  // verdict. A fully provisioned protected workspace must stay "no issues".
  const entry = row({}, { protected: true });
  assert.equal(permissionFacts(entry).protected, true);
  assert.deepEqual(issueCodes(entry), []);
  assert.equal(entryNeedsRepair(entry), false);
  // An older host does not report the flag; absence of the fact is not an issue.
  assert.equal(permissionFacts(row()).protected, false);
});

test('missing account rights are reported as writeDac / writeOwner', () => {
  assert.deepEqual(issueCodes(row({}, { writeDac: false })), ['writeDac']);
  assert.deepEqual(issueCodes(row({}, { writeOwner: false })), ['writeOwner']);
  assert.deepEqual(issueCodes(row({}, { writeDac: false, writeOwner: false })), ['writeDac', 'writeOwner']);
  assert.equal(entryNeedsRepair(row({}, { writeDac: false })), true);
});

test('a root grant that never reached the existing subfolders still needs repair', () => {
  const entry = row({}, { childDirs: 7, childDirsWithGrant: 7 });
  assert.deepEqual(issueCodes(entry), []);
  const partial = row({}, { childDirs: 7, childDirsWithGrant: 3 });
  assert.deepEqual(issueCodes(partial), ['children']);
  assert.equal(entryNeedsRepair(partial), true);
});

test('a workspace holding the temp root is an issue but never repairable', () => {
  const entry = row({ tempInside: true }, { writeDac: false, rootGrant: false });
  assert.deepEqual(issueCodes(entry), ['temp']);
  assert.equal(entryNeedsRepair(entry), false);
});

test('an unreadable report is an issue and is offered for repair', () => {
  const entry = { path: 'E:\\Games', permissions: { ok: false, error: 'denied' } };
  assert.deepEqual(issueCodes(entry), ['unreadable']);
  assert.equal(entryNeedsRepair(entry), true);
  assert.equal(permissionFacts(entry).readable, false);
});

test('a folder without the sandbox Low label still needs repair', () => {
  // The confined shell is Low-integrity and write-restricted: the capability grant
  // without the Low no-write-up label is inert, and every write is denied. DSH itself
  // counts a folder provisioned only when grant + deny + label all hold, so a report
  // that says "no issues" here is exactly the silent failure this rule prevents.
  const missing = row({}, { lowLabel: 'none' });
  assert.deepEqual(issueCodes(missing), ['label']);
  assert.equal(entryNeedsRepair(missing), true);
  const medium = row({}, { lowLabel: 'other' });
  assert.deepEqual(issueCodes(medium), ['label']);
  assert.equal(entryNeedsRepair(medium), true);
  // An older host does not report the label; absence of the fact is not a verdict.
  assert.deepEqual(issueCodes(row({}, { lowLabel: 'unknown' })), []);
  assert.deepEqual(issueCodes(row({}, { lowLabel: undefined })), []);
});

test('the label issue is reported after the grant and child facts', () => {
  const entry = row({}, { rootGrant: false, lowLabel: 'none' });
  assert.deepEqual(issueCodes(entry), ['rootGrant', 'label']);
});

test('findWorkspace matches on the normalized path only', () => {
  const entries = [row({ path: 'E:\\Games' }), row({ path: 'D:\\temp' })];
  assert.equal(findWorkspace(entries, 'e:/games/')?.path, 'E:\\Games');
  assert.equal(findWorkspace(entries, 'E:\\Games\\sub'), undefined);
  assert.equal(findWorkspace(entries, undefined), undefined);
  assert.equal(findWorkspace([], 'E:\\Games'), undefined);
  assert.equal(findWorkspace(null, 'E:\\Games'), undefined);
});

test('a missing WRITE_DAC always needs a UAC elevation, whoever owns the folder', () => {
  // Two things remove the right: an owner that is not the signed-in account (another
  // machine's SID, SYSTEM, builtin), or a deny ACE that strips it even from the owner.
  // Both are only rewritable by an enabled Administrators group, i.e. through UAC.
  assert.equal(ownerNeedsElevation({ ok: true, writeDac: true, ownerKind: 'foreign' }), false);
  assert.equal(ownerNeedsElevation({ ok: true, writeDac: false, ownerKind: 'foreign' }), true);
  assert.equal(ownerNeedsElevation({ ok: true, writeDac: false, ownerKind: 'system' }), true);
  assert.equal(ownerNeedsElevation({ ok: true, writeDac: false, ownerKind: 'local-other' }), true);
  // A deny ACE on a folder you own looks like this; ownerKind does not change the answer.
  assert.equal(ownerNeedsElevation({ ok: true, writeDac: false, ownerKind: 'current' }), true);
  // An unreadable probe is a different failure; it must not advertise elevation.
  assert.equal(ownerNeedsElevation({ ok: false, writeDac: false, ownerKind: 'foreign' }), false);
  assert.equal(ownerNeedsElevation(undefined), false);
  // A host that predates ownerKind still reports writeDac: the answer stays the same.
  assert.equal(ownerNeedsElevation({ ok: true, writeDac: false, ownerKind: 'unknown' }), true);
});
