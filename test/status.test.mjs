import assert from 'node:assert/strict';
import test from 'node:test';

import { entryNeedsRepair, findWorkspace, issueCodes, normalizePath, permissionFacts } from '../lib/status.mjs';

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

test('findWorkspace matches on the normalized path only', () => {
  const entries = [row({ path: 'E:\\Games' }), row({ path: 'D:\\temp' })];
  assert.equal(findWorkspace(entries, 'e:/games/')?.path, 'E:\\Games');
  assert.equal(findWorkspace(entries, 'E:\\Games\\sub'), undefined);
  assert.equal(findWorkspace(entries, undefined), undefined);
  assert.equal(findWorkspace([], 'E:\\Games'), undefined);
  assert.equal(findWorkspace(null, 'E:\\Games'), undefined);
});
