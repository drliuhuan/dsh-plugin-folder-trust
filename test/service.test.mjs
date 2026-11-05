import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { FolderTrustService } from '../lib/service.mjs';

const scratch = mkdtempSync(join(tmpdir(), 'folder-trust-svc-'));

test.after(() => {
  try {
    rmSync(scratch, { recursive: true, force: true });
  } catch {
    // best effort
  }
});

/** Wait until the classification queue has drained. */
async function settle(service) {
  for (let i = 0; i < 400; i += 1) {
    if (service.queue.length === 0 && service.draining === false) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error('classification queue did not drain');
}

function serviceWith(home) {
  const savedDSH = process.env.DSH_HOME;
  process.env.DSH_HOME = home;
  const rows = [];
  const service = new FolderTrustService({ listWorkspaces: () => rows });
  return {
    service,
    rows,
    restore: () => { process.env.DSH_HOME = savedDSH; }
  };
}

test('a folder already owned by the user never becomes pending', async () => {
  const home = join(scratch, 'home-a');
  const workspace = join(scratch, 'ok-a');
  mkdirSync(workspace, { recursive: true });
  const { service, rows, restore } = serviceWith(home);
  try {
    service.start();
    rows.push({ path: workspace, title: 'ok-a' });
    service.poll();
    await settle(service);
    assert.equal(service.snapshot().pending.length, 0);
    assert.equal(service.started, true);
    assert.ok(service.polls >= 2);
  } finally {
    service.stop();
    restore();
  }
});

test('a workspace that contains the temp root is pending with the temp reason', async () => {
  const home = join(scratch, 'home-b');
  const workspace = join(scratch, 'host-b');
  mkdirSync(workspace, { recursive: true });
  const savedTemp = process.env.TEMP;
  process.env.TEMP = join(workspace, 'Temp');
  const { service, rows, restore } = serviceWith(home);
  try {
    service.start();
    rows.push({ path: workspace, title: 'host-b' });
    service.poll();
    await settle(service);
    const pending = service.snapshot().pending;
    assert.equal(pending.length, 1);
    assert.equal(pending[0].path, workspace);
    assert.equal(pending[0].reason, 'temp-inside-workspace');
    assert.equal((await service.trust(workspace)).ok, false);
  } finally {
    service.stop();
    restore();
    process.env.TEMP = savedTemp;
  }
});

test('a workspace registered while the harness was running is classified on the first poll', async () => {
  const home = join(scratch, 'home-e');
  const workspace = join(scratch, 'existing-e');
  mkdirSync(workspace, { recursive: true });
  const savedTemp = process.env.TEMP;
  process.env.TEMP = join(workspace, 'Temp');
  const { service, rows, restore } = serviceWith(home);
  try {
    rows.push({ path: workspace, title: 'existing-e' });
    service.start();
    await settle(service);
    assert.equal(service.snapshot().pending.length, 1);
  } finally {
    service.stop();
    restore();
    process.env.TEMP = savedTemp;
  }
});

test('repairing a path that is not a registered workspace is refused', async () => {
  const home = join(scratch, 'home-f');
  const { service, restore } = serviceWith(home);
  try {
    assert.deepEqual((await service.report()).workspaces, []);
    const outcome = await service.repair(join(scratch, 'not-registered'));
    assert.equal(outcome.ok, false);
    assert.match(String(outcome.message), /not a registered workspace/);
  } finally {
    restore();
  }
});

test('dismissing persists so a restart does not prompt again', async () => {
  const home = join(scratch, 'home-c');
  const workspace = join(scratch, 'host-c');
  mkdirSync(workspace, { recursive: true });
  const savedTemp = process.env.TEMP;
  process.env.TEMP = join(workspace, 'Temp');
  try {
    const first = serviceWith(home);
    first.service.start();
    first.rows.push({ path: workspace, title: 'host-c' });
    first.service.poll();
    await settle(first.service);
    assert.equal(first.service.snapshot().pending.length, 1);
    first.service.dismiss(workspace);
    assert.equal(first.service.snapshot().pending.length, 0);
    first.service.stop();
    first.restore();

    const persisted = JSON.parse(readFileSync(join(home, 'folder-trust', 'state.json'), 'utf8'));
    assert.deepEqual(persisted.dismissed, [workspace.toLowerCase()]);

    const second = serviceWith(home);
    second.service.start();
    second.rows.push({ path: workspace, title: 'host-c' });
    second.service.poll();
    await settle(second.service);
    assert.equal(second.service.snapshot().pending.length, 0);
    second.service.stop();
    second.restore();
  } finally {
    process.env.TEMP = savedTemp;
  }
});

test('repairing a dismissed workspace drops the stale dismissal', async () => {
  // A folder the user ignored and later repaired must not stay "ignored": the report
  // used to come back with trusted:true and dismissed:true, and persist() wrote that
  // contradiction back to state.json on every restart.
  const home = join(scratch, 'home-dismiss-repair');
  const workspace = join(scratch, 'dismissed-then-repaired');
  mkdirSync(workspace, { recursive: true });
  const normalized = workspace.replaceAll('/', '\\').toLowerCase();
  const { service, rows, restore } = serviceWith(home);
  try {
    service.start();
    rows.push({ path: workspace, title: 'dismissed-then-repaired' });
    service.poll();
    await settle(service);
    service.dismiss(workspace);
    assert.equal(service.dismissed.has(normalized), true);

    const outcome = await service.repair(workspace);
    assert.equal(outcome.ok, true, `repair failed: ${String(outcome.message)}`);
    assert.equal(service.dismissed.has(normalized), false, 'the service must forget the dismissal');
    assert.equal(service.trusted.has(normalized), true);
    assert.equal(service.propagated.has(normalized), true);

    const persisted = JSON.parse(readFileSync(join(home, 'folder-trust', 'state.json'), 'utf8'));
    assert.equal(persisted.dismissed.includes(normalized), false, 'state.json must not keep both flags');
    assert.equal(persisted.trusted.includes(normalized), true);

    const row = (await service.report(false)).workspaces.find((entry) => entry.path === workspace);
    assert.equal(row.trusted, true);
    assert.equal(row.dismissed, false);
  } finally {
    service.stop();
    restore();
  }
});

test('a stale dismissal on an already-trusted workspace heals on the next poll', async () => {
  // Upgrading from a version that wrote the contradiction must not need a hand-edited
  // state file: classify() sees the trusted entry and forgets the dismissal.
  const home = join(scratch, 'home-heal');
  const workspace = join(scratch, 'heal-a');
  mkdirSync(workspace, { recursive: true });
  mkdirSync(join(home, 'folder-trust'), { recursive: true });
  const normalized = workspace.replaceAll('/', '\\').toLowerCase();
  writeFileSync(join(home, 'folder-trust', 'state.json'), JSON.stringify({
    trusted: [normalized],
    dismissed: [normalized],
    propagated: [normalized]
  }), 'utf8');

  const { service, rows, restore } = serviceWith(home);
  try {
    assert.equal(service.dismissed.has(normalized), true, 'the fixture starts contradictory');
    service.start();
    rows.push({ path: workspace, title: 'heal-a' });
    service.poll();
    await settle(service);

    assert.equal(service.dismissed.has(normalized), false);
    const persisted = JSON.parse(readFileSync(join(home, 'folder-trust', 'state.json'), 'utf8'));
    assert.deepEqual(persisted.dismissed, []);
    assert.deepEqual(persisted.trusted, [normalized]);
  } finally {
    service.stop();
    restore();
  }
});


