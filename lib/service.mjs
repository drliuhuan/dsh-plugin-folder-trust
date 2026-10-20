// Workspace trust state for the folder-trust plugin.
//
// The service owns three things:
//   - which workspace folders were added since the last classification,
//   - the pending trust requests the client renders as one modal,
//   - the persisted "already handled" set so a restart never nags twice.
//
// It never touches a folder until the user clicks trust: classification only
// reads the folder's effective rights with the harness token.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

import { containsTempRoot, grantFullControl, inspectWorkspace, killActiveHelpers, probeDirectory, propagateWorkspace, propagateWorkspaceStream } from './acl.mjs';
import { entryNeedsRepair, issueCodes } from './status.mjs';

const POLL_INTERVAL_MS = 2_000;

/** Normalize a Windows path for set membership. */
function key(path) {
  return path.replaceAll('/', '\\').replace(/\\+$/, '').toLowerCase();
}

/** DSH home used for the plugin's own state file. */
function stateFile() {
  const home = process.env.DSH_HOME ?? join(homedir(), '.dsh');
  return join(home, 'folder-trust', 'state.json');
}

/** Read the persisted handled set; corrupt state never blocks the plugin. */
function loadState() {
  try {
    const parsed = JSON.parse(readFileSync(stateFile(), 'utf8'));
    return {
      trusted: new Set(Array.isArray(parsed.trusted) ? parsed.trusted : []),
      dismissed: new Set(Array.isArray(parsed.dismissed) ? parsed.dismissed : []),
      propagated: new Set(Array.isArray(parsed.propagated) ? parsed.propagated : [])
    };
  } catch {
    return { trusted: new Set(), dismissed: new Set(), propagated: new Set() };
  }
}

/**
 * Own workspace trust requests for one harness process.
 */
export class FolderTrustService {
  /**
   * @param {object} options
   * @param {() => Array<{ path: string, title?: string }>} options.listWorkspaces current workspace rows.
   * @param {{ warn?: Function }} [options.logger]
   */
  constructor({ listWorkspaces, logger }) {
    this.listWorkspaces = listWorkspaces;
    this.logger = logger;
    this.pending = new Map();
    this.seen = new Set();
    this.queue = [];
    this.draining = false;
    this.timer = undefined;
    this.started = false;
    this.lastError = null;
    this.polls = 0;
    const state = loadState();
    this.trusted = state.trusted;
    this.dismissed = state.dismissed;
    this.propagated = state.propagated;
  }

  /**
   * Begin watching the workspace list. Every workspace that has not been
   * handled yet is classified on the first poll, so a folder that was added
   * while the harness was running still gets its prompt after a restart.
   */
  start() {
    if (this.started) return;
    this.started = true;
    this.poll();
    this.timer = setInterval(() => this.poll(), POLL_INTERVAL_MS);
    this.timer.unref?.();
  }

  /** Stop the poll timer. */
  stop() {
    if (this.timer !== undefined) clearInterval(this.timer);
    this.timer = undefined;
    this.started = false;
    killActiveHelpers();
  }

  /** Best-effort workspace rows from the registry. */
  readWorkspaces() {
    try {
      const rows = this.listWorkspaces();
      return Array.isArray(rows)
        ? rows.filter((row) => row !== null && typeof row === 'object' && typeof row.path === 'string')
        : [];
    } catch (error) {
      this.lastError = String(error?.message ?? error);
      this.logger?.warn?.(`folder-trust: workspace list failed: ${String(error?.message ?? error)}`);
      return [];
    }
  }

  /** Queue workspaces added since the previous poll and drop vanished rows. */
  poll() {
    this.polls += 1;
    const live = new Set();
    for (const workspace of this.readWorkspaces()) {
      live.add(key(workspace.path));
      if (this.seen.has(key(workspace.path))) continue;
      this.seen.add(key(workspace.path));
      this.queue.push(workspace);
    }
    for (const pendingKey of [...this.pending.keys()]) {
      if (!live.has(pendingKey)) this.pending.delete(pendingKey);
    }
    this.drainQueue();
  }

  /**
   * Classify queued workspaces one per event-loop turn: each probe spawns a
   * helper process, so a batch must never block the host for all of them.
   */
  drainQueue() {
    if (this.draining) return;
    this.draining = true;
    const step = async () => {
      const next = this.queue.shift();
      if (next === undefined) {
        this.draining = false;
        return;
      }
      try {
        await this.classify(next);
      } catch (error) {
        this.lastError = String(error?.message ?? error);
        this.logger?.warn?.(`folder-trust: classify failed: ${String(error?.message ?? error)}`);
      }
      setImmediate(step);
    };
    setImmediate(step);
  }

  /** Decide whether a newly seen workspace needs the prompt. */
  async classify(workspace) {
    const path = workspace.path;
    const normalized = key(path);
    if (this.trusted.has(normalized)) {
      await this.ensurePropagation(path);
      return;
    }
    if (this.dismissed.has(normalized)) return;
    if (!existsSync(path)) return;
    if (containsTempRoot(path)) {
      this.pending.set(normalized, {
        path,
        title: workspace.title,
        reason: 'temp-inside-workspace'
      });
      return;
    }
    const probe = await probeDirectory(path);
    if (probe.state === 'ok') {
      this.trusted.add(normalized);
      this.persist();
      await this.ensurePropagation(path);
      return;
    }
    this.pending.set(normalized, {
      path,
      title: workspace.title,
      reason: probe.state === 'error' ? 'probe-failed' : 'missing-rights',
      writeDac: probe.writeDac,
      writeOwner: probe.writeOwner,
      error: probe.error
    });
  }

  /** Snapshot for the browser poll. */
  snapshot() {
    return {
      pending: [...this.pending.values()].map((entry) => ({ ...entry }))
    };
  }

  /**
   * Repair one pending workspace after the user clicked trust.
   * @param {string} path workspace directory reported by the client.
   * @returns {{ ok: boolean, changed?: boolean, reason?: string, message?: string }}
   */
  async trust(path) {
    const normalized = key(path);
    if (containsTempRoot(path)) {
      return {
        ok: false,
        reason: 'temp-inside-workspace',
        message: 'This folder contains the harness temp directory, so the confined sandbox can never use it. Switch this session to full access instead.'
      };
    }
    const before = await probeDirectory(path);
    const grant = before.state === 'ok'
      ? { ok: true, changed: false, granted: true }
      : await grantFullControl(path);
    const after = grant.ok ? await probeDirectory(path) : before;
    if (!grant.ok || after.state !== 'ok') {
      const missing = [
        after.writeDac === false ? 'change file permissions' : null,
        after.writeOwner === false ? 'change the owner or integrity label' : null
      ].filter((part) => part !== null);
      return {
        ok: false,
        reason: 'grant-failed',
        message: grant.error
          ?? `Windows still denies your account the right to ${missing.join(' and ') || 'provision this folder'}; an administrator must fix this folder once, or use full access for this session.`
      };
    }
    this.trusted.add(normalized);
    this.pending.delete(normalized);
    this.persist();
    const propagation = this.ensurePropagation(path);
    return {
      ok: true,
      changed: grant.changed === true,
      propagated: propagation?.ok === true,
      propagationError: propagation?.ok === false ? propagation.error : undefined
    };
  }

  /**
   * Push the capability grant and the Low label through the existing subtree.
   * Runs at most once per path per machine (persisted): the harness itself
   * writes both with a directory handle, which never propagates to children
   * that already existed, so a folder whose root is usable can still deny every
   * pre-existing subfolder.
   * @param {string} path workspace directory.
   * @returns {{ ok: boolean, error?: string }|null} null when it was already done.
   */
  async ensurePropagation(path) {
    const normalized = key(path);
    if (this.propagated.has(normalized)) return null;
    const result = await propagateWorkspace(path);
    if (result.ok === true) {
      this.propagated.add(normalized);
      this.persist();
    } else {
      this.lastError = result.error ?? 'propagation failed';
    }
    return result;
  }

  /**
   * Repair one registered workspace while reporting progress.
   * Emits `{ kind: 'line' | 'progress' | 'done', ... }` events to the caller.
   * @param {string} path workspace path.
   * @param {(event: object) => void} emit event sink.
   * @returns {Promise<{ ok: boolean, message?: string, entry?: object }>}
   */
  async repairStream(path, emit, signal) {
    const normalized = key(path);
    const known = this.readWorkspaces().find((workspace) => key(workspace.path) === normalized);
    if (known === undefined) return { ok: false, message: 'this folder is not a registered workspace' };
    if (containsTempRoot(known.path)) {
      return { ok: false, message: 'This folder contains the harness temp directory; the confined sandbox can never use it.' };
    }
    let progress = 0;
    const line = (text) => { emit({ kind: 'line', line: text }); };
    const bump = (value) => { progress = Math.max(progress, Math.min(95, value)); emit({ kind: 'progress', progress }); };

    line('开始修复：' + known.path);
    const before = await probeDirectory(known.path);
    if (before.state !== 'ok') {
      line('账户缺少权限，先补一条完全控制 ACE…');
      const grant = await grantFullControl(known.path);
      if (!grant.ok) {
        line('ERROR ' + (grant.error ?? 'grant failed'));
        return { ok: false, message: grant.error ?? 'Windows still denies your account' };
      }
      line('账户权限已补齐');
    } else {
      line('账户权限已就绪（可改权限与所有者）');
    }
    bump(10);

    const result = await propagateWorkspaceStream(known.path, (text) => {
      line(text);
      const step = /^STEP (\d+)\/7/.exec(text);
      if (step !== null) bump(Math.round((Number(step[1]) - 1) / 7 * 85) + 10);
      if (text.startsWith('CHILD ')) bump(progress + 1);
    }, signal);
    if (result.ok !== true) {
      line('ERROR ' + (result.error ?? 'propagation failed'));
      return { ok: false, message: result.error ?? 'the grant could not be pushed through the existing subfolders' };
    }

    this.trusted.add(normalized);
    this.propagated.add(normalized);
    this.pending.delete(normalized);
    this.persist();
    this.reportCache?.delete(normalized);
    line('生成最新权限状态…');
    const entry = {
      path: known.path,
      title: known.title,
      tempInside: false,
      trusted: this.trusted.has(normalized),
      dismissed: this.dismissed.has(normalized),
      propagated: this.propagated.has(normalized),
      permissions: await inspectWorkspace(known.path)
    };
    bump(100);
    line('修复完成');
    return { ok: true, entry };
  }
  /**
   * Status of every registered workspace for the permissions dialog.
   * @param {boolean} [useCache] reuse reports younger than 15s.
   * @returns {{ workspaces: Array<object> }}
   */
  async report(useCache = true) {
    const now = Date.now();
    return {
      workspaces: await Promise.all(this.readWorkspaces().map(async (workspace) => {
        const normalized = key(workspace.path);
        const cached = this.reportCache?.get(normalized);
        let permissions;
        if (useCache && cached !== undefined && now - cached.at < 15_000) {
          permissions = cached.value;
        } else {
          permissions = await inspectWorkspace(workspace.path);
          if (this.reportCache === undefined) this.reportCache = new Map();
          this.reportCache.set(normalized, { at: now, value: permissions });
        }
        const row = {
          path: workspace.path,
          title: workspace.title,
          tempInside: containsTempRoot(workspace.path),
          trusted: this.trusted.has(normalized),
          dismissed: this.dismissed.has(normalized),
          propagated: this.propagated.has(normalized),
          // The registry entity filters `sessionIds` by the live canonical-cwd
          // index, so the browser can name its workspace without a second probe.
          sessionIds: Array.isArray(workspace.sessionIds) ? [...workspace.sessionIds] : [],
          permissions
        };
        // Both browser surfaces read the same verdict, so the rule that decides
        // "usable" lives in status.mjs instead of being re-implemented there.
        row.issues = issueCodes(row);
        row.needsRepair = entryNeedsRepair(row);
        return row;
      }))
    };
  }

  /**
   * Repair one registered workspace: user FullControl, then the harness grant and
   * the Low label propagated through the existing subtree, then a fresh report.
   * @param {string} path workspace path reported by the browser.
   * @returns {{ ok: boolean, message?: string, entry?: object }}
   */
  /**
   * Repair one registered workspace (non-streaming convenience wrapper).
   * @param {string} path workspace path.
   * @returns {Promise<{ ok: boolean, message?: string, entry?: object }>}
   */
  async repair(path) {
    return this.repairStream(path, () => {});
  }
  /**
   * Status of every registered workspace for the permissions dialog.
   * @param {boolean} [useCache] reuse reports younger than 15s.
   * @returns {{ workspaces: Array<object> }}
   */
  async report(useCache = true) {
    const now = Date.now();
    return {
      workspaces: await Promise.all(this.readWorkspaces().map(async (workspace) => {
        const normalized = key(workspace.path);
        const cached = this.reportCache?.get(normalized);
        let permissions;
        if (useCache && cached !== undefined && now - cached.at < 15_000) {
          permissions = cached.value;
        } else {
          permissions = await inspectWorkspace(workspace.path);
          if (this.reportCache === undefined) this.reportCache = new Map();
          this.reportCache.set(normalized, { at: now, value: permissions });
        }
        const row = {
          path: workspace.path,
          title: workspace.title,
          tempInside: containsTempRoot(workspace.path),
          trusted: this.trusted.has(normalized),
          dismissed: this.dismissed.has(normalized),
          propagated: this.propagated.has(normalized),
          // The registry entity filters `sessionIds` by the live canonical-cwd
          // index, so the browser can name its workspace without a second probe.
          sessionIds: Array.isArray(workspace.sessionIds) ? [...workspace.sessionIds] : [],
          permissions
        };
        // Both browser surfaces read the same verdict, so the rule that decides
        // "usable" lives in status.mjs instead of being re-implemented there.
        row.issues = issueCodes(row);
        row.needsRepair = entryNeedsRepair(row);
        return row;
      }))
    };
  }

  /**
   * Repair one registered workspace: user FullControl, then the harness grant and
   * the Low label propagated through the existing subtree, then a fresh report.
   * @param {string} path workspace path reported by the browser.
   * @returns {{ ok: boolean, message?: string, entry?: object }}
   */
  async repair(path) {
    const normalized = key(path);
    const known = this.readWorkspaces().find((workspace) => key(workspace.path) === normalized);
    if (known === undefined) {
      return { ok: false, message: 'this folder is not a registered workspace' };
    }
    if (containsTempRoot(known.path)) {
      return { ok: false, message: 'This folder contains the harness temp directory; the confined sandbox can never use it. Switch the session to full access instead.' };
    }
    const before = await probeDirectory(known.path);
    if (before.state !== 'ok') {
      const grant = await grantFullControl(known.path);
      if (!grant.ok) {
        return { ok: false, message: grant.error ?? 'Windows still denies your account the right to change this folder\'s permissions.' };
      }
    }
    const propagation = await propagateWorkspace(known.path);
    this.reportCache?.delete(normalized);
    if (propagation.ok !== true) {
      return { ok: false, message: propagation.error ?? 'the grant could not be pushed through the existing subfolders' };
    }
    this.trusted.add(normalized);
    this.propagated.add(normalized);
    this.pending.delete(normalized);
    this.persist();
    const fresh = await this.report(false);
    const entry = fresh.workspaces.find((workspace) => key(workspace.path) === normalized);
    return { ok: true, entry };
  }

  /** Record a refusal so the same folder does not prompt again. */
  dismiss(path) {
    const normalized = key(path);
    this.pending.delete(normalized);
    this.dismissed.add(normalized);
    this.persist();
    return { ok: true };
  }

  /** Diagnostics for the host half. */
  debugInfo() {
    return {
      started: this.started,
      polls: this.polls,
      seen: this.seen.size,
      queued: this.queue.length,
      pending: this.snapshot().pending,
      workspaces: this.readWorkspaces().map((row) => ({ path: row.path, title: row.title })),
      lastError: this.lastError
    };
  }

  /** Write the handled sets; a failed write is logged, never thrown. */
  persist() {
    try {
      const file = stateFile();
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, JSON.stringify({
        trusted: [...this.trusted],
        dismissed: [...this.dismissed],
        propagated: [...this.propagated]
      }, null, 2), 'utf8');
    } catch (error) {
      this.logger?.warn?.(`folder-trust: state write failed: ${String(error?.message ?? error)}`);
    }
  }
}




