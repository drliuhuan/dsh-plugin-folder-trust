// Headless contract test for the browser half.
//
// The client bundle is a classic script that talks to the harness only through
// `window.__ModuleLoader__`, `require('react')`, `fetch`, and the slot API, so
// the whole surface can be exercised in a VM with stubs: this pins what the
// composer chip shows, what it hides, and what the settings page lists.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const here = dirname(fileURLToPath(import.meta.url));
const CLIENT = readFileSync(join(here, '..', 'client.js'), 'utf8');

/** A workspace report row; override only what a case cares about. */
function row(path, { sessionIds = [], title, tempInside = false } = {}, permissions = {}) {
  return {
    path,
    title: title ?? path.split('\\').pop(),
    tempInside,
    trusted: true,
    propagated: true,
    sessionIds,
    permissions: {
      ok: true,
      writeDac: true,
      writeOwner: true,
      rootGrant: true,
      childDirs: 1,
      childDirsWithGrant: 1,
      ...permissions
    }
  };
}

/**
 * Minimal hook runtime: hook slots persist across renders, an effect re-runs
 * only when its dependency array changes, and `createElement` produces the
 * plain object tree the assertions walk.
 */
function createRuntime() {
  const slots = [];
  let pending = [];
  let cursor = 0;
  let dirty = false;

  function claim(kind) {
    const index = cursor;
    cursor += 1;
    if (slots[index] === undefined) slots[index] = { kind };
    return index;
  }

  const React = {
    useState(initial) {
      const index = claim('state');
      const slot = slots[index];
      if (!('value' in slot)) slot.value = initial;
      return [slot.value, (next) => {
        const current = slots[index].value;
        const value = typeof next === 'function' ? next(current) : next;
        if (!Object.is(value, current)) {
          slots[index].value = value;
          dirty = true;
        }
      }];
    },
    useEffect(fn, deps) {
      const index = claim('effect');
      const slot = slots[index];
      const previous = slot.deps;
      const changed = deps === undefined
        || previous === undefined
        || deps.length !== previous.length
        || deps.some((entry, at) => !Object.is(entry, previous[at]));
      slot.deps = deps;
      if (changed) {
        slot.fn = fn;
        pending.push(slot);
      }
    },
    useCallback(fn, deps) {
      claim('callback');
      return fn;
    },
    createElement(type, props) {
      const children = Array.prototype.slice.call(arguments, 2);
      return { type, props: { ...(props ?? {}), children } };
    }
  };

  async function flush() {
    await new Promise((resolve) => setImmediate(resolve));
  }

  return {
    React,
    async render(Component, props) {
      let element;
      for (let pass = 0; pass < 8; pass += 1) {
        cursor = 0;
        dirty = false;
        pending = [];
        element = Component(props ?? {});
        const effectBatch = pending;
        pending = [];
        for (const slot of effectBatch) {
          const cleanup = slot.fn();
          slot.cleanup = typeof cleanup === 'function' ? cleanup : undefined;
        }
        await flush();
        if (!dirty) return element;
      }
      throw new Error('component kept re-rendering');
    },
    unmount() {
      for (const slot of slots) {
        if (typeof slot.cleanup === 'function') {
          try {
            slot.cleanup();
          } catch {
            // cleanup is best effort in the stub too
          }
        }
      }
    }
  };
}

/** Text of one element tree, flattened. */
function texts(node) {
  if (node === null || node === undefined) return [];
  if (typeof node === 'string' || typeof node === 'number') return [String(node)];
  if (Array.isArray(node)) return node.flatMap(texts);
  return texts(node.props?.children);
}

/** Every button whose visible text is exactly `label`. */
function buttons(node, label) {
  const found = [];
  (function walk(current) {
    if (current === null || typeof current !== 'object') return;
    if (Array.isArray(current)) {
      current.forEach(walk);
      return;
    }
    if (current.type === 'button' && texts(current).join('') === label) found.push(current);
    walk(current.props?.children);
  })(node);
  return found;
}

/**
 * Boot the bundle in a VM and hand back its slot registrations.
 * @param {{report: Array<object>, listItems?: Array<object>}} host stubs.
 */
async function boot(host) {
  const runtime = createRuntime();
  const registrations = [];
  const probes = [];
  const document = {
    head: { appendChild() {} },
    getElementById: () => null,
    createElement: () => ({ set textContent(value) { this._text = value; }, get textContent() { return this._text; } })
  };
  const sandbox = {
    window: {},
    document,
    navigator: { language: 'zh-CN' },
    console,
    setInterval: () => 1,
    clearInterval: () => {},
    setTimeout,
    clearTimeout,
    Promise,
    Object,
    Array,
    JSON,
    String,
    Number,
    Boolean,
    Error,
    Math,
    RegExp,
    fetch: (url, init = {}) => {
      if (String(url).includes('/folder-trust/debug')) {
        probes.push(init.body);
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ ok: true }) });
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ workspaces: host.report })
      });
    }
  };
  sandbox.window.__ModuleLoader__ = { load: (definition) => { sandbox.__definition = definition; } };
  vm.createContext(sandbox);
  vm.runInContext(CLIENT, sandbox);

  const definition = sandbox.__definition;
  const module = definition.factory(() => runtime.React);
  const listHandle = { getSnapshot: () => ({ phase: 'ready', items: host.listItems ?? [] }) };
  const ctx = {
    get: (name) => (name === 'workspaces' ? { list: listHandle } : undefined),
    slots: {
      inject: (name, fn) => { registrations.push(fn()); },
      register: (options, component) => {
        registrations.push({ name: options.name, options, component });
        return { dispose() {} };
      }
    }
  };
  module.apply(ctx);
  await new Promise((resolve) => setImmediate(resolve));

  const byId = (id) => registrations.find((entry) => entry.options?.id === id);
  return { runtime, registrations, probes, byId };
}

/** A report where D:\temp has never inherited the grant, and E:\Games is healthy. */
function mixedReport() {
  return [
    row('E:\\Games', { sessionIds: ['s-ok'] }),
    row('D:\\temp', { sessionIds: ['s-bad'] }, { childDirs: 6, childDirsWithGrant: 0 })
  ];
}

test('registers the trust overlay, the composer check and the settings section', async () => {
  const { byId, registrations } = await boot({ report: mixedReport() });
  assert.ok(byId('folder-trust'), 'trust overlay');
  assert.ok(byId('folder-trust-check'), 'composer check');
  assert.ok(byId('folder-trust-permissions'), 'settings section');
  assert.equal(byId('folder-trust-check').options.name, 'conversation.input.right');
  assert.equal(byId('folder-trust-check').options.inject, undefined, 'sessionId is a standard prop');
  assert.equal(byId('folder-trust-permissions').options.name, 'settings.section');
  assert.equal(byId('folder-trust-permissions').options.label(), '工作区权限');
  assert.ok(registrations.some((entry) => entry.name === 'shell.overlay'));
});

test('the chip is hidden when the current workspace is usable', async () => {
  const { byId, runtime } = await boot({
    report: mixedReport(),
    listItems: [{ workspaceId: 'w1', path: 'E:\\Games', sessionIds: ['s-ok'] }]
  });
  const check = byId('folder-trust-check').component;
  assert.equal(await runtime.render(check, { sessionId: 's-ok' }), null);
});

test('the chip appears for the current workspace only, and its dialog lists only that one', async () => {
  const { byId, runtime, probes } = await boot({
    report: mixedReport(),
    listItems: [{ workspaceId: 'w2', path: 'D:\\temp', sessionIds: ['s-bad'] }]
  });
  const check = byId('folder-trust-check').component;
  const chip = await runtime.render(check, { sessionId: 's-bad' });
  assert.ok(chip, 'chip rendered');
  assert.equal(chip.type, 'button');
  assert.equal(chip.props.className, 'dshft-check');
  assert.deepEqual(texts(chip), ['工作区权限异常']);
  assert.equal(probes.length > 0, true, 'slot props were reported for diagnostics');
  assert.equal(probes[0].includes('sessionId'), true);

  const stillClosed = await runtime.render(check, { sessionId: 's-bad' });
  assert.equal(stillClosed.type, 'button', 'a closed chip renders only the chip');
  assert.doesNotMatch(texts(stillClosed).join(' '), /当前工作区权限/);

  // Clicking the chip opens the report for that workspace only.
  chip.props.onClick();
  const opened = await runtime.render(check, { sessionId: 's-bad' });
  const shown = texts(opened).join(' ');
  assert.match(shown, /当前工作区权限/);
  assert.match(shown, /D:\\temp/);
  assert.doesNotMatch(shown, /E:\\Games/);
  assert.equal(buttons(opened, '修复权限').length, 1);
});

test('a useSession-only host (snapshot carries no cwd) hides the chip instead of guessing', async () => {
  // Regression guard: `useSession` returns a SessionSnapshot, which has no cwd.
  // Reading `.cwd` off it must never be treated as "workspace resolved". A host
  // that predates the report's `sessionIds` field offers no other handle here.
  const report = mixedReport().map((entry) => ({ ...entry, sessionIds: undefined }));
  const { byId, runtime, probes } = await boot({ report, listItems: [] });
  const check = byId('folder-trust-check').component;
  const props = {
    sessionId: 's-bad',
    useSession: (selector) => selector({ sessionId: 's-bad', running: false, blank: false })
  };
  assert.equal(await runtime.render(check, props), null);
  assert.equal(probes.length > 0, true, 'the component still mounted and reported its props');
});

test('after the host reports sessionIds the chip resolves without any hook', async () => {
  const { byId, runtime } = await boot({ report: mixedReport(), listItems: [] });
  const check = byId('folder-trust-check').component;
  const chip = await runtime.render(check, { sessionId: 's-bad' });
  assert.ok(chip, 'the report row claiming this session resolved the workspace');
  assert.deepEqual(texts(chip), ['工作区权限异常']);
});

test('the chip resolves the workspace from the shell standard hooks', async () => {
  // The real host hands session-scoped entries `sessionId` + the snapshot hooks;
  // no ctx store access is involved on that path.
  const { byId, runtime } = await boot({ report: mixedReport(), listItems: [] });
  const check = byId('folder-trust-check').component;
  const props = {
    sessionId: 's-bad',
    useSessions: (selector) => selector({ ids: ['s-bad'], byId: { 's-bad': { id: 's-bad', cwd: 'D:\\temp' } } }),
    useWorkspaces: (selector) => selector({ items: [{ workspaceId: 'w2', path: 'D:\\temp', sessionIds: ['s-bad'] }] })
  };
  const chip = await runtime.render(check, props);
  assert.ok(chip, 'the session cwd resolved to a workspace that needs repair');
  assert.deepEqual(texts(chip), ['工作区权限异常']);
});

test('a session whose summary has no cwd yet falls back to the workspace row', async () => {
  const { byId, runtime } = await boot({ report: mixedReport(), listItems: [] });
  const check = byId('folder-trust-check').component;
  const props = {
    sessionId: 's-bad',
    useSessions: (selector) => selector({ ids: ['s-bad'], byId: { 's-bad': { id: 's-bad' } } }),
    useWorkspaces: (selector) => selector({ items: [{ workspaceId: 'w2', path: 'D:\\temp', sessionIds: ['s-bad'] }] })
  };
  assert.ok(await runtime.render(check, props));
});

test('the chip stays hidden when the session maps to no workspace', async () => {
  const { byId, runtime } = await boot({ report: mixedReport(), listItems: [] });
  const check = byId('folder-trust-check').component;
  assert.equal(await runtime.render(check, { sessionId: 's-unknown' }), null);
  assert.equal(await runtime.render(check, {}), null);
});

test('the settings page lists every workspace with its own repair action', async () => {
  const { byId, runtime } = await boot({ report: mixedReport(), listItems: [] });
  const page = byId('folder-trust-permissions').component;
  const element = await runtime.render(page, {});
  const shown = texts(element).join(' ');
  assert.match(shown, /工作区权限/);
  assert.match(shown, /E:\\Games/);
  assert.match(shown, /D:\\temp/);
  assert.equal(buttons(element, '修复权限').length, 1);
  assert.equal(buttons(element, '重新检测').length, 1);
});

test('a temp-root workspace is reported as unusable and never repairable', async () => {
  const report = [row('C:\\Users\\someone', { sessionIds: ['s-home'], tempInside: true }, {
    rootGrant: false,
    childDirs: 3,
    childDirsWithGrant: 0
  })];
  const { byId, runtime } = await boot({
    report,
    listItems: [{ workspaceId: 'w3', path: 'C:\\Users\\someone', sessionIds: ['s-home'] }]
  });
  const check = byId('folder-trust-check').component;
  assert.equal(await runtime.render(check, { sessionId: 's-home' }), null);
  const page = byId('folder-trust-permissions').component;
  const element = await runtime.render(page, {});
  assert.equal(buttons(element, '修复权限').length, 0);
  assert.match(texts(element).join(' '), /包含临时目录/);
});

test('an unreadable report still renders a repairable row', async () => {
  const report = [{ path: 'E:\\Games', title: 'Games', tempInside: false, permissions: { ok: false, error: 'denied' } }];
  const { byId, runtime } = await boot({
    report,
    listItems: [{ workspaceId: 'w1', path: 'E:\\Games', sessionIds: ['s-ok'] }]
  });
  const check = byId('folder-trust-check').component;
  const chip = await runtime.render(check, { sessionId: 's-ok' });
  assert.ok(chip, 'an unreadable workspace shows the chip');
  const page = byId('folder-trust-permissions').component;
  const element = await runtime.render(page, {});
  assert.equal(buttons(element, '修复权限').length, 1);
});

test('the fixed chip box matches the composer control row', () => {
  // Hard-coded on purpose: another deployment may have no pwsh7 chip to measure.
  assert.match(CLIENT, /var CHIP_WIDTH = 108;/);
  assert.match(CLIENT, /var CHIP_HEIGHT = 20;/);
  assert.match(CLIENT, /'width:' \+ CHIP_WIDTH \+ 'px;height:' \+ CHIP_HEIGHT \+ 'px/);
  assert.match(CLIENT, /border-radius:5px/);
});
