// dsh-plugin-folder-trust — Web client half.
//
// Two surfaces, one service:
//
//   * `shell.overlay` — the one-time folder-trust prompt shown when a workspace
//     was just added and the harness could not provision its own write grant.
//   * `conversation.input.right` — the permission check for the workspace this
//     composer belongs to. It stays hidden while that workspace is usable and
//     appears as a fixed-size "工作区权限异常" control when it is not; clicking it
//     shows only that workspace's problems and a repair action.
//   * `settings.section` — every registered workspace, with the same repair.
//
// Loaded through the harness module loader as a classic script, so React comes
// from the loader's `require` and nothing is imported at module scope. The
// repair/verdict rules themselves live in `lib/status.mjs` on the host half;
// this file only renders what `GET /folder-trust/report` reports.
(function () {
  'use strict';

  var PLUGIN_ID = 'dsh-plugin-folder-trust';
  var ROUTE_STATE = '/folder-trust/state';
  var ROUTE_TRUST = '/folder-trust/trust';
  var ROUTE_DISMISS = '/folder-trust/dismiss';
  var ROUTE_REPORT = '/folder-trust/report';
  var ROUTE_REPAIR = '/folder-trust/repair';
  var ROUTE_DEBUG = '/folder-trust/debug';
  var POLL_MS = 2000;
  var CHECK_POLL_MS = 15000;
  var STYLE_ID = 'dsh-folder-trust-style';

  // The permission-check control sits in the composer's control row next to the
  // pwsh7 chip. That row is 20px tall, so the box is hard-coded to the same
  // height and to a width that fits the longest label, instead of measuring a
  // neighbour that another deployment may not install.
  var CHIP_HEIGHT = 20;
  var CHIP_WIDTH = 108;

  var TEXT = {
    zh: {
      title: '信任此文件夹吗？',
      body: 'DSH 需要修改这个文件夹的权限，才能在工作区内修改时让受限 shell 写入其中。点「信任文件夹」会给你的 Windows 账户补一条完全控制权限，并把权限和 Low 完整性标签铺到已有的子文件夹；点「忽略」不会改动任何权限。',
      ignoreNote: '忽略后不会再提示这个文件夹。但在「工作区内修改」模式下，DSH 仍无法为它准备写权限：之后每次需要在其中写入时，沙箱都会再次请求授权（你也可以临时把会话切到「完全权限」）。',
      tempBody: '这个文件夹包含了 DSH 的临时目录，受限沙箱无法在这里工作（无论权限如何）。请把工作区换到别处，或把本会话切到「完全权限」。',
      trust: '信任文件夹',
      cancel: '忽略',
      busy: '正在授予…',
      retry: '重试',
      granted: '已授予，可以继续工作。',
      failed: '授予失败',
      noteMissing: '缺少权限：',
      rightsDac: '修改权限',
      rightsOwner: '修改所有者/完整性标签',
      checkChip: '工作区权限异常',
      checkChipHint: '当前工作区的权限不足以支持「工作区内修改」，点此查看并修复',
      checkTitle: '当前工作区权限',
      checkIntro: '下面的状态来自真实探测：你的账户权利、沙箱写入授权是否已落在工作区根目录、以及是否已继承到已有的子文件夹。修复会补当前账户完全控制，并把授权与 Low 完整性标签铺到已有子目录。',
      checkReady: '当前工作区权限正常。',
      checkClose: '关闭',
      checkRepair: '修复权限',
      checkRepairing: '正在修复…',
      checkRepairFailed: '修复失败',
      checkFailedPrefix: '探测失败：',
      settingsNav: '工作区权限',
      settingsTitle: '工作区权限',
      settingsSubtitle: '所有已注册工作区的读写权限状态。修复只作用于已注册工作区，不会改动文件内容或所有者。',
      settingsRefresh: '重新检测',
      settingsRefreshing: '正在检测…',
      settingsLoading: '正在检测工作区权限…',
      settingsEmpty: '还没有注册任何工作区。',
      settingsUnavailable: '当前宿主没有提供工作区注册表，无法列出工作区。',
      account: '账户',
      accountOk: '可改权限与所有者',
      accountMissing: '缺少 ',
      grant: '沙箱授权',
      grantOk: '根目录已就绪',
      grantMissing: '根目录未就绪',
      children: '子文件夹',
      noChildren: '无子文件夹',
      childrenOk: '{done}/{total} 已继承',
      childrenPartial: '{done}/{total} 已继承',
      temp: '包含临时目录，无法使用',
      unreadable: '无法读取权限',
      ready: '已就绪',
      repair: '修复权限',
      repairing: '正在修复…',
      repairFailed: '修复失败'
    },
    en: {
      title: 'Trust this folder?',
      body: 'DSH must change this folder\'s permissions so its confined shell can write inside your workspace. Trusting adds a full-control entry for your Windows account and pushes the grant plus the Low integrity label through the folders that already exist; ignoring leaves every permission untouched.',
      ignoreNote: 'Ignoring stops this prompt for this folder. In workspace-write mode DSH still cannot provision it, so the sandbox will ask for authorization again on every write there (or you can switch the session to full access for a while).',
      tempBody: 'This folder contains the harness temp directory, so the confined sandbox can never use it, whatever its permissions say. Pick another workspace or switch this session to full access.',
      trust: 'Trust folder',
      cancel: 'Ignore',
      busy: 'Granting…',
      retry: 'Retry',
      granted: 'Granted. You can keep working.',
      failed: 'Could not grant',
      noteMissing: 'Missing rights: ',
      rightsDac: 'change permissions',
      rightsOwner: 'change owner / integrity label',
      checkChip: 'Workspace access',
      checkChipHint: 'This workspace cannot be used in workspace-write mode; open its permission report and repair it.',
      checkTitle: 'Current workspace access',
      checkIntro: 'These states come from real probes: your account rights, whether the sandbox grant reached the workspace root, and whether it inherited into the folders that already exist. Repair grants your account full control and pushes the grant plus the Low integrity label through the existing subtree.',
      checkReady: 'This workspace is usable.',
      checkClose: 'Close',
      checkRepair: 'Repair access',
      checkRepairing: 'Repairing…',
      checkRepairFailed: 'Repair failed',
      checkFailedPrefix: 'Probe failed: ',
      settingsNav: 'Workspace access',
      settingsTitle: 'Workspace access',
      settingsSubtitle: 'Read/write permission state for every registered workspace. Repair only touches registered workspaces and never changes file contents or owners.',
      settingsRefresh: 'Check again',
      settingsRefreshing: 'Checking…',
      settingsLoading: 'Checking workspace permissions…',
      settingsEmpty: 'No workspaces are registered yet.',
      settingsUnavailable: 'This host exposes no workspace registry, so there is nothing to list.',
      account: 'Account',
      accountOk: 'can change permissions and owner',
      accountMissing: 'missing ',
      grant: 'Sandbox grant',
      grantOk: 'root ready',
      grantMissing: 'root not ready',
      children: 'Subfolders',
      noChildren: 'no subfolders',
      childrenOk: '{done}/{total} inherited',
      childrenPartial: '{done}/{total} inherited',
      temp: 'contains the temp root, unusable',
      unreadable: 'cannot read permissions',
      ready: 'Ready',
      repair: 'Repair access',
      repairing: 'Repairing…',
      repairFailed: 'Repair failed'
    }
  };

  function text() {
    var lang = typeof navigator !== 'undefined' && typeof navigator.language === 'string' ? navigator.language.toLowerCase() : 'en';
    return lang.indexOf('zh') === 0 ? TEXT.zh : TEXT.en;
  }

  function fmt(template, values) {
    var out = template;
    Object.keys(values).forEach(function (key) {
      out = out.replace('{' + key + '}', String(values[key]));
    });
    return out;
  }

  function insertStyle() {
    if (typeof document === 'undefined' || document.getElementById(STYLE_ID)) return;
    var style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = [
      '.dshft-backdrop{position:fixed;inset:0;z-index:60;display:flex;align-items:center;justify-content:center;',
      'background:rgba(0,0,0,.55);padding:24px;box-sizing:border-box}',
      '.dshft-card{width:min(560px,100%);border-radius:18px;background:#2b2b2b;color:#f2f2f2;',
      'box-shadow:0 24px 64px rgba(0,0,0,.45);padding:22px 22px 16px;font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}',
      '.dshft-title{font-size:20px;font-weight:650;text-align:center;margin:2px 0 14px}',
      '.dshft-path{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px;color:#b9b9b9;',
      'text-align:center;margin:0 0 14px;word-break:break-all}',
      '.dshft-body{color:#d6d6d6;margin:0 0 10px}',
      '.dshft-note{color:#e0a458;margin:0 0 10px;font-size:13px}',
      '.dshft-ignore{color:#a9a9a9;margin:12px 0 0;font-size:12.5px;line-height:1.45}',
      '.dshft-error{color:#ff8a8a;margin:8px 0 0;font-size:13px;white-space:pre-wrap;word-break:break-word}',
      '.dshft-actions{display:flex;flex-direction:column;gap:10px;margin-top:18px}',
      '.dshft-btn{appearance:none;border:1px solid transparent;border-radius:999px;padding:12px 16px;font:inherit;',
      'font-weight:600;cursor:pointer;transition:filter .15s ease}',
      '.dshft-btn:disabled{opacity:.55;cursor:default}',
      '.dshft-primary{background:#f4f4f4;color:#1b1b1b}',
      '.dshft-primary:hover:not(:disabled){filter:brightness(.94)}',
      '.dshft-secondary{background:transparent;color:#ededed;border-color:rgba(255,255,255,.28)}',
      '.dshft-secondary:hover:not(:disabled){background:rgba(255,255,255,.07)}',
      '.dshft-runlog{margin:10px 0 4px;border:1px solid rgba(255,255,255,.12);border-radius:12px;padding:10px;background:rgba(0,0,0,.22)}',
      '.dshft-barout{height:6px;border-radius:999px;background:rgba(255,255,255,.12);overflow:hidden;margin-bottom:8px}',
      '.dshft-barin{height:100%;background:#8ee6a1;transition:width .2s ease}',
      '.dshft-log{margin:0;max-height:180px;overflow:auto;font:11.5px/1.5 ui-monospace,Consolas,monospace;color:#cfcfcf;white-space:pre-wrap;word-break:break-all}',
      // Permission check: a fixed 20px box, the same height and radius as the
      // composer's pwsh7 chip, so the two read as one control row.
      '.dshft-check{box-sizing:border-box;display:inline-flex;align-items:center;justify-content:center;',
      'width:' + CHIP_WIDTH + 'px;height:' + CHIP_HEIGHT + 'px;padding:0;margin:0;',
      'border:1px solid var(--dsw-alias-state-error-primary,#ff9a9a);border-radius:5px;',
      'background:var(--dsw-static-red-600-a08,rgba(255,154,154,.12));',
      'color:var(--dsw-alias-state-error-primary,#ff9a9a);font:inherit;font-size:12px;line-height:18px;',
      'white-space:nowrap;overflow:hidden;cursor:pointer}',
      '.dshft-check:hover{filter:brightness(1.08)}',
      '.dshft-check:focus-visible{outline:var(--dsw-focus-ring-width,2px) solid var(--dsw-alias-state-error-primary,#ff9a9a);',
      'outline-offset:2px}',
      // Reports
      '.dshft-card-wide{width:min(720px,100%);max-height:min(82vh,760px);overflow:auto}',
      '.dshft-wslist{display:flex;flex-direction:column;gap:10px;margin:12px 0 6px;max-height:54vh;overflow:auto}',
      '.dshft-wsrow{border:1px solid rgba(255,255,255,.12);border-radius:12px;padding:10px 12px}',
      '.dshft-wstitle{font-weight:600}',
      '.dshft-wspath{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;color:#b9b9b9;',
      'word-break:break-all;margin:2px 0 6px}',
      '.dshft-wsline{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:6px}',
      '.dshft-tag{font-size:12px;border-radius:999px;padding:3px 9px;border:1px solid rgba(255,255,255,.2);color:#cfcfcf}',
      '.dshft-tag.good{color:#8ee6a1;border-color:rgba(142,230,161,.4)}',
      '.dshft-tag.warn{color:#e0a458;border-color:rgba(224,164,88,.4)}',
      '.dshft-tag.bad{color:#ff9a9a;border-color:rgba(255,154,154,.4)}',
      '.dshft-repair{appearance:none;border-radius:999px;border:1px solid rgba(244,244,244,.85);background:#f4f4f4;',
      'color:#1b1b1b;font:600 12px/1.3 inherit;padding:5px 12px;cursor:pointer}',
      '.dshft-repair:disabled{opacity:.55;cursor:default}',
      // Settings page: the section owns its scroll area, like the pwsh7 page.
      '.dshft-setRoot{box-sizing:border-box;height:100%;display:flex;flex-direction:column;min-width:0;',
      'color:var(--dsw-alias-label-primary)}',
      '.dshft-setScroll{flex:1;min-height:0;overflow-y:auto;overflow-x:hidden;padding:4px 4px 48px;scroll-padding-bottom:48px}',
      '.dshft-setInner{box-sizing:border-box;width:100%;max-width:760px;margin:0 auto;display:flex;flex-direction:column;gap:16px}',
      '.dshft-setHead{display:flex;flex-wrap:wrap;align-items:center;gap:8px;min-width:0;padding:4px 4px 0}',
      '.dshft-setTitle{margin:0;font-size:16px;line-height:24px;font-weight:500}',
      '.dshft-setSubtitle{flex:1 1 100%;margin:0;font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary)}',
      '.dshft-card2{box-sizing:border-box;display:flex;flex-direction:column;gap:10px;min-width:0;padding:14px 16px;',
      'border:1px solid var(--dsw-alias-settings-card-stroke,var(--dsw-alias-border-l2));',
      'border-radius:var(--dsw-radius-lg,12px);background:var(--dsw-alias-settings-card-fill,transparent)}',
      '.dshft-card2Head{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}',
      '.dshft-card2Title{margin:0;font-size:14px;line-height:22px;font-weight:500}',
      '.dshft-card2Path{margin:0;font-family:var(--ds-font-family-code,ui-monospace,monospace);font-size:12px;line-height:18px;',
      'color:var(--dsw-alias-label-secondary);word-break:break-all}',
      '.dshft-flags{display:flex;flex-wrap:wrap;gap:6px;margin:0;padding:0}',
      '.dshft-flag{display:inline-flex;align-items:center;gap:5px;padding:1px 8px;border-radius:999px;',
      'border:.5px solid var(--dsw-alias-border-l2);font-size:11px;line-height:18px;color:var(--dsw-alias-label-tertiary)}',
      '.dshft-flag[data-tone=good]{color:var(--dsw-alias-state-success-primary);border-color:var(--dsw-alias-state-success-primary)}',
      '.dshft-flag[data-tone=warn]{color:var(--dsw-alias-label-secondary);border-color:var(--dsw-alias-border-l3)}',
      '.dshft-flag[data-tone=bad]{color:var(--dsw-alias-state-error-primary);border-color:var(--dsw-alias-state-error-primary)}',
      '.dshft-setActions{display:flex;flex-wrap:wrap;align-items:center;gap:8px}',
      '.dshft-btn2{appearance:none;box-sizing:border-box;height:28px;padding:0 12px;border-radius:var(--dsw-radius-md,8px);',
      'border:.5px solid var(--dsw-alias-border-l3);background:transparent;color:var(--dsw-alias-label-primary);',
      'font:inherit;font-size:12px;line-height:26px;cursor:pointer;white-space:nowrap}',
      '.dshft-btn2:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover)}',
      '.dshft-btn2:disabled{opacity:.5;cursor:not-allowed}',
      '.dshft-empty{margin:0;font-size:13px;line-height:20px;color:var(--dsw-alias-label-tertiary)}',
      '.dshft-setError{margin:0;font-size:12px;line-height:18px;color:var(--dsw-alias-state-error-primary);white-space:pre-wrap}'
    ].join('');
    document.head.appendChild(style);
  }

  function fetchState() {
    return fetch(ROUTE_STATE, { cache: 'no-store', credentials: 'same-origin' }).then(function (response) {
      if (!response.ok) throw new Error('HTTP ' + response.status);
      return response.json();
    });
  }

  /**
   * POST one NDJSON streaming action and report every frame.
   * @param {string} url route path.
   * @param {string} path workspace path.
   * @param {(event: object) => void} onEvent frame sink.
   * @returns {Promise<{ status: number, body: object }>}
   */
  /**
   * POST one NDJSON streaming action and report every frame AS IT ARRIVES.
   * `response.text()` would buffer the whole body until the repair finishes, so
   * this reads the body reader incrementally and splits frames across chunks.
   * @param {string} url route path.
   * @param {string} path workspace path.
   * @param {(event: object) => void} onEvent frame sink.
   * @returns {Promise<{ status: number, body: object }>}
   */
  function postStream(url, path, onEvent) {
    return fetch(url, {
      method: 'POST',
      cache: 'no-store',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ path: path })
    }).then(function (response) {
      var body = {};
      function handle(raw) {
        var text = String(raw).trim();
        if (text.length === 0) return;
        var frame;
        try { frame = JSON.parse(text); } catch (error) { return; }
        if (typeof onEvent === 'function') onEvent(frame);
        if (frame && typeof frame.ok === 'boolean') body = frame;
      }
      if (response.body && typeof response.body.getReader === 'function') {
        var reader = response.body.getReader();
        var decoder = new TextDecoder();
        var buffer = '';
        function pump() {
          return reader.read().then(function (chunk) {
            if (chunk.done) {
              if (buffer.length > 0) handle(buffer);
              return { status: response.status, body: body };
            }
            buffer += decoder.decode(chunk.value, { stream: true });
            var index;
            while ((index = buffer.indexOf('\n')) >= 0) {
              handle(buffer.slice(0, index));
              buffer = buffer.slice(index + 1);
            }
            return pump();
          });
        }
        return pump();
      }
      return response.text().then(function (text) {
        String(text).split('\n').forEach(handle);
        return { status: response.status, body: body };
      });
    });
  }
  function postJson(url, path) {
    return fetch(url, {
      method: 'POST',
      cache: 'no-store',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ path: path })
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (body) {
        return { status: response.status, body: body };
      });
    });
  }

  function FolderTrustDialog() {
    var React = window.__DSH_FOLDER_TRUST_REACT__;
    var t = text();
    var pendingState = React.useState([]);
    var pending = pendingState[0];
    var setPending = pendingState[1];
    var busyState = React.useState(false);
    var busy = busyState[0];
    var setBusy = busyState[1];
    var errorState = React.useState(null);
    var errorText = errorState[0];
    var setError = errorState[1];
    var runState = React.useState(null);
    var run = runState[0];
    var setRun = runState[1];
    var runner = useRepairRun(React);
    var logsState = React.useState({});
    var logs = logsState[0];
    var setLogs = logsState[1];
    var progressState = React.useState({});
    var progress = progressState[0];
    var setProgress = progressState[1];

    React.useEffect(function () {
      insertStyle();
      var alive = true;
      function refresh() {
        fetchState().then(function (body) {
          if (!alive) return;
          setPending(Array.isArray(body.pending) ? body.pending : []);
        }).catch(function () { /* the harness may be restarting */ });
      }
      refresh();
      var timer = setInterval(refresh, POLL_MS);
      return function () {
        alive = false;
        clearInterval(timer);
      };
    }, []);

    var current = pending.length > 0 ? pending[0] : null;
    if (current === null) return null;

    var blockedByTemp = current.reason === 'temp-inside-workspace';
    var missing = [];
    if (current.writeDac === false) missing.push(t.rightsDac);
    if (current.writeOwner === false) missing.push(t.rightsOwner);

    function decide() {
      if (busy) return;
      setBusy(true);
      setError(null);
      setRun({ lines: [], progress: 0, busy: true });
      postStream(ROUTE_REPAIR, current.path, function (event) {
        setRun(function (previous) {
          var base = previous || { lines: [], progress: 0, busy: true };
          if (event.kind === 'line') {
            return { lines: base.lines.concat([event.line]).slice(-300), progress: base.progress, busy: true };
          }
          if (event.kind === 'progress') {
            return { lines: base.lines, progress: event.progress, busy: true };
          }
          if (event.kind === 'done') {
            return { lines: base.lines, progress: event.ok === true ? 100 : base.progress, busy: false };
          }
          return base;
        });
      }).then(function (outcome) {
        setBusy(false);
        if (outcome.body && outcome.body.ok === true) {
          setPending(function (rows) { return rows.filter(function (row) { return row.path !== current.path; }); });
          return;
        }
        setError((outcome.body && outcome.body.message) || t.failed);
      }).catch(function (caught) {
        setBusy(false);
        setError(String(caught && caught.message ? caught.message : caught));
      });
    }

    function cancel() {
      if (busy) return;
      setPending(function (rows) { return rows.filter(function (row) { return row.path !== current.path; }); });
      postJson(ROUTE_DISMISS, current.path).catch(function () { /* dismissal is best effort */ });
    }

    return React.createElement('div', { className: 'dshft-backdrop', role: 'presentation' },
      React.createElement('div', {
        className: 'dshft-card',
        role: 'dialog',
        'aria-modal': 'true',
        'aria-label': t.title
      },
      React.createElement('div', { className: 'dshft-title' }, t.title),
      React.createElement('p', { className: 'dshft-path' }, current.path),
      React.createElement('p', { className: 'dshft-body' }, blockedByTemp ? t.tempBody : t.body),
      (!blockedByTemp && missing.length > 0)
        ? React.createElement('p', { className: 'dshft-note' }, t.noteMissing + missing.join(' / '))
        : null,
      (!blockedByTemp && !busy && errorText === null)
        ? React.createElement('p', { className: 'dshft-ignore' }, t.ignoreNote)
        : null,
      errorText === null ? null : React.createElement('p', { className: 'dshft-error' }, errorText),
      renderRunLog(React, run),
      React.createElement('div', { className: 'dshft-actions' },
        blockedByTemp
          ? null
          : React.createElement('button', {
            type: 'button',
            className: 'dshft-btn dshft-primary',
            disabled: busy,
            onClick: decide
          }, busy ? t.busy : t.trust),
        React.createElement('button', {
          type: 'button',
          className: 'dshft-btn dshft-secondary',
          disabled: busy,
          onClick: cancel
        }, t.cancel)
      ))
    );
  }

  // ---- shared status rendering -------------------------------------------

  /**
   * The host computes `issues` / `needsRepair` from `lib/status.mjs`; an older
   * host that predates those fields still renders through this fallback.
   * @param {object} entry one workspace report row.
   * @returns {string[]} issue codes.
   */
  function issuesOf(entry) {
    if (entry !== null && typeof entry === 'object') {
      if (Array.isArray(entry.issues)) return entry.issues;
      if (entry.tempInside === true) return ['temp'];
      var permissions = entry.permissions;
      if (permissions === undefined || permissions === null || permissions.ok !== true) return ['unreadable'];
      var codes = [];
      if (permissions.writeDac !== true) codes.push('writeDac');
      if (permissions.writeOwner !== true) codes.push('writeOwner');
      if (permissions.rootGrant !== true) codes.push('rootGrant');
      if ((permissions.childDirs || 0) > (permissions.childDirsWithGrant || 0)) codes.push('children');
      return codes;
    }
    return ['unreadable'];
  }

  /**
   * Per-path repair progress: `lines` is the rolling log, `progress` the bar,
   * `busy` the in-flight flag. One hook per component, keyed by workspace path.
   * @param {object} React the loader-provided React.
   * @returns {{ runs: object, start: Function }}
   */
  function useRepairRun(React) {
    var state = React.useState({});
    var runs = state[0];
    var setRuns = state[1];

    function update(path, patch) {
      setRuns(function (current) {
        var next = Object.assign({}, current);
        var run = next[path] || { lines: [], progress: 0, busy: true };
        next[path] = {
          lines: patch.lines !== undefined ? patch.lines : run.lines,
          progress: patch.progress !== undefined ? patch.progress : run.progress,
          busy: patch.busy !== undefined ? patch.busy : run.busy
        };
        return next;
      });
    }

    function start(path, onDone) {
      update(path, { lines: [], progress: 0, busy: true });
      return postRepair(path, function (event) {
        if (event.kind === 'line') {
          setRuns(function (current) {
            var next = Object.assign({}, current);
            var run = next[path] || { lines: [], progress: 0, busy: true };
            next[path] = {
              lines: run.lines.concat([event.line]).slice(-300),
              progress: run.progress,
              busy: true
            };
            return next;
          });
        } else if (event.kind === 'progress') {
          update(path, { progress: event.progress });
        } else if (event.kind === 'done') {
          update(path, { progress: event.ok === true ? 100 : undefined, busy: false });
        }
      }).then(function (outcome) {
        update(path, { busy: false, progress: outcome.body.ok === true ? 100 : undefined });
        if (typeof onDone === 'function') onDone(outcome);
        return outcome;
      }).catch(function (error) {
        update(path, { busy: false });
        if (typeof onDone === 'function') onDone({ status: 0, body: { ok: false, message: String(error && error.message ? error.message : error) } });
      });
    }

    return { runs: runs, start: start };
  }

  /**
   * The rolling repair log plus its progress bar, or null when idle.
   * @param {object} React the loader-provided React.
   * @param {object|undefined} run one `useRepairRun` entry.
   * @returns {object|null} the element.
   */
  function renderRunLog(React, run) {
    if (run === undefined || run === null) return null;
    if (run.lines.length === 0 && run.progress === 0 && run.busy !== true) return null;
    return React.createElement('div', { className: 'dshft-runlog' },
      React.createElement('div', { className: 'dshft-barout' },
        React.createElement('div', { className: 'dshft-barin', style: { width: String(run.progress || 0) + '%' } })),
      React.createElement('pre', { className: 'dshft-log' }, run.lines.join('\n')));
  }
  function needsRepair(entry) {
    if (entry !== null && typeof entry === 'object' && typeof entry.needsRepair === 'boolean') {
      return entry.needsRepair;
    }
    var codes = issuesOf(entry);
    return codes.length > 0 && codes[0] !== 'temp';
  }

  function permissionBlock(entry) {
    return entry !== null && typeof entry === 'object' && entry.permissions !== null
      && typeof entry.permissions === 'object' && entry.permissions.ok === true
      ? entry.permissions
      : undefined;
  }

  /** @returns {Array<{tone: string, text: string}>} account rights tag. */
  function accountFlag(entry, t) {
    var permissions = permissionBlock(entry);
    if (permissions === undefined) return [{ tone: 'bad', text: t.account + ': ' + t.unreadable }];
    if (permissions.writeDac && permissions.writeOwner) return [{ tone: 'good', text: t.account + ': ' + t.accountOk }];
    var missing = [];
    if (permissions.writeDac === false) missing.push(t.rightsDac);
    if (permissions.writeOwner === false) missing.push(t.rightsOwner);
    return [{ tone: 'bad', text: t.account + ': ' + t.accountMissing + missing.join(' / ') }];
  }

  /** @returns {Array<{tone: string, text: string}>} sandbox-grant tag. */
  function grantFlag(entry, t) {
    if (entry !== null && typeof entry === 'object' && entry.tempInside === true) {
      return [{ tone: 'warn', text: t.grant + ': ' + t.temp }];
    }
    var permissions = permissionBlock(entry);
    if (permissions === undefined) return [{ tone: 'bad', text: t.grant + ': ' + t.unreadable }];
    if (permissions.rootGrant === true) return [{ tone: 'good', text: t.grant + ': ' + t.grantOk }];
    return [{ tone: 'bad', text: t.grant + ': ' + t.grantMissing }];
  }

  /** @returns {Array<{tone: string, text: string}>} subfolder inheritance tag. */
  function childrenFlag(entry, t) {
    if (entry !== null && typeof entry === 'object' && entry.tempInside === true) return [];
    var permissions = permissionBlock(entry);
    if (permissions === undefined) return [{ tone: 'bad', text: t.children + ': ' + t.unreadable }];
    var total = permissions.childDirs || 0;
    var done = permissions.childDirsWithGrant || 0;
    if (total === 0) return [{ tone: 'good', text: t.children + ': ' + t.noChildren }];
    var values = { done: done, total: total };
    return [{
      tone: done === total ? 'good' : 'warn',
      text: t.children + ': ' + fmt(done === total ? t.childrenOk : t.childrenPartial, values)
    }];
  }

  function flagsOf(entry, t) {
    return accountFlag(entry, t).concat(grantFlag(entry, t)).concat(childrenFlag(entry, t));
  }

  function flagNodes(React, flags, keyPrefix) {
    return flags.map(function (flag, index) {
      return React.createElement('span', {
        key: keyPrefix + '-' + index,
        className: 'dshft-flag',
        'data-tone': flag.tone
      }, flag.text);
    });
  }

  // ---- current workspace --------------------------------------------------

  /**
   * Resolve a session to its workspace directory through the client-side
   * `workspaces` service (the same store the sidebar tree reads). Set from
   * `apply`; undefined on a host without that service.
   * @type {((sessionId: string) => string|undefined)|undefined}
   */
  var resolveWorkspacePath;

  /**
   * The absolute directory of the workspace this composer belongs to.
   *
   * A `session`-scoped slot such as `conversation.input.right` is handed the
   * shell's standard props: `sessionId` plus the bound snapshot hooks. The
   * session *snapshot* has no `cwd`, so the directory comes from the list
   * summary (`useSessions(...).byId[id].cwd`, exactly what the shipped composer
   * reads) or, before that summary arrives, from the owning workspace row.
   * @param {object} props the slot's props.
   * @returns {string|undefined} absolute directory, or undefined when unknown.
   */
  function useCurrentCwd(props) {
    var sessionId = props !== undefined && props !== null && typeof props.sessionId === 'string'
      ? props.sessionId
      : undefined;
    var useSessions = props !== undefined && typeof props.useSessions === 'function' ? props.useSessions : undefined;
    var useWorkspaces = props !== undefined && typeof props.useWorkspaces === 'function' ? props.useWorkspaces : undefined;

    // Hook calls must not depend on `sessionId` appearing: a hook seat that
    // vanishes between renders reorders React's hook list. The guard lives in
    // the selector instead.
    var summaryCwd = useSessions === undefined
      ? undefined
      : useSessions(function (state) {
        if (sessionId === undefined) return undefined;
        var summary = state !== null && state !== undefined && state.byId !== undefined
          ? state.byId[sessionId]
          : undefined;
        return summary !== null && summary !== undefined && typeof summary.cwd === 'string'
          ? summary.cwd
          : undefined;
      });

    var workspacePath = useWorkspaces === undefined
      ? undefined
      : useWorkspaces(function (state) {
        if (sessionId === undefined) return undefined;
        var items = state !== null && state !== undefined && Array.isArray(state.items) ? state.items : [];
        for (var index = 0; index < items.length; index += 1) {
          var item = items[index];
          if (item !== null && typeof item === 'object' && Array.isArray(item.sessionIds)
            && item.sessionIds.indexOf(sessionId) !== -1 && typeof item.path === 'string') {
            return item.path;
          }
        }
        return undefined;
      });

    var candidates = [
      summaryCwd,
      workspacePath,
      props !== undefined && props !== null ? props.cwd : undefined,
      props !== undefined && props !== null ? props.workspacePath : undefined
    ];
    for (var index = 0; index < candidates.length; index += 1) {
      if (typeof candidates[index] === 'string' && candidates[index].length > 0) return candidates[index];
    }
    return undefined;
  }

  function normalizePath(path) {
    return typeof path === 'string' ? path.replaceAll('/', '\\').replace(/\\+$/, '').toLowerCase() : '';
  }

  /**
   * The report row owning a directory: exact match first, then the longest
   * registered ancestor, so a session that sits in a workspace subfolder still
   * resolves to its workspace.
   * @param {Array<object>} entries report rows.
   * @param {string|undefined} cwd the session's directory.
   * @returns {object|undefined}
   */
  function entryForCwd(entries, cwd) {
    var wanted = normalizePath(cwd);
    if (wanted.length === 0 || !Array.isArray(entries)) return undefined;
    var exact = entries.find(function (entry) {
      return entry !== null && typeof entry === 'object' && normalizePath(entry.path) === wanted;
    });
    if (exact !== undefined) return exact;
    var best;
    var bestLength = -1;
    entries.forEach(function (entry) {
      if (entry === null || typeof entry !== 'object') return;
      var candidate = normalizePath(entry.path);
      if (candidate.length === 0 || candidate.length <= bestLength) return;
      if (wanted === candidate || wanted.indexOf(candidate + '\\') === 0) {
        best = entry;
        bestLength = candidate.length;
      }
    });
    return best;
  }

  /**
   * The report row that claims this session: the workspace registry filters
   * `sessionIds` by the live canonical-cwd index, so membership is authoritative.
   * @param {Array<object>} entries report rows.
   * @param {string|undefined} sessionId the slot's session id.
   * @returns {object|undefined}
   */
  function entryForSession(entries, sessionId) {
    if (typeof sessionId !== 'string' || sessionId.length === 0 || !Array.isArray(entries)) return undefined;
    return entries.find(function (entry) {
      return entry !== null && typeof entry === 'object'
        && Array.isArray(entry.sessionIds)
        && entry.sessionIds.indexOf(sessionId) !== -1;
    });
  }

  // ---- composer: permission check -----------------------------------------
  /**
   * Report the props this slot actually receives once, so a host that renders
   * the slot differently can be diagnosed from `GET /folder-trust/debug`.
   * @param {object} props slot props.
   */
  function reportProbe(props) {
    try {
      var keys = props !== undefined && props !== null ? Object.keys(props) : [];
      fetch(ROUTE_DEBUG, {
        method: 'POST',
        cache: 'no-store',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          source: 'conversation.input.right',
          keys: keys,
          sessionId: props !== undefined && props !== null && typeof props.sessionId === 'string' ? props.sessionId : null
        })
      }).catch(function () { /* diagnostics only */ });
    } catch (error) {
      // diagnostics must never break the chip
    }
  }

  function WorkspacePermissionCheck(props) {
    var React = window.__DSH_FOLDER_TRUST_REACT__;
    var t = text();
    var cwd = useCurrentCwd(props);
    var dataState = React.useState(null);
    var data = dataState[0];
    var setData = dataState[1];
    var openState = React.useState(false);
    var open = openState[0];
    var setOpen = openState[1];
    var busyState = React.useState(false);
    var busy = busyState[0];
    var setBusy = busyState[1];
    var errorState = React.useState(null);
    var errorText = errorState[0];
    var setError = errorState[1];
    var runState = React.useState(null);
    var run = runState[0];
    var setRun = runState[1];
    var runner = useRepairRun(React);
    var logsState = React.useState({});
    var logs = logsState[0];
    var setLogs = logsState[1];
    var progressState = React.useState({});
    var progress = progressState[0];
    var setProgress = progressState[1];

    var refresh = React.useCallback(function () {
      return fetchReport().then(function (body) {
        setData(Array.isArray(body.workspaces) ? body.workspaces : []);
        setError(null);
      }).catch(function () { /* the harness may be restarting */ });
    }, []);

    React.useEffect(function () {
      insertStyle();
      reportProbe(props);
      refresh();
      var timer = setInterval(refresh, CHECK_POLL_MS);
      return function () { clearInterval(timer); };
    }, []);

    var sessionId = props !== undefined && props !== null && typeof props.sessionId === 'string'
      ? props.sessionId
      : undefined;
    var cwd = useCurrentCwd(props);
    if (cwd === undefined && sessionId !== undefined && resolveWorkspacePath !== undefined) {
      cwd = resolveWorkspacePath(sessionId);
    }
    var entry = entryForSession(data, sessionId) || entryForCwd(data, cwd);
    if (entry === undefined || !needsRepair(entry)) return null;

    function repair() {
      if (busy) return;
      setBusy(true);
      setError(null);
      runner.start(entry.path, function (outcome) {
        setBusy(false);
        if (outcome.body && outcome.body.ok === true) {
          refresh();
          return;
        }
        setError((outcome.body && outcome.body.message) || t.checkRepairFailed);
        refresh();
      });
    }

    var chip = React.createElement('button', {
      type: 'button',
      className: 'dshft-check',
      title: t.checkChipHint,
      'aria-label': t.checkChipHint,
      onClick: function () { setOpen(true); }
    }, t.checkChip);

    if (!open) return chip;

    return React.createElement('span', { style: { display: 'inline-flex' } },
      chip,
      React.createElement('div', { className: 'dshft-backdrop', role: 'presentation' },
        React.createElement('div', {
          className: 'dshft-card',
          role: 'dialog',
          'aria-modal': 'true',
          'aria-label': t.checkTitle
        },
        React.createElement('div', { className: 'dshft-title' }, t.checkTitle),
        React.createElement('p', { className: 'dshft-path' }, entry.path),
        React.createElement('p', { className: 'dshft-body' }, t.checkIntro),
        React.createElement('div', { className: 'dshft-wsline' }, flagNodes(React, flagsOf(entry, t), 'cur')),
        renderRunLog(React, runner.runs[entry.path]),
        errorText === null ? null : React.createElement('p', { className: 'dshft-error' }, errorText),
        React.createElement('div', { className: 'dshft-actions' },
          needsRepair(entry)
            ? React.createElement('button', {
              type: 'button',
              className: 'dshft-btn dshft-primary',
              disabled: busy,
              onClick: repair
            }, busy ? t.checkRepairing : t.checkRepair)
            : React.createElement('p', { className: 'dshft-ignore' }, t.checkReady),
          React.createElement('button', {
            type: 'button',
            className: 'dshft-btn dshft-secondary',
            onClick: function () { setOpen(false); }
          }, t.checkClose)
        ))
      ));
  }

  // ---- settings: every workspace ------------------------------------------

  function WorkspacePermissionsSettings() {
    var React = window.__DSH_FOLDER_TRUST_REACT__;
    var t = text();
    var dataState = React.useState(null);
    var data = dataState[0];
    var setData = dataState[1];
    var loadingState = React.useState(true);
    var loading = loadingState[0];
    var setLoading = loadingState[1];
    var busyState = React.useState(null);
    var busy = busyState[0];
    var setBusy = busyState[1];
    var errorState = React.useState(null);
    var errorText = errorState[0];
    var setError = errorState[1];
    var runState = React.useState(null);
    var run = runState[0];
    var setRun = runState[1];
    var runner = useRepairRun(React);
    var logsState = React.useState({});
    var logs = logsState[0];
    var setLogs = logsState[1];
    var progressState = React.useState({});
    var progress = progressState[0];
    var setProgress = progressState[1];

    var refresh = React.useCallback(function () {
      insertStyle();
      setLoading(true);
      return fetchReport().then(function (body) {
        setData(Array.isArray(body.workspaces) ? body.workspaces : []);
        setError(null);
      }).catch(function (caught) {
        setError(String(caught && caught.message ? caught.message : caught));
      }).then(function () { setLoading(false); });
    }, []);

    React.useEffect(function () { refresh(); }, []);

    function repair(entry) {
      if (busy !== null) return;
      setBusy(entry.path);
      setError(null);
      runner.start(entry.path, function (outcome) {
        setBusy(null);
        if (outcome.body && outcome.body.ok === true) {
          refresh();
          return;
        }
        setError((outcome.body && outcome.body.message) || t.repairFailed);
        refresh();
      });
    }

    var entries = Array.isArray(data) ? data : [];
    var cards = entries.map(function (entry) {
      var flags = flagsOf(entry, t);
      return React.createElement('div', { className: 'dshft-card2', key: entry.path },
        React.createElement('div', { className: 'dshft-card2Head' },
          React.createElement('p', { className: 'dshft-card2Title' }, entry.title || entry.path),
          needsRepair(entry)
            ? React.createElement('button', {
              type: 'button',
              className: 'dshft-btn2',
              disabled: busy !== null,
              onClick: function () { repair(entry); }
            }, busy === entry.path ? t.repairing : t.repair)
            : React.createElement('span', { className: 'dshft-flag', 'data-tone': 'good' }, t.ready)
        ),
        React.createElement('p', { className: 'dshft-card2Path' }, entry.path),
        React.createElement('div', { className: 'dshft-flags' }, flagNodes(React, flags, entry.path + '-flag')),
        renderRunLog(React, runner.runs[entry.path])
      );
    });

    var body;
    if (loading && data === null) {
      body = React.createElement('p', { className: 'dshft-empty' }, t.settingsLoading);
    } else if (entries.length === 0) {
      body = React.createElement('p', { className: 'dshft-empty' }, t.settingsEmpty);
    } else {
      body = cards;
    }

    return React.createElement('div', { className: 'dshft-setRoot' },
      React.createElement('div', { className: 'dshft-setScroll' },
        React.createElement('div', { className: 'dshft-setInner' },
          React.createElement('div', { className: 'dshft-setHead' },
            React.createElement('h2', { className: 'dshft-setTitle' }, t.settingsTitle),
            React.createElement('button', {
              type: 'button',
              className: 'dshft-btn2',
              disabled: loading,
              onClick: refresh
            }, loading ? t.settingsRefreshing : t.settingsRefresh),
            React.createElement('p', { className: 'dshft-setSubtitle' }, t.settingsSubtitle)
          ),
          errorText === null ? null : React.createElement('p', { className: 'dshft-setError' }, errorText),
          body
        )
      )
    );
  }

  function fetchReport() {
    return fetch(ROUTE_REPORT, { cache: 'no-store', credentials: 'same-origin' }).then(function (response) {
      if (!response.ok) throw new Error('HTTP ' + response.status);
      return response.json();
    });
  }

  /**
   * Run one repair. The host answers in NDJSON (a stream): `{"kind":"line"}`
   * frames are progress, and the last `{"kind":"done"}` frame is the result.
   * `response.json()` cannot parse that stream, so the frames are split here.
   * @param {string} path workspace path.
   * @param {(event: object) => void} [onEvent] per-frame sink.
   * @returns {Promise<{ status: number, body: object }>}
   */
  /**
   * Run one repair over the streaming route.
   * @param {string} path workspace path.
   * @param {(event: object) => void} [onEvent] per-frame sink.
   * @returns {Promise<{ status: number, body: object }>}
   */
  function postRepair(path, onEvent) {
    return postStream(ROUTE_REPAIR, path, onEvent);
  }
  if (typeof window !== 'undefined' && window.__ModuleLoader__ && typeof window.__ModuleLoader__.load === 'function') {
    window.__ModuleLoader__.load({
      id: PLUGIN_ID,
      factory: function (require) {
        window.__DSH_FOLDER_TRUST_REACT__ = require('react');
        return {
          inject: ['slots'],
          /**
           * Client plugin body: the trust prompt, the per-workspace permission
           * check in the composer, and the settings page listing every workspace.
           * @param {object} ctx the plugin's client cordis context.
           */
          apply: function (ctx) {
            // The sidebar's workspace store already indexes sessions by canonical
            // cwd, so the composer chip can name its workspace without asking the
            // host. Missing service simply leaves the chip hidden.
            try {
              var workspaces = typeof ctx.get === 'function' ? ctx.get('workspaces') : undefined;
              var list = workspaces !== undefined && workspaces !== null ? workspaces.list : undefined;
              if (list !== undefined && typeof list.getSnapshot === 'function') {
                resolveWorkspacePath = function (sessionId) {
                  try {
                    var snapshot = list.getSnapshot();
                    var items = snapshot !== null && snapshot !== undefined && Array.isArray(snapshot.items)
                      ? snapshot.items
                      : [];
                    for (var index = 0; index < items.length; index += 1) {
                      var item = items[index];
                      if (item === null || typeof item !== 'object' || !Array.isArray(item.sessionIds)) continue;
                      if (item.sessionIds.indexOf(sessionId) === -1) continue;
                      var path = typeof item.path === 'string' ? item.path : item.cwd;
                      if (typeof path === 'string' && path.length > 0) return path;
                    }
                  } catch (error) {
                    // a failing store must not break the chip
                  }
                  return undefined;
                };
              }
            } catch (error) {
              // no workspaces service on this host
            }

            ctx.slots.inject('shell.overlay', function () {
              return ctx.slots.register({
                name: 'shell.overlay',
                id: 'folder-trust',
                order: 95
              }, FolderTrustDialog);
            });
            // A session-scoped list slot. The shell hands session-scoped
            // components `sessionId` plus the snapshot hooks as standard props,
            // so this entry declares no `inject`: injecting `sessionId` again
            // would collide with the standard seat that already provides it.
            ctx.slots.inject('conversation.input.right', function () {
              return ctx.slots.register({
                name: 'conversation.input.right',
                id: 'folder-trust-check',
                order: 12
              }, WorkspacePermissionCheck);
            });
            ctx.slots.inject('settings.section', function () {
              return ctx.slots.register({
                name: 'settings.section',
                id: 'folder-trust-permissions',
                order: 85,
                label: function () { return text().settingsNav; }
              }, WorkspacePermissionsSettings);
            });
          }
        };
      }
    });
  }
})();
