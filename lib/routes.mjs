// HTTP surface of the folder-trust plugin.
//
// Three same-origin routes serve the browser modal:
//   GET  /folder-trust/state    -> { pending: [...] }
//   POST /folder-trust/trust    -> repair one pending folder, report the outcome
//   POST /folder-trust/dismiss  -> record a refusal, never touch the folder
//
// Only paths that are currently pending may be acted on: the browser cannot ask
// the host to rewrite the permissions of an arbitrary directory.

import { Buffer } from 'node:buffer';

const MAX_BODY_BYTES = 8 * 1024;
const ROUTES = Object.freeze({
  state: '/folder-trust/state',
  debug: '/folder-trust/debug',
  report: '/folder-trust/report',
  repair: '/folder-trust/repair',
  trust: '/folder-trust/trust',
  dismiss: '/folder-trust/dismiss'
});

function jsonHeaders(extra = {}) {
  return {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...extra
  };
}

function sendJson(req, res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, jsonHeaders({ 'content-length': Buffer.byteLength(body) }));
  if (req.method === 'HEAD') {
    res.end();
    return;
  }
  res.end(body);
}

function sendError(req, res, status, message) {
  sendJson(req, res, status, { ok: false, error: message });
}

/** Missing or opaque Origin is treated as a same-origin caller, like the rest of the harness. */
function sameOrigin(req) {
  const origin = req.headers?.origin;
  if (typeof origin !== 'string' || origin.length === 0 || origin === 'null') return true;
  try {
    return new URL(origin).host.toLowerCase() === String(req.headers.host ?? '').toLowerCase();
  } catch {
    return false;
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    const onData = (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        settled = true;
        req.off('data', onData);
        req.resume();
        reject(Object.assign(new Error('request body is too large'), { status: 413 }));
        return;
      }
      chunks.push(chunk);
    };
    req.on('data', onData);
    req.on('end', () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks).toString('utf8'));
    });
    req.on('error', (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    });
  });
}

async function readJsonBody(req) {
  const text = await readBody(req);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw Object.assign(new Error('request body is not valid JSON'), { status: 400 });
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw Object.assign(new Error('request body must be a JSON object'), { status: 400 });
  }
  return parsed;
}

/**
 * Build the route handlers over one trust service.
 * @param {import('./service.mjs').FolderTrustService} service
 * @param {{ logger?: { warn?: Function } }} [options]
 * @returns {{ state: Function, trust: Function, dismiss: Function }}
 */
export function createHandlers(service, options = {}) {
  const logger = options.logger;

  function guardPost(req, res) {
    if (req.method !== 'POST') {
      sendError(req, res, 405, 'use POST');
      return false;
    }
    if (!sameOrigin(req)) {
      sendError(req, res, 403, 'cross-origin requests are not allowed');
      return false;
    }
    const contentType = String(req.headers['content-type'] ?? '').toLowerCase();
    if (!contentType.startsWith('application/json')) {
      sendError(req, res, 415, 'send application/json');
      return false;
    }
    return true;
  }

  function state(req, res) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      sendError(req, res, 405, 'use GET');
      return;
    }
    try {
      sendJson(req, res, 200, service.snapshot());
    } catch (error) {
      logger?.warn?.(`folder-trust: state route failed: ${String(error?.message ?? error)}`);
      sendError(req, res, 500, 'could not read the folder trust state');
    }
  }

  /** Last thing the browser reported about itself, for diagnostics only. */
  let clientProbe;

  /** Diagnostics for the host half: is the poll running, and what does it see? */
  function debug(req, res) {
    if (req.method === 'POST') {
      // The client posts the props its slot received once per mount, so a host
      // that renders the slot differently can be diagnosed without a debugger.
      if (!guardPost(req, res)) return;
      readJsonBody(req).then((body) => {
        clientProbe = { at: new Date().toISOString(), body };
        sendJson(req, res, 200, { ok: true });
      }).catch((error) => {
        sendError(req, res, error?.status ?? 400, error?.message ?? 'could not read the client probe');
      });
      return;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      sendError(req, res, 405, 'use GET');
      return;
    }
    try {
      sendJson(req, res, 200, { ...service.debugInfo(), clientProbe });

    } catch (error) {
      logger?.warn?.(`folder-trust: debug route failed: ${String(error?.message ?? error)}`);
      sendError(req, res, 500, 'could not read the folder trust diagnostics');
    }
  }

  /** Per-workspace permission report for the permissions dialog. */
  async function report(req, res) {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      sendError(req, res, 405, 'use GET');
      return;
    }
    try {
      sendJson(req, res, 200, await service.report(true));
    } catch (error) {
      logger?.warn?.(`folder-trust: report route failed: ${String(error?.message ?? error)}`);
      sendError(req, res, 500, 'could not read the workspace permission report');
    }
  }

  /**
   * Repair one registered workspace and stream what it is doing as NDJSON:
   * `{"kind":"line","line":...}`, `{"kind":"progress","progress":0-100}` and a
   * final `{"kind":"done","ok":...,"entry":...}`. The browser renders the lines
   * and the bar while the repair runs.
   */
  async function repair(req, res) {
    if (!guardPost(req, res)) return;
    let body;
    try {
      body = await readJsonBody(req);
    } catch (error) {
      sendError(req, res, error?.status ?? 400, error?.message ?? 'invalid body');
      return;
    }
    const path = typeof body.path === 'string' ? body.path : '';
    if (path.length === 0) {
      sendError(req, res, 400, 'send the workspace path');
      return;
    }
    res.writeHead(200, {
      'content-type': 'application/x-ndjson; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff'
    });
    const send = (event) => {
      try {
        res.write(`${JSON.stringify(event)}\n`);
      } catch {
        // the browser went away; the repair finishes anyway
      }
    };
    const controller = new AbortController();
    res.on('close', () => { controller.abort(); });
    try {
      const outcome = await service.repairStream(path, send, controller.signal);
      send({ kind: 'done', ok: outcome.ok === true, message: outcome.message, entry: outcome.entry });
    } catch (error) {
      logger?.warn?.(`folder-trust: repair route failed: ${String(error?.message ?? error)}`);
      send({ kind: 'done', ok: false, message: String(error?.message ?? error) });
    }
    res.end();
  }

  function resolvePending(body) {
    const requested = typeof body.path === 'string' ? body.path : '';
    const normalized = requested.replaceAll('/', '\\').replace(/\\+$/, '').toLowerCase();
    return service.pending.get(normalized);
  }

  async function trust(req, res) {
    if (!guardPost(req, res)) return;
    try {
      const body = await readJsonBody(req);
      const entry = resolvePending(body);
      if (entry === undefined) {
        sendError(req, res, 404, 'this folder is not pending a trust decision');
        return;
      }
      sendJson(req, res, 200, await service.trust(entry.path));
    } catch (error) {
      logger?.warn?.(`folder-trust: trust route failed: ${String(error?.message ?? error)}`);
      sendError(req, res, error?.status ?? 500, error?.message ?? 'could not grant the folder');
    }
  }

  async function dismiss(req, res) {
    if (!guardPost(req, res)) return;
    try {
      const body = await readJsonBody(req);
      const entry = resolvePending(body);
      if (entry === undefined) {
        sendError(req, res, 404, 'this folder is not pending a trust decision');
        return;
      }
      sendJson(req, res, 200, service.dismiss(entry.path));
    } catch (error) {
      logger?.warn?.(`folder-trust: dismiss route failed: ${String(error?.message ?? error)}`);
      sendError(req, res, error?.status ?? 500, error?.message ?? 'could not record the refusal');
    }
  }

  return { state, debug, trust, dismiss, report, repair };
}

/**
 * `webServer.register()` rows for the plugin's three routes.
 * @param {ReturnType<typeof createHandlers>} handlers
 * @returns {Array<{ kind: 'exact', path: string, handler: Function }>}
 */
export function routeRows(handlers) {
  return [
    { kind: 'exact', path: ROUTES.state, handler: handlers.state },
    { kind: 'exact', path: ROUTES.debug, handler: handlers.debug },
    { kind: 'exact', path: ROUTES.report, handler: handlers.report },
    { kind: 'exact', path: ROUTES.repair, handler: handlers.repair },
    { kind: 'exact', path: ROUTES.trust, handler: handlers.trust },
    { kind: 'exact', path: ROUTES.dismiss, handler: handlers.dismiss }
  ];
}

export { ROUTES };




