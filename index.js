// dsh-plugin-folder-trust — host plugin entry.
//
// Watches the persistent workspace registry, and when a folder is added after
// startup it checks whether the harness could provision its own workspace-write
// grant there (WRITE_DAC + WRITE_OWNER on the folder). Folders that would fail
// are served to the browser modal as pending trust requests; clicking trust
// repairs the folder's NTFS permissions for the signed-in user and verifies the
// result. Nothing is modified before that click.
//
// The row name must stay the bare package name: DSH's client-module scanner uses
// it to discover the package's `dsh.client` bundle (client.js).

import { FolderTrustService } from './lib/service.mjs';
import { createHandlers, routeRows } from './lib/routes.mjs';

export const name = 'folder-trust';
export const inject = ['webServer'];

/**
 * Resolve the workspace registry through either access path a Cordis row can
 * have: the injected property or an explicit `ctx.get` lookup.
 * @param {object} ctx plugin context.
 * @returns {object|undefined}
 */
function resolveRegistry(ctx) {
  try {
    if (ctx.workspaceRegistry !== undefined) return ctx.workspaceRegistry;
  } catch {
    // fall through to ctx.get
  }
  try {
    if (typeof ctx.get === 'function') return ctx.get('workspaceRegistry');
  } catch {
    // no registry available
  }
  return undefined;
}

/**
 * Cordis plugin body: own the trust service and its routes.
 * @param {object} ctx plugin context.
 */
export function apply(ctx) {
  const service = new FolderTrustService({
    listWorkspaces: () => {
      const registry = resolveRegistry(ctx);
      return typeof registry?.list === 'function' ? registry.list() : [];
    },
    logger: ctx.logger
  });

  ctx.inject(['workspaceRegistry'], () => {
    service.start();
  });

  const handlers = createHandlers(service, { logger: ctx.logger });
  const rows = routeRows(handlers);
  ctx.inject(['webServer'], (scope) => {
    const disposers = rows.map((row) => scope.webServer.register(row));
    ctx.effect(() => () => {
      for (const dispose of disposers) {
        try {
          dispose?.();
        } catch {
          // a route disposer failing must not abort teardown
        }
      }
    }, 'folder-trust: routes');
  });

  ctx.effect(() => () => service.stop(), 'folder-trust: poll timer');
}

export { FolderTrustService };
