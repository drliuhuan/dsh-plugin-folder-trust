// Pure permission-state helpers for the folder-trust plugin.
//
// Both browser surfaces (the composer's permission-check button and the Settings
// page) must agree on what "this workspace needs repair" means, so that rule
// lives here instead of being duplicated in client code. Nothing in this module
// touches the filesystem, `window`, or React: the host-side `lib/service.mjs`
// and the browser bundle can both import it.

/**
 * Normalize a Windows path for comparison, matching `service.mjs`'s set keys.
 * @param {unknown} path any value the registry or the browser may hand over.
 * @returns {string} lowercase, backslash-separated, no trailing separator.
 */
export function normalizePath(path) {
  return typeof path === 'string'
    ? path.replaceAll('/', '\\').replace(/\\+$/, '').toLowerCase()
    : '';
}

/**
 * Read the facts the report carries for one workspace, without interpreting them.
 * @param {object} entry one row of the host's workspace report.
 * @returns {{readable: boolean, tempInside: boolean, writeDac: boolean, writeOwner: boolean,
 *   rootGrant: boolean, childDirs: number, childDirsWithGrant: number}}
 */
export function permissionFacts(entry) {
  const permissions = entry !== null && typeof entry === 'object' ? entry.permissions : undefined;
  const readable = permissions !== null
    && typeof permissions === 'object'
    && permissions.ok === true;
  return {
    readable,
    tempInside: entry?.tempInside === true,
    writeDac: readable && permissions.writeDac === true,
    writeOwner: readable && permissions.writeOwner === true,
    rootGrant: readable && permissions.rootGrant === true,
    childDirs: readable && Number.isFinite(permissions.childDirs) ? permissions.childDirs : 0,
    childDirsWithGrant: readable && Number.isFinite(permissions.childDirsWithGrant)
      ? permissions.childDirsWithGrant
      : 0
  };
}

/**
 * Every distinct reason this workspace cannot be used for workspace-write work.
 *
 * The order is the order the browser shows them in: a structural refusal first,
 * then the account rights, then the sandbox grant, then its reach into the
 * subfolders that already existed.
 * @param {object} entry one row of the host's workspace report.
 * @returns {string[]} stable codes; `[]` means the workspace is usable.
 */
export function issueCodes(entry) {
  const facts = permissionFacts(entry);
  if (facts.tempInside) return ['temp'];
  if (!facts.readable) return ['unreadable'];
  const codes = [];
  if (!facts.writeDac) codes.push('writeDac');
  if (!facts.writeOwner) codes.push('writeOwner');
  if (!facts.rootGrant) codes.push('rootGrant');
  if (facts.childDirs > facts.childDirsWithGrant) codes.push('children');
  return codes;
}

/**
 * Whether this workspace should offer a repair action.
 * @param {object} entry one row of the host's workspace report.
 * @returns {boolean}
 */
export function entryNeedsRepair(entry) {
  const codes = issueCodes(entry);
  if (codes.length === 0) return false;
  // A workspace that structurally contains the temp root is never repairable.
  return codes[0] !== 'temp';
}

/**
 * Find the report row for one workspace path.
 * @param {Array<object>} entries the report's `workspaces` array.
 * @param {unknown} path the path to look for.
 * @returns {object|undefined}
 */
export function findWorkspace(entries, path) {
  const wanted = normalizePath(path);
  if (wanted.length === 0 || !Array.isArray(entries)) return undefined;
  return entries.find((entry) => entry !== null && typeof entry === 'object'
    && normalizePath(entry.path) === wanted);
}
