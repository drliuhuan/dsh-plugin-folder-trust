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
 *   rootGrant: boolean, lowLabel: string, childDirs: number, childDirsWithGrant: number}}
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
    // 'low' | 'other' | 'none' | 'unknown'. Only a host that reports it can tell
    // the label apart from a grant; an older host leaves this 'unknown'.
    lowLabel: readable && typeof permissions.lowLabel === 'string' ? permissions.lowLabel : 'unknown',
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
  // The sandbox's write token is a Low-integrity, write-restricted one: without the
  // Low no-write-up label the capability grant is inert and every write is denied,
  // even though `rootGrant` says the ACE is there. DSH itself treats a folder as
  // provisioned only when grant + deny + label all hold.
  if (facts.lowLabel === 'none' || facts.lowLabel === 'other') codes.push('label');
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
 * Whether repairing this workspace needs the user to approve a UAC elevation.
 *
 * Adding a DACL entry needs effective WRITE_DAC. The owner has that right
 * implicitly, so an owner that IS the signed-in account never needs help; every
 * other owner (another machine's SID, SYSTEM, builtin) can only be rewritten by
 * an account whose Administrators group is enabled — which Windows only grants
 * through the UAC prompt.
 * @param {object} permissions the `permissions` block of a report row.
 * @returns {boolean}
 */
export function ownerNeedsElevation(permissions) {
  if (permissions === null || typeof permissions !== 'object' || permissions.ok !== true) return false;
  if (permissions.writeDac === true) return false;
  return permissions.ownerKind !== 'current';
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
