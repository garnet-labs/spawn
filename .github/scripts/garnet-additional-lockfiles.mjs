// Policy-v2 trusted-host planner. All package-manager/source execution remains
// inside the recorder's nonroot, credential-isolated workload containers.
import path from 'node:path';

const assert = (ok, message) => { if (!ok) throw new Error(message); };
const quote = value => `'${String(value).replaceAll("'", "'\\''")}'`;
const join = (dir, file) => dir === '.' ? file : `${dir}/${file}`;
const POETRY = '2.2.1';
const YARN_FALLBACKS = Object.freeze({'4': '2.4.3', '6': '3.8.7', '8': '4.9.2'});

function parents(directory) {
  const result = [];
  for (;;) {
    result.push(directory);
    if (directory === '.') return result;
    directory = path.posix.dirname(directory);
  }
}

function yarnSpec(value) {
  if (value === undefined) return null;
  assert(typeof value === 'string', 'BLOCKED: invalid Yarn packageManager');
  const match = /^yarn@(\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?)(?:\+sha(?:224|256|384|512)\.[a-f0-9]+)?$/.exec(value);
  assert(match, 'BLOCKED: Yarn packageManager must pin a numeric version');
  const major = Number(match[1].split('.')[0]);
  assert(major >= 1 && major <= 4, 'BLOCKED: unreviewed Yarn major version');
  return {version: match[1], major, reference: value};
}

// Bounded workspace globs; unsupported syntax fails instead of silently
// selecting an unrelated ancestor install.
function workspaceMatch(pattern, directory) {
  assert(typeof pattern === 'string' && pattern.length <= 256 &&
    !pattern.startsWith('/') && !pattern.includes('\\') &&
    !/[\x00-\x1f\x7f{}()[\]]/.test(pattern) &&
    !pattern.split('/').includes('..'), 'BLOCKED: unsupported Yarn workspace pattern');
  let regex = '^';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '*' && pattern[i + 1] === '*') { regex += '.*'; i++; }
    else if (c === '*') regex += '[^/]*';
    else if (c === '?') regex += '[^/]';
    else regex += c.replace(/[.+^$|]/g, '\\$&');
  }
  return new RegExp(`${regex}/?$`).test(directory);
}

function belongsToWorkspace(pkg, root, directory) {
  const patterns = Array.isArray(pkg.workspaces) ? pkg.workspaces : pkg.workspaces?.packages;
  if (!Array.isArray(patterns)) return false;
  const relative = path.posix.relative(root, directory);
  assert(!relative.startsWith('../'), 'BLOCKED: workspace directory escaped root');
  const include = patterns.filter(p => typeof p === 'string' && !p.startsWith('!'));
  const exclude = patterns.filter(p => typeof p === 'string' && p.startsWith('!')).map(p => p.slice(1));
  return include.some(p => workspaceMatch(p, relative)) && !exclude.some(p => workspaceMatch(p, relative));
}

// Evidence of final unchanged bytes, not a claim to detect transient
// change-and-restore by hostile hooks; package-manager stale-lock checks remain.
const lockBefore = file =>
  `garnet_lock_before=$(/usr/bin/sha256sum ${quote(file)}); readonly garnet_lock_before`;
const lockAfter = "printf '%s\\n' \"$garnet_lock_before\" | /usr/bin/sha256sum --check --status";

/**
 * Additional workload plan, or null to delegate to npm/pnpm/uv/pip/Go/Cargo/Ruby.
 * All reads MUST use the recorder's symlink-safe readSource function.
 */
export function planAdditionalLockfile({root, file, kind, read}) {
  assert(typeof read === 'function', 'Missing trusted source reader');
  const text = (directory, name) => read(root, join(directory, name), true);
  const nearest = (directory, name) => parents(directory).find(p => text(p, name) !== null);
  const pkgAt = directory => JSON.parse(read(root, join(directory, 'package.json')));
  const fileDir = path.posix.dirname(file);
  const noCompetingNodeLocks = directory => {
    assert(['pnpm-lock.yaml', 'package-lock.json', 'npm-shrinkwrap.json']
      .every(name => text(directory, name) === null),
    'BLOCKED: competing Node lockfiles require reviewed upstream-workflow manager selection; no automatic override');
  };

  if (kind === 'node') {
    const packageDir = nearest(fileDir, 'package.json');
    if (packageDir === undefined) return null;
    const localPkg = pkgAt(packageDir);
    const localSpec = localPkg.packageManager;
    const ownLock = text(packageDir, 'yarn.lock') !== null;
    // Even packageManager is insufficient to waive mixed-lock ambiguity here.
    // An upstream workflow must be reviewed and a separately trusted policy
    // added before such a repo (e.g. mixed npm/Yarn extension) can run.
    if (ownLock) noCompetingNodeLocks(packageDir);
    if (localSpec !== undefined && !String(localSpec).startsWith('yarn@')) {
      assert(!ownLock, 'BLOCKED: Yarn lock conflicts with declared packageManager');
      return null;
    }
    const explicitYarn = localSpec !== undefined;
    const fixture = packageDir.split('/').some(p => /^(?:\.?fixtures|__fixtures__)$/.test(p));
    if (fixture && !explicitYarn && !ownLock) return null;
    const directory = ownLock ? packageDir : nearest(packageDir, 'yarn.lock');
    if (directory === undefined) {
      assert(!explicitYarn, 'BLOCKED: Yarn requires an existing lockfile');
      return null;
    }
    const pkg = pkgAt(directory);
    if (directory !== packageDir && !belongsToWorkspace(pkg, directory, packageDir)) {
      assert(!explicitYarn, 'BLOCKED: Yarn package is not in its ancestor lockfile workspace');
      return null;
    }
    noCompetingNodeLocks(directory);
    assert(path.posix.basename(file) === 'package.json' ||
      (path.posix.basename(file) === 'yarn.lock' && fileDir === directory),
    'BLOCKED: changed lockfile does not belong to the selected Yarn project');
    const spec = yarnSpec(pkg.packageManager);
    if (explicitYarn && directory !== packageDir) {
      const nestedSpec = yarnSpec(localSpec);
      assert(spec && spec.reference === nestedSpec.reference,
        'BLOCKED: conflicting Yarn workspace packageManager versions or integrity');
    }
    const lock = read(root, join(directory, 'yarn.lock'));
    const modern = /(?:^|\n)__metadata:\s*(?:\r?\n|$)/.test(lock);
    const classic = /(?:^|\n)# yarn lockfile v1(?:\r?\n|$)/.test(lock);
    assert(modern !== classic, 'BLOCKED: unknown or ambiguous Yarn lockfile format');
    const metadata = modern ? /(?:^|\n)__metadata:\s*\r?\n((?:[ \t]+[^\n]*\n?)*)/.exec(lock)?.[1] : '';
    const lockVersion = modern ? /^\s+version:\s*["']?(\d+)["']?\s*$/m.exec(metadata || '')?.[1] : '1';
    const version = spec?.version ?? (classic ? '1.22.22' : YARN_FALLBACKS[lockVersion]);
    assert(version, 'BLOCKED: unknown modern Yarn lock version requires packageManager');
    const major = Number(version.split('.')[0]);
    assert((major === 1 && classic) || (major >= 2 && modern), 'BLOCKED: Yarn version/lockfile format mismatch');
    const fallback = spec ? 'packageManager respected' :
      `explicit fallback yarn@${version} from ${classic ? 'classic v1 lock' : `modern metadata version ${lockVersion}`}`;
    return {
      directory, locked: true,
      commands: [
        lockBefore('yarn.lock'),
        // Export (not command-local) so bare `yarn` in lifecycle subprocesses
        // uses the same selected global Corepack release and ignores yarnPath.
        'export COREPACK_ENABLE_PROJECT_SPEC=0 COREPACK_DEFAULT_TO_LATEST=0 YARN_IGNORE_PATH=1',
        `corepack install --global ${quote(spec?.reference ?? `yarn@${version}`)}`,
        'mkdir -p /home/workload/.local/bin',
        'corepack enable --install-directory /home/workload/.local/bin yarn',
        major === 1
          ? 'corepack yarn install --frozen-lockfile --non-interactive --production=false'
          : 'corepack yarn install --immutable',
        lockAfter,
      ],
      scope: 'yarn-locked-install-with-lifecycle-hooks-no-explicit-workspace-build',
      note: `${fallback}; writable Yarn shim; Corepack project reselection/latest lookup and yarnPath delegation disabled for install and inherited lifecycle environment; lifecycle/workspace hooks retained if configured; no separate workspace build; final lock bytes checked`,
    };
  }

  if (kind === 'python' && /^(pyproject\.toml|poetry\.lock|uv\.lock)$/.test(path.posix.basename(file))) {
    const directory = nearest(fileDir, 'pyproject.toml');
    if (directory === undefined || text(directory, 'poetry.lock') === null) return null;
    assert(text(directory, 'uv.lock') === null, 'BLOCKED: both uv.lock and poetry.lock require an explicit ecosystem policy');
    assert(path.posix.basename(file) === 'pyproject.toml' || fileDir === directory,
      'BLOCKED: changed Poetry lock is not at the selected project root');
    const lock = read(root, join(directory, 'poetry.lock'));
    const metadata = /(?:^|\n)\[metadata\]\s*\r?\n([\s\S]*?)(?=\n\[|$)/.exec(lock)?.[1] || '';
    const lockVersion = /^\s*lock-version\s*=\s*["'](\d+\.\d+)["']\s*$/m.exec(metadata)?.[1];
    assert(['1.1', '2.0', '2.1'].includes(lockVersion), 'BLOCKED: unreviewed Poetry lockfile format');
    const poetry = 'POETRY_NO_INTERACTION=1 POETRY_VIRTUALENVS_CREATE=true POETRY_VIRTUALENVS_IN_PROJECT=true poetry';
    return {
      directory, locked: true,
      commands: [
        lockBefore('poetry.lock'),
        `python -m pip install --user poetry==${POETRY}`,
        `${poetry} check --lock`,
        `${poetry} sync --no-root --no-directory --all-groups`,
        lockAfter,
      ],
      scope: 'poetry-locked-all-groups-no-root-or-directory-builds',
      note: `Poetry ${POETRY}, lock format ${lockVersion}; stale locks fail check; all groups including optional groups; root/directory dependencies excluded; extras not automatically enabled; final lock bytes checked`,
    };
  }
  return null;
}

// Reviewed Bun workspace and exact-pair Python image support.
// Pure bounded source-data inspection; no new imports or source execution.
const remainingAssert = (ok, message) => { if (!ok) throw new Error(`BLOCKED: ${message}`); };
const remainingJoin = (a, b) => a === '.' ? b : `${a}/${b}`;
const remainingParent = p => p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '.';
const remainingAncestors = p => {
  const out = [];
  for (;;) {
    out.push(p);
    if (p === '.') return out;
    p = remainingParent(p);
  }
};

export function reviewedImageTag(snapshot, kind, defaultTag) {
  if (kind !== 'python' || snapshot.repository !== 'garnet-labs/gradio-test' ||
      !snapshot.manifests.includes('test/requirements.txt')) return defaultTag;
  remainingAssert(snapshot.baseline_sha === '55041996db69b086ee2a5116ad3db40bced6b056' &&
    snapshot.head?.sha === '36f97efa0200792ebc2b1fea5f32f2cd28efc5eb' &&
    snapshot.manifests.length === 1,
  'Gradio Python 3.10 recipe is reviewed only for this exact source pair and workload');
  // CI test-python.yml explicitly passes python_version: "3.10".
  // Resolve this tag ONCE to linux/amd64 digest, then reuse/verify on both sides.
  return 'python:3.10-bookworm';
}

function remainingWorkspaceMatch(pattern, directory) {
  remainingAssert(typeof pattern === 'string' && pattern.length > 0 && pattern.length <= 512 &&
    !pattern.startsWith('/') && !pattern.includes('\\') &&
    !pattern.split('/').some(x => x === '..' || x === '.' || !x) &&
    /^[A-Za-z0-9_.*@/-]+$/.test(pattern), 'unsupported Bun workspace glob');
  const pieces = pattern.split('/');
  const target = directory.split('/');
  remainingAssert(pieces.length <= 30 && pieces.every(p => !p.includes('*') || ['*', '**'].includes(p)),
    'unsupported Bun workspace glob segment');
  const memo = new Map();
  const compute = (i, j) => {
    if (i === pieces.length) return j === target.length;
    if (pieces[i] === '**') return match(i + 1, j) || j < target.length && match(i, j + 1);
    if (j === target.length) return false;
    return (pieces[i] === '*' || pieces[i] === target[j]) && match(i + 1, j + 1);
  };
  const match = (i, j) => {
    const key = `${i}:${j}`;
    if (!memo.has(key)) memo.set(key, compute(i, j));
    return memo.get(key);
  };
  return match(0, 0);
}

function remainingMember(pkg, rootDirectory, member) {
  if (rootDirectory === member) return true;
  const patterns = Array.isArray(pkg.workspaces) ? pkg.workspaces : pkg.workspaces?.packages;
  if (!Array.isArray(patterns)) return false;
  const relative = rootDirectory === '.' ? member : member.slice(rootDirectory.length + 1);
  remainingAssert(patterns.length <= 100 && relative.split('/').length <= 30,
    'Bun workspace pattern bounds exceeded');
  const positives = [], negatives = [];
  for (const p of patterns) {
    remainingAssert(typeof p === 'string', 'invalid Bun workspace pattern');
    if (p.startsWith('!')) negatives.push(p.slice(1)); else positives.push(p);
  }
  return positives.some(p => remainingWorkspaceMatch(p, relative)) &&
    !negatives.some(p => remainingWorkspaceMatch(p, relative));
}

// Bun's current text lock uses JSON with trailing commas. Do not evaluate it
// or regex-rewrite commas embedded in package names/URLs. Unsupported comment
// syntax fails closed; this intentionally is not a generic Bun lock parser.
function remainingLockData(text) {
  let clean = '', string = false, escaped = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (string) {
      clean += c;
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === '"') string = false;
    } else if (c === '"') {
      string = true; clean += c;
    } else if (c === ',') {
      let next = i + 1;
      while (/\s/.test(text[next] || '') && next < text.length) next++;
      if (!['}', ']'].includes(text[next])) clean += c;
    } else clean += c;
  }
  let data;
  try { data = JSON.parse(clean); } catch { throw new Error('BLOCKED: unsupported Bun lock JSON data'); }
  remainingAssert(data?.lockfileVersion === 1 && data.workspaces &&
    typeof data.workspaces === 'object' && !Array.isArray(data.workspaces), 'unsupported Bun text lock schema');
  return data;
}

function remainingManifestLocked(lock, directory, pkg) {
  const data = lock.workspaces[directory];
  remainingAssert(data && typeof data === 'object', 'Bun lock is missing a selected workspace');
  for (const section of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    const canonical = object => {
      remainingAssert(object && typeof object === 'object' && !Array.isArray(object) &&
        Object.values(object).every(x => typeof x === 'string'), 'invalid Bun dependency specification');
      return JSON.stringify(Object.entries(object).sort(([a], [b]) => a.localeCompare(b)));
    };
    remainingAssert(canonical(pkg[section] || {}) === canonical(data[section] || {}),
      'stale Bun lock: selected workspace dependency specs differ from its immutable manifest; no dependency edits permitted');
  }
}

export function planBunLockfile({root, file, kind, read}) {
  if (kind !== 'node') return null;
  const original = remainingParent(file);
  const readAt = (dir, name) => read(root, remainingJoin(dir, name), true);
  const packageDir = remainingAncestors(original).find(dir => readAt(dir, 'package.json') !== null);
  if (packageDir === undefined) return null;
  const member = JSON.parse(readAt(packageDir, 'package.json'));
  const explicitBun = typeof member.packageManager === 'string' && member.packageManager.startsWith('bun@');
  let candidate;
  for (const dir of remainingAncestors(packageDir)) {
    const textLock = readAt(dir, 'bun.lock'), binaryLock = readAt(dir, 'bun.lockb');
    if (textLock === null && binaryLock === null) continue;
    const manifest = readAt(dir, 'package.json');
    remainingAssert(manifest !== null, 'Bun lockfile has no package manifest');
    const pkg = JSON.parse(manifest);
    if (!remainingMember(pkg, dir, packageDir)) continue;
    candidate = {dir, pkg, textLock, binaryLock};
    break;
  }
  if (!candidate) {
    remainingAssert(!explicitBun && !/\/?bun\.lockb?$/.test(file), 'Bun frozen install requires its owning lockfile');
    return null;
  }
  const {dir, pkg, textLock, binaryLock} = candidate;
  remainingAssert(binaryLock === null && textLock !== null, 'only reviewed Bun text locks are supported');
  const lockData = remainingLockData(textLock);
  // A nested competing manifest/lock must never cause an npm fallback after
  // ancestor selection. Cross-manager and mixed-lock cases require review.
  const chain = remainingAncestors(packageDir).slice(0, remainingAncestors(packageDir).indexOf(dir) + 1);
  for (const d of chain) {
    for (const lock of ['pnpm-lock.yaml', 'pnpm-workspace.yaml', 'yarn.lock', 'package-lock.json', 'npm-shrinkwrap.json']) {
      remainingAssert(readAt(d, lock) === null, 'competing Node managers on Bun workspace selection path');
    }
    const data = readAt(d, 'package.json');
    if (data !== null) {
      const manager = JSON.parse(data).packageManager;
      remainingAssert(manager === undefined || manager === 'bun@1.3.11',
        'Bun version/manager requires an explicitly reviewed numeric version');
    }
  }
  if (pkg.packageManager === undefined && member.packageManager === undefined) {
    // Source-backed fallback ONLY for the bounded 1.3.11 pin observed in this
    // repository's immutable CI, not a version inferred from @types/bun.
    const pin = read(root, '.github/workflows/agent-tarballs.yml', true) || '';
    const test = read(root, '.github/workflows/test.yml', true) || '';
    remainingAssert(/bun-version:\s*["']1\.3\.11["']/.test(pin) &&
      /uses:\s*oven-sh\/setup-bun@/.test(pin) && /run:\s*bun install\s*(?:\r?\n|$)/.test(test),
    'unversioned Bun project requires a reviewed CI version; no latest fallback');
  }
  remainingManifestLocked(lockData, '', pkg);
  remainingManifestLocked(lockData, dir === packageDir ? '' :
    dir === '.' ? packageDir : packageDir.slice(dir.length + 1), member);
  return {
    directory: dir, locked: true,
    scope: 'bun-locked-workspace-install-with-lifecycle-hooks-and-pinned-toolchain-bootstrap',
    commands: [
      // Bootstrap in /tmp, not the source directory: do not load project npm
      // config while acquiring the bounded runtime. Intended Bun/npm bootstrap
      // lifecycle is retained, and no credentials are forwarded by the wrapper.
      "(cd /tmp && npm install --global --prefix /home/workload/bun-toolchain --registry https://registry.npmjs.org --no-audit --no-fund 'bun@1.3.11')",
      'export PATH="/home/workload/bun-toolchain/bin:$PATH"',
      'test "$(bun --version)" = "1.3.11"',
      'bun_lock_before="$(sha256sum bun.lock)"',
      'bun install --frozen-lockfile',
      'test "$bun_lock_before" = "$(sha256sum bun.lock)"',
    ],
    note: 'Bun 1.3.11 verified against source CI/release and asserted at execution; true owning workspace root; frozen lock and byte-identity check; source-defined lifecycle/trustedDependencies retained (not force-trusted); no tests/build command; stricter immutable-install verification than upstream plain bun install; stale locks block here, not a claim upstream CI cannot regenerate its lock',
  };
}

export function assertNoUnselectedBun({root, directory, selected, read}) {
  if (read(root, remainingJoin(directory, 'bun.lock'), true) !== null ||
      read(root, remainingJoin(directory, 'bun.lockb'), true) !== null) {
    remainingAssert(selected?.scope?.startsWith('bun-locked-'), 'final selected Bun root must not fall through to npm/pnpm/Yarn');
  }
}
