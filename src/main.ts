import './style.css';
import {
  buildMerkleTree,
  generateProof,
  hashInternal,
  tamperLeaf,
  verifyProof,
  type InclusionProof,
  type MerkleNode,
  type MerkleTree,
  type OddMode,
} from './merkle';

interface Preset {
  key: string;
  label: string;
  items: string[];
}

interface StepHash {
  level: number;
  left: string;
  right: string;
  result: string;
}

interface MalleabilityResult {
  rootThree: string;
  rootFour: string;
  collides: boolean;
}

interface AppState {
  activePreset: string;
  textareaValue: string;
  leaves: string[];
  oddMode: OddMode;
  tree: MerkleTree | null;
  originalTree: MerkleTree | null;
  selectedLeafIndex: number;
  proof: InclusionProof | null;
  proofValid: boolean | null;
  proofSteps: StepHash[];
  proofError: string | null;
  tampered: boolean;
  originalProofCheckAgainstTampered: boolean | null;
  tamperedPathHashes: Set<string>;
  proofCalculatorN: number;
  malleability: Record<OddMode, MalleabilityResult> | null;
  /**
   * "Walk the proof" cursor. -1 = not walking (show the whole proof at once);
   * 0..siblings.length = the level the learner has climbed to. At value k the
   * running hash is proofSteps[k-1].result (or the raw leaf hash when k === 0),
   * and the sibling about to be consumed is siblings[k].
   */
  walkStep: number;
}

const presets: Preset[] = [
  {
    key: 'library',
    label: 'Library Catalog (8 items)',
    items: [
      'Pale Fire \u2014 Nabokov (QA76.73.P98 N38)',
      'The Name of the Rose \u2014 Eco (PQ4865.C6 N613)',
      'G\u00f6del Escher Bach \u2014 Hofstadter (Q335 .H59)',
      'The Selfish Gene \u2014 Dawkins (QH437 .D38)',
      'Thinking Fast and Slow \u2014 Kahneman (BF441 .K35)',
      'The Road \u2014 McCarthy (PS3563.C337 R63)',
      'Sapiens \u2014 Harari (GN360 .H37)',
      'The Order of Time \u2014 Rovelli (QB209 .R6813)',
    ],
  },
  {
    key: 'git',
    label: 'Git Commits (6 items)',
    items: [
      'a3f8c1d: initial commit',
      'b92e4f7: add authentication module',
      'c17d2a9: fix null pointer in parser',
      'd44b8e3: add unit tests for crypto',
      'e55f1c2: update dependencies',
      'f88a9d4: release v1.2.0',
    ],
  },
  {
    key: 'tx',
    label: 'Transaction Set (5 items)',
    items: [
      'Alice \u2192 Bob: 0.5 BTC',
      'Bob \u2192 Carol: 1.2 BTC',
      'Carol \u2192 Dave: 0.3 BTC',
      'Dave \u2192 Eve: 2.0 BTC',
      'Eve \u2192 Alice: 0.8 BTC',
    ],
  },
  {
    key: 'custom',
    label: 'Custom',
    items: ['alpha', 'beta', 'gamma', 'delta'],
  },
];

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing app root element.');
}

const initialLeaves = presets[0].items;
const state: AppState = {
  activePreset: presets[0].key,
  textareaValue: initialLeaves.join('\n'),
  leaves: initialLeaves.slice(),
  oddMode: 'promote',
  tree: null,
  originalTree: null,
  selectedLeafIndex: 0,
  proof: null,
  proofValid: null,
  proofSteps: [],
  proofError: null,
  tampered: false,
  originalProofCheckAgainstTampered: null,
  tamperedPathHashes: new Set<string>(),
  proofCalculatorN: 1024,
  malleability: null,
  walkStep: -1,
};

const announcer = document.querySelector<HTMLDivElement>('#sr-announcer');
const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

/**
 * Announce a message to assistive tech via the persistent live region in
 * index.html. Clearing first guarantees the region re-fires even when the same
 * text is announced twice in a row (e.g. building the tree repeatedly).
 */
function announce(message: string): void {
  if (!announcer) {
    return;
  }
  announcer.textContent = '';
  // A microtask gap lets screen readers detect the content change.
  window.requestAnimationFrame(() => {
    announcer.textContent = message;
  });
}

function scrollIntoViewIfNeeded(selector: string): void {
  const target = document.querySelector<HTMLElement>(selector);
  if (!target) {
    return;
  }
  target.scrollIntoView({
    behavior: prefersReducedMotion.matches ? 'auto' : 'smooth',
    block: 'nearest',
  });
}

function truncate(value: string, max = 30): string {
  return value.length > max ? `${value.slice(0, max)}...` : value;
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

async function computeProofSteps(proof: InclusionProof): Promise<StepHash[]> {
  const steps: StepHash[] = [];
  let current = proof.leafHash;

  for (let i = 0; i < proof.siblings.length; i += 1) {
    const sibling = proof.siblings[i];
    const left = sibling.position === 'left' ? sibling.hash : current;
    const right = sibling.position === 'right' ? sibling.hash : current;
    const result = await hashInternal(left, right);
    steps.push({ level: i + 1, left, right, result });
    current = result;
  }

  return steps;
}

function parseLeavesFromTextarea(raw: string): string[] {
  return raw
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

function treeLevels(root: MerkleNode): MerkleNode[][] {
  const levels: MerkleNode[][] = [[root]];
  while (levels[levels.length - 1].some((node) => !node.isLeaf)) {
    const next: MerkleNode[] = [];
    for (const node of levels[levels.length - 1]) {
      if (node.isLeaf) {
        // A leaf on a non-final level (can happen when a promoted sibling sits
        // beside a taller subtree): carry it straight down so columns align.
        next.push(node);
      } else if (node.isPromoted && node.left) {
        // RFC 6962 pass-through node has a single child; descend into it.
        next.push(node.left);
      } else if (node.left && node.right) {
        next.push(node.left);
        next.push(node.right);
      }
    }
    if (next.length === 0) break;
    levels.push(next);
  }
  return levels;
}

function findPathToLeaf(node: MerkleNode, leafIndex: number): MerkleNode[] | null {
  if (node.isLeaf && node.leafIndex === leafIndex && !node.isDuplicated) {
    return [node];
  }

  // RFC 6962 pass-through node: single child, descend through it.
  if (node.isPromoted && node.left) {
    const promotedPath = findPathToLeaf(node.left, leafIndex);
    return promotedPath ? [node, ...promotedPath] : null;
  }

  if (!node.left || !node.right) {
    return null;
  }

  const leftPath = findPathToLeaf(node.left, leafIndex);
  if (leftPath) {
    return [node, ...leftPath];
  }

  const rightPath = findPathToLeaf(node.right, leafIndex);
  if (rightPath) {
    return [node, ...rightPath];
  }

  return null;
}

/**
 * For the currently selected leaf, walk the same path generateProof() walks and
 * return, for each proof LEVEL (bottom-up), the sibling MerkleNode that is
 * consumed at that level. Index 0 is the leaf's immediate sibling; the last
 * entry is the sibling combined just below the root. Returns [] when no tree /
 * no path. This mirrors generateProof exactly (promoted pass-through parents
 * contribute no sibling and are skipped), so the visual highlight lines up
 * one-to-one with the textual proof steps.
 */
function siblingNodesForSelectedLeaf(): MerkleNode[] {
  if (!state.tree) {
    return [];
  }
  const path = findPathToLeaf(state.tree.root, state.selectedLeafIndex);
  if (!path) {
    return [];
  }
  // path is root -> ... -> leaf. Walk it leaf-up, collecting the sibling of the
  // child we came from at each real (non-promoted) internal node.
  const siblings: MerkleNode[] = [];
  for (let i = path.length - 1; i > 0; i -= 1) {
    const child = path[i];
    const parent = path[i - 1];
    if (parent.isPromoted) {
      continue; // pass-through: no sibling emitted, matches generateProof
    }
    const left = parent.left;
    const right = parent.right;
    if (!left || !right) {
      continue;
    }
    if (left === child) {
      siblings.push(right);
    } else if (right === child) {
      siblings.push(left);
    }
  }
  return siblings;
}

function treeNodeClass(node: MerkleNode, depth: number, hiddenMobile: boolean): string {
  const classes = ['tree-node'];
  if (depth === 0) {
    classes.push('node-root');
  } else if (node.isLeaf) {
    classes.push('node-leaf');
  } else {
    classes.push('node-internal');
  }
  if (hiddenMobile) {
    classes.push('mobile-hidden');
  }
  if (state.tamperedPathHashes.has(node.hash)) {
    classes.push('node-tampered');
  }
  if (state.selectedLeafIndex === node.leafIndex && !node.isDuplicated) {
    classes.push('selected-node');
  }
  return classes.join(' ');
}

/**
 * Edge list (parent DOM id -> its child DOM ids) for the last renderTree() call.
 * drawTreeConnectors() reads this after layout to stroke SVG lines between each
 * parent node and its children — turning the implied grid into a drawn tree.
 */
let treeEdges: Array<{ parent: string; child: string }> = [];

/** Map from MerkleNode object -> the DOM id assigned to it in renderTree. */
let nodeDomIds = new WeakMap<MerkleNode, string>();

function renderTree(): string {
  treeEdges = [];
  nodeDomIds = new WeakMap<MerkleNode, string>();
  if (!state.tree) {
    return '<p class="panel-empty">Build a tree to visualize it.</p>';
  }

  const levels = treeLevels(state.tree.root);
  const pathHashes = new Set<string>();
  const path = findPathToLeaf(state.tree.root, state.selectedLeafIndex);
  if (path) {
    for (const node of path) {
      pathHashes.add(node.hash);
    }
  }

  // Siblings consumed by the current proof, bottom-up (index 0 = leaf's sibling).
  const siblingNodes = state.proof ? siblingNodesForSelectedLeaf() : [];
  const siblingSet = new Set<MerkleNode>(siblingNodes);
  // During a walk, siblingNodes[walkStep] is the sibling being pulled in right now.
  const activeSibling =
    state.walkStep >= 0 && state.walkStep < siblingNodes.length
      ? siblingNodes[state.walkStep]
      : null;
  // Nodes on the climb path already reached (running-hash lineage). The climb has
  // combined `walkStep` siblings, so the running hash currently sits at the parent
  // that is `walkStep` levels above the leaf along the path.
  const climbedNodes = new Set<MerkleNode>();
  if (path && state.walkStep >= 0) {
    // path is root..leaf; the leaf is last. Count non-promoted rises from the leaf.
    let rises = 0;
    let cursor = path.length - 1; // leaf
    climbedNodes.add(path[cursor]);
    while (cursor > 0 && rises < state.walkStep) {
      const parent = path[cursor - 1];
      cursor -= 1;
      if (parent.isPromoted) {
        continue;
      }
      rises += 1;
      climbedNodes.add(parent);
    }
  }
  const runningHashNode =
    climbedNodes.size > 0 ? [...climbedNodes][climbedNodes.size - 1] : null;

  // Assign DOM ids per node (depth + index within level) and remember them.
  levels.forEach((nodes, depth) => {
    nodes.forEach((node, idx) => {
      nodeDomIds.set(node, `mn-${depth}-${idx}`);
    });
  });
  // Build the parent->child edge list structurally.
  for (let depth = 0; depth < levels.length - 1; depth += 1) {
    for (const parent of levels[depth]) {
      const pid = nodeDomIds.get(parent)!;
      if (parent.isLeaf) {
        continue; // carried-down leaf: no children below
      }
      if (parent.isPromoted && parent.left) {
        const cid = nodeDomIds.get(parent.left);
        if (cid) treeEdges.push({ parent: pid, child: cid });
        continue;
      }
      for (const child of [parent.left, parent.right]) {
        if (!child) continue;
        const cid = nodeDomIds.get(child);
        if (cid) treeEdges.push({ parent: pid, child: cid });
      }
    }
  }

  return levels
    .map((nodes, depth) => {
      const html = nodes
        .map((node) => {
          const domId = nodeDomIds.get(node)!;
          const isSelectableLeaf =
            node.isLeaf && !node.isDuplicated && node.leafIndex !== undefined;
          const isSelected =
            state.selectedLeafIndex === node.leafIndex && !node.isDuplicated;
          const isSibling = siblingSet.has(node);
          const isActiveSibling = activeSibling === node;
          const onClimb = climbedNodes.has(node);
          const isRunning = runningHashNode === node;
          const hiddenMobile =
            depth > 0 &&
            depth < levels.length - 1 &&
            !isSelected &&
            !isSibling &&
            !onClimb &&
            !pathHashes.has(node.hash);
          const isTampered = state.tamperedPathHashes.has(node.hash);
          const caption =
            depth === 0
              ? 'Root'
              : node.isLeaf
                ? node.isDuplicated
                  ? `Leaf ${node.leafIndex} (dup)`
                  : `Leaf ${node.leafIndex}`
                : `Internal d${depth}`;
          const leafData =
            isSelectableLeaf
              ? `<span class="tree-data">${escapeHtml(truncate(state.leaves[node.leafIndex!] ?? ''))}</span>`
              : '';
          // Non-color cue: tampered nodes also carry a visible badge + label,
          // so the state is not communicated by color alone (WCAG 1.4.1).
          const tamperBadge = isTampered
            ? '<span class="tree-flag" aria-hidden="true">⚠ tampered</span>'
            : '';
          // Sibling / running-hash badges are icon+text, not color alone (1.4.1).
          const roleBadge = isRunning
            ? '<span class="tree-flag flag-running" aria-hidden="true">running hash</span>'
            : isActiveSibling
              ? '<span class="tree-flag flag-sibling" aria-hidden="true">sibling in →</span>'
              : isSibling
                ? '<span class="tree-flag flag-sibling-dim" aria-hidden="true">sibling</span>'
                : '';

          const roleClasses = [
            isSibling ? 'node-sibling' : '',
            isActiveSibling ? 'node-sibling-active' : '',
            onClimb && state.walkStep >= 0 ? 'node-climbed' : '',
            isRunning ? 'node-running' : '',
          ]
            .filter(Boolean)
            .join(' ');

          // Full hash and role exposed to assistive tech; the visible label is truncated.
          const srRole = isActiveSibling
            ? ', sibling being combined at this step'
            : isSibling
              ? ', proof sibling'
              : isRunning
                ? ', current running hash'
                : '';
          const describe = `${caption}, hash ${node.hash}${srRole}${isTampered ? ', tampered' : ''}`;

          if (isSelectableLeaf) {
            const label = `Select ${caption} for proof. ${describe}`;
            return `<button
                type="button"
                id="${domId}"
                class="${treeNodeClass(node, depth, hiddenMobile)} ${roleClasses}"
                data-leaf-index="${node.leafIndex}"
                aria-pressed="${isSelected ? 'true' : 'false'}"
                aria-label="${escapeHtml(label)}">
              <span class="tree-caption">${caption}</span>
              <span class="tree-hash" aria-hidden="true">${node.hash.slice(0, 8)}...</span>
              ${leafData}
              ${tamperBadge}
              ${roleBadge}
            </button>`;
          }

          return `<div
              id="${domId}"
              class="${treeNodeClass(node, depth, hiddenMobile)} ${roleClasses}"
              role="group"
              aria-label="${escapeHtml(describe)}">
            <span class="tree-caption">${caption}</span>
            <span class="tree-hash" aria-hidden="true">${node.hash.slice(0, 8)}...</span>
            ${tamperBadge}
            ${roleBadge}
          </div>`;
        })
        .join('');

      const levelLabel =
        depth === 0 ? 'Root level' : depth === levels.length - 1 ? 'Leaf level' : `Level ${depth}`;
      return `<div class="tree-level level-${depth}" role="group" aria-label="${levelLabel}">${html}</div>`;
    })
    .join('');
}

/**
 * After the tree HTML is in the DOM and laid out, stroke SVG connector lines
 * between each parent node and its children. This is a pure visual overlay
 * (aria-hidden) redrawn on every render and on resize; it turns the column grid
 * into an actually-drawn binary tree. Sibling/active edges are colored to match
 * the node highlights so the eye can follow a sibling into its parent.
 */
function drawTreeConnectors(): void {
  const shell = document.querySelector<HTMLElement>('#tree-view');
  if (!shell || !state.tree) {
    return;
  }
  const existing = shell.querySelector('svg.tree-connectors');
  if (existing) existing.remove();
  if (treeEdges.length === 0) return;

  const shellRect = shell.getBoundingClientRect();
  const width = shell.scrollWidth;
  const height = shell.scrollHeight;
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('class', 'tree-connectors');
  svg.setAttribute('width', String(width));
  svg.setAttribute('height', String(height));
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('aria-hidden', 'true');

  // Which child DOM ids are the active / any sibling, to color their in-edge.
  const siblingNodes = state.proof ? siblingNodesForSelectedLeaf() : [];
  const activeSibling =
    state.walkStep >= 0 && state.walkStep < siblingNodes.length
      ? siblingNodes[state.walkStep]
      : null;
  const siblingIds = new Set(
    siblingNodes.map((n) => nodeDomIds.get(n)).filter(Boolean) as string[],
  );
  const activeId = activeSibling ? nodeDomIds.get(activeSibling) ?? null : null;

  const center = (el: HTMLElement, edge: 'top' | 'bottom') => {
    const r = el.getBoundingClientRect();
    return {
      x: r.left - shellRect.left + shell.scrollLeft + r.width / 2,
      y:
        (edge === 'top' ? r.top : r.bottom) -
        shellRect.top +
        shell.scrollTop,
    };
  };

  for (const edge of treeEdges) {
    const parentEl = document.getElementById(edge.parent);
    const childEl = document.getElementById(edge.child);
    if (!parentEl || !childEl) continue;
    // Skip edges to mobile-hidden nodes (they have zero box).
    if (childEl.offsetParent === null && childEl.getClientRects().length === 0) {
      continue;
    }
    const p = center(parentEl, 'bottom');
    const c = center(childEl, 'top');
    const line = document.createElementNS(NS, 'path');
    // A gentle vertical S-curve reads as a tree branch.
    const midY = (p.y + c.y) / 2;
    line.setAttribute(
      'd',
      `M ${p.x} ${p.y} C ${p.x} ${midY}, ${c.x} ${midY}, ${c.x} ${c.y}`,
    );
    let cls = 'connector';
    if (edge.child === activeId) cls += ' connector-active';
    else if (siblingIds.has(edge.child)) cls += ' connector-sibling';
    line.setAttribute('class', cls);
    svg.appendChild(line);
  }
  shell.prepend(svg);
}

function proofSummary(): string {
  if (!state.tree) {
    return '';
  }
  const hashes = state.tree.depth;
  const bytes = hashes * 32;
  return `${hashes} hashes x 32 bytes = ${bytes} bytes to prove membership in ${state.tree.leafCount}-leaf tree`;
}

function renderProofPanel(): string {
  if (!state.tree) {
    return '<p class="panel-empty">Build a tree and select a leaf to generate a proof.</p>';
  }

  if (!state.proof) {
    return '<p class="panel-empty">Select a leaf, then click Generate Proof.</p>';
  }

  const siblings = state.proof.siblings
    .map(
      (sibling, index) => `<li${sibling.isSelfCopy ? ' class="sibling-selfcopy"' : ''}>
        <span class="proof-index">Level ${index + 1} (${sibling.position})${sibling.isSelfCopy ? ' <span class="tree-flag">self-copy</span>' : ''}</span>
        <span class="mono">${sibling.hash}</span>
      </li>`,
    )
    .join('');

  const selfCopyWarning = state.proof.usesDuplicatedSibling
    ? `<p class="notice notice-warn" role="note">
        <span aria-hidden="true">⚠</span> This proof relies on a <strong>self-copy sibling</strong> — the target's own
        subtree hash duplicated to fill an odd slot (Bitcoin mode). A verifier that does not also check the
        tree size can be fooled into accepting a forged position here. This is the odd-leaf duplication leak;
        switch to RFC 6962 mode to remove it.
      </p>`
    : '';

  const totalSteps = state.proofSteps.length;
  const walking = state.walkStep >= 0;
  // In walk mode only reveal recomputation lines already climbed; otherwise all.
  const visibleSteps = walking ? state.proofSteps.slice(0, state.walkStep) : state.proofSteps;
  const steps = visibleSteps
    .map(
      (step) => `<li>
        <span class="proof-index">Step ${step.level}</span>
        <span class="mono">H(0x01 || ${step.left.slice(0, 8)}... || ${step.right.slice(0, 8)}...) = ${step.result}</span>
      </li>`,
    )
    .join('');

  // The hash we have climbed to so far (byte-for-byte). Before any step it is the
  // leaf hash; after step k it is proofSteps[k-1].result. This is real, recomputed
  // from SHA-256 — never a stand-in for the committed root.
  const climbedCount = walking ? state.walkStep : totalSteps;
  const runningHash =
    climbedCount === 0 ? state.proof.leafHash : state.proofSteps[climbedCount - 1].result;
  const recomputedRoot = totalSteps === 0 ? state.proof.leafHash : state.proofSteps[totalSteps - 1].result;
  const climbComplete = climbedCount >= totalSteps;

  // "Walk the proof" step controls: advance one level at a time so the recursion
  // is felt, not dumped. Buttons are only meaningful once there is >0 step.
  const walkControls =
    totalSteps === 0
      ? '<p class="field-hint">This leaf is the root — a single-leaf tree needs no sibling steps.</p>'
      : `
      <div class="walk-controls" role="group" aria-label="Walk the proof one level at a time">
        <button type="button" id="walk-start" class="secondary walk-btn">${walking ? 'Restart walk' : 'Walk the proof ▸'}</button>
        <button type="button" id="walk-next" class="primary walk-btn" ${walking && !climbComplete ? '' : 'disabled'}>Next level ▸</button>
        <button type="button" id="walk-all" class="secondary walk-btn" ${walking && climbComplete ? 'disabled' : ''}>Show all at once</button>
        <span class="walk-progress" aria-hidden="true">${walking ? `Level ${climbedCount} / ${totalSteps}` : `${totalSteps} levels`}</span>
      </div>
      ${
        walking
          ? `<div class="walk-readout" role="status" aria-live="polite">
              <p class="walk-line"><span class="walk-lbl">Running hash</span> <span class="mono wrap">${runningHash}</span></p>
              ${
                climbComplete
                  ? `<p class="walk-line walk-done"><span aria-hidden="true">▲</span> Reached the top — the running hash below is the recomputed root.</p>`
                  : `<p class="walk-line"><span class="walk-lbl">Next: pull sibling (${state.proof.siblings[state.walkStep].position})</span> <span class="mono wrap">${state.proof.siblings[state.walkStep].hash}</span></p>
                     <p class="walk-line"><span class="walk-lbl">Combine →</span> <span class="mono wrap">${state.proofSteps[state.walkStep].result}</span></p>`
              }
            </div>`
          : ''
      }`;

  // Verification as a visible byte-equality assertion (not just a VALID banner).
  // Only assert once the climb reaches the top. Highlighted node ids in the tree
  // let the learner SEE the two strings are the same before the color turns green.
  // Compare against the tree's LIVE committed root: after a tamper the leaf's
  // recomputed root no longer matches, so the panel honestly turns red.
  const committedRoot = state.tree.root.hash;
  const rootsMatch = recomputedRoot === committedRoot;
  const equalityPanel = climbComplete
    ? `<div class="equality proof-status ${rootsMatch ? 'equality-match' : 'equality-mismatch'}" role="status" aria-live="polite">
        <div class="eq-row">
          <span class="eq-lbl">Recomputed root (climbed from the leaf)</span>
          <span class="mono wrap eq-hash">${recomputedRoot}</span>
        </div>
        <div class="eq-op" aria-hidden="true">${rootsMatch ? '=' : '≠'}</div>
        <div class="eq-row">
          <span class="eq-lbl">Committed root (the tree's published commitment)</span>
          <span class="mono wrap eq-hash">${committedRoot}</span>
        </div>
        <p class="eq-verdict">
          <span aria-hidden="true">${rootsMatch ? '✅' : '❌'}</span>
          ${
            rootsMatch
              ? 'Byte-for-byte identical — the leaf is proven to be in the committed tree.'
              : 'The two roots differ — this leaf is NOT in the committed tree (the leaf or a sibling was tampered).'
          }
        </p>
      </div>`
    : `<p class="field-hint">Finish the walk (or “Show all at once”) to compare the recomputed root against the committed root.</p>`;

  return `
    <div class="proof-block">
      <p class="proof-gloss"><strong>Inclusion proof, in one line:</strong> prove this one item is in the set without sending the whole set — just this leaf plus one sibling hash per level (O(log n) of them).</p>
      <p><strong>Leaf hash:</strong></p>
      <p class="mono wrap">${state.proof.leafHash}</p>
      <p><strong>Siblings (one per level, ${state.proof.siblings.length} total):</strong></p>
      <ol class="proof-list">${siblings}</ol>
      ${walkControls}
      <p><strong>Root recomputation${walking ? ` (level ${climbedCount} / ${totalSteps})` : ''}:</strong></p>
      <ol class="proof-list">${steps || '<li class="field-hint">Press “Next level” to climb the first step.</li>'}</ol>
      ${equalityPanel}
      <p class="root-row">
        <strong>Committed root:</strong>
        <span class="mono wrap" id="root-hash">${committedRoot}</span>
        <button type="button" class="copy-btn" data-copy="${committedRoot}" aria-label="Copy root hash to clipboard">
          <span aria-hidden="true">Copy</span>
        </button>
      </p>
      ${selfCopyWarning}
      <p class="proof-size">${proofSummary()}</p>
    </div>
  `;
}

function renderMalleability(): string {
  if (!state.malleability) {
    return '';
  }
  const dup = state.malleability.duplicate;
  const prom = state.malleability.promote;
  const row = (label: string, res: MalleabilityResult) => `
    <div class="mall-case">
      <h4>${label}</h4>
      <p class="mono wrap"><span class="mall-lbl">root([a,b,c]):</span> ${res.rootThree}</p>
      <p class="mono wrap"><span class="mall-lbl">root([a,b,c,c]):</span> ${res.rootFour}</p>
      <p class="${res.collides ? 'proof-invalid' : 'proof-valid'}">
        <span aria-hidden="true">${res.collides ? '❌' : '✅'}</span>
        ${res.collides
          ? 'Roots COLLIDE — appending a duplicate transaction leaves the Merkle root unchanged (CVE-2012-2459 malleability).'
          : 'Roots DIFFER — the two leaf lists commit to distinct roots, so the malleability is fixed.'}
      </p>
    </div>`;
  return `
    <section class="panel mall-panel">
      <h3>Odd-leaf malleability (CVE-2012-2459), demonstrated</h3>
      <p>
        These roots are computed live from real SHA-256. A three-item list and a four-item list whose
        fourth item repeats the third are hashed under each convention:
      </p>
      ${row('Bitcoin — duplicate', dup)}
      ${row('RFC 6962 — promote', prom)}
    </section>
  `;
}

function renderCalculator(): string {
  const n = Math.max(2, Math.min(1_000_000_000, state.proofCalculatorN));
  const depth = Math.ceil(Math.log2(n));
  const bytes = depth * 32;
  const fraction = (bytes / (n * 32)) * 100;

  return `
    <div class="calculator-results">
      <p>Tree depth: <strong>${depth}</strong></p>
      <p>Proof size: <strong>${depth}</strong> hashes</p>
      <p>Proof bytes: <strong>${bytes}</strong></p>
      <p>Fraction downloaded: <strong>${fraction.toExponential(3)}%</strong></p>
    </div>
  `;
}

function renderApp(): void {
  const focusedId = (document.activeElement as HTMLElement)?.id ?? null;
  let cursorPos: number | null = null;
  if (document.activeElement) {
    try {
      cursorPos = (document.activeElement as any).selectionStart ?? null;
    } catch {
      // Ignore
    }
  }

  const isOdd = state.leaves.length % 2 === 1;
  const duplicateNote = isOdd
    ? state.oddMode === 'promote'
      ? '<p class="notice">Odd leaf count detected. The lone last node is <strong>promoted unchanged</strong> to the next level (RFC 6962). No duplication.</p>'
      : '<p class="notice">Odd leaf count detected. The lone last node is <strong>hashed with a copy of itself</strong> (Bitcoin convention) — this is the CVE-2012-2459 pattern demonstrated below.</p>'
    : '<p class="notice">Even leaf count: this level pairs cleanly, so the odd-node rule does not apply here.</p>';

  // The selected odd-node mode only takes effect on the NEXT build. Flag the gap
  // so a first-timer knows a mode switch needs a rebuild (a real workflow trap).
  const rebuildNeeded = state.tree !== null && state.tree.oddMode !== state.oddMode;

  app!.innerHTML = `
    <main class="page" id="main" tabindex="-1">
      <header class="cl-hero">
        <div class="cl-hero-main">
          <h1 class="cl-hero-title">Merkle Vault</h1>
          <p class="cl-hero-sub">Binary hash tree · SHA-256 · O(log n) inclusion proofs</p>
          <p class="cl-hero-desc">Build a binary Merkle tree with real SHA-256, generate O(log n) inclusion proofs for any leaf, and watch tamper detection invalidate the root.</p>
        </div>
        <aside class="cl-hero-why" aria-label="Why it matters">
          <span class="cl-hero-why-label">WHY IT MATTERS</span>
          <p class="cl-hero-why-text">Merkle proofs let a client confirm one record belongs to a massive dataset by checking only a handful of hashes — the backbone of Git, Bitcoin, and Certificate Transparency. Domain separation is what keeps those proofs unforgeable.</p>
        </aside>
      </header>

      <section class="panel" id="section-a">
        <h2>Section A: What is a Merkle Tree?</h2>
        <div class="copy-grid">
          <article>
            <h3>A1 - Structure</h3>
            <p>A Merkle tree is a binary hash tree. Leaves hash data items, internal nodes hash child hashes, and the root commits to the whole dataset.</p>
            <p>Any leaf change cascades to a different root, so the root is a cryptographic commitment.</p>
          </article>
          <article>
            <h3>A2 - Domain Separation</h3>
            <p>Leaves are hashed as <span class="mono">SHA-256(0x00 || data)</span>; internal nodes as <span class="mono">SHA-256(0x01 || left || right)</span>.</p>
            <p>This blocks second preimage attacks on tree structure where internal hashes could otherwise be reinterpreted as leaf hashes.</p>
          </article>
          <article>
            <h3>A3 - Inclusion Proofs</h3>
            <p><strong>In plain terms:</strong> prove one item is in the set without sending the whole set.</p>
            <p>A proof includes the target leaf hash and one sibling hash per level. The verifier recomputes up to root.</p>
            <p>Proof size is <span class="mono">O(log n)</span>; for 1 million leaves, only 20 hashes are needed.</p>
          </article>
        </div>
        <div class="static-tree">
          <div class="tree-level level-0">
            <div class="tree-node node-root">Root</div>
          </div>
          <div class="tree-level level-1">
            <div class="tree-node node-internal node-proof">H(L0,L1)</div>
            <div class="tree-node node-internal node-proof">H(L2,L3)</div>
          </div>
          <div class="tree-level level-2">
            <div class="tree-node node-leaf">L0</div>
            <div class="tree-node node-leaf node-proof">L1</div>
            <div class="tree-node node-leaf">L2</div>
            <div class="tree-node node-leaf">L3</div>
          </div>
          <p class="caption">Amber nodes show the proof path for leaf L1.</p>
        </div>
      </section>

      <section class="panel" id="section-b">
        <h2>Section B: Live Tree Builder</h2>
        <div class="preset-row">
          ${presets
            .map(
              (preset) => `<button type="button" class="preset-btn ${state.activePreset === preset.key ? 'active' : ''}" data-preset="${preset.key}" aria-pressed="${state.activePreset === preset.key ? 'true' : 'false'}">${preset.label}</button>`,
            )
            .join('')}
        </div>
        <p class="section-lede">The core loop: <strong>build</strong> a tree, <strong>select</strong> a leaf, <strong>generate</strong> its proof, then <strong>tamper</strong> a leaf and watch the proof break. (Odd-leaf conventions and the CVE-2012-2459 malleability bug live in <em>Advanced</em>, below.)</p>
        <label for="leaf-input">Leaf data (one item per line, 2-16 leaves)</label>
        <textarea id="leaf-input" rows="8">${escapeHtml(state.textareaValue)}</textarea>
        <div class="meta-row">
          <p>Leaf count: <strong>${state.leaves.length}</strong></p>
          <p>Mode: <strong>${state.oddMode === 'promote' ? 'RFC 6962 — promote' : 'Bitcoin — duplicate'}</strong>${rebuildNeeded ? ' <span class="rebuild-flag">⟳ rebuild to apply</span>' : ''}</p>
        </div>
        ${state.proofError ? `<p class="proof-invalid">${state.proofError}</p>` : ''}
        <div class="action-row">
          <button type="button" id="build-tree" class="primary">Build Tree</button>
          <button type="button" id="generate-proof" class="secondary" ${state.tree ? '' : 'disabled'}>Generate Proof</button>
          <button type="button" id="tamper-leaf" class="danger" ${state.tree && !state.tampered ? '' : 'disabled'}>Tamper Leaf</button>
          <button type="button" id="restore-tree" class="secondary" ${state.tampered ? '' : 'disabled'}>Restore Original</button>
        </div>
        <div
          id="tree-view"
          class="tree-shell"
          role="group"
          aria-label="Merkle tree visualization. Select a leaf to set the proof target."
          tabindex="0"
        >${renderTree()}</div>
        <section class="proof-panel">
          <h3>Inclusion Proof and Verification</h3>
          ${renderProofPanel()}
          ${
            state.tampered && state.tree && state.originalTree
              ? `<p class="proof-invalid"><span aria-hidden="true">❌</span> PROOF INVALID — Root changed from ${state.originalTree.root.hash.slice(0, 12)}... to ${state.tree.root.hash.slice(0, 12)}...</p>`
              : ''
          }
        </section>

        <details class="advanced" id="advanced-odd"${state.oddMode === 'duplicate' || state.tampered ? ' open' : ''}>
          <summary>
            <span class="adv-title">Advanced — odd-leaf conventions &amp; the CVE-2012-2459 malleability bug</span>
            <span class="adv-hint">optional deep dive · safe to skip on a first read</span>
          </summary>
          <div class="advanced-body">
            <fieldset class="mode-fieldset">
              <legend>Odd-node convention</legend>
              <div class="mode-row" role="radiogroup" aria-label="Odd-node convention">
                <button
                  type="button"
                  class="mode-btn ${state.oddMode === 'promote' ? 'active' : ''}"
                  data-odd-mode="promote"
                  role="radio"
                  aria-checked="${state.oddMode === 'promote' ? 'true' : 'false'}"
                >RFC 6962 — promote</button>
                <button
                  type="button"
                  class="mode-btn ${state.oddMode === 'duplicate' ? 'active' : ''}"
                  data-odd-mode="duplicate"
                  role="radio"
                  aria-checked="${state.oddMode === 'duplicate' ? 'true' : 'false'}"
                >Bitcoin — duplicate</button>
              </div>
              <p class="field-hint">
                RFC 6962 (the default, matching Certificate Transparency) carries a lone node up unchanged.
                Bitcoin hashes it with a copy of itself, which caused CVE-2012-2459.
                <strong>Changing the mode does not take effect until you rebuild the tree</strong> — press Build Tree above after switching.
              </p>
              ${duplicateNote}
            </fieldset>
            ${renderMalleability()}
          </div>
        </details>
      </section>

      <section class="panel" id="section-c">
        <h2>Section C: Real-World Systems</h2>
        <article class="system-card">
          <h3>C1 - Git</h3>
          <p>Git stores blobs, trees, and commits as content-addressed objects. A commit object includes the tree object ID for the repository snapshot.</p>
          <p>Any file change alters blob IDs, then tree IDs, then commit IDs. Git historically used SHA-1 and supports SHA-256 repositories with object format selection.</p>
          <div class="flow">file -> blob -> tree -> commit</div>
        </article>
        <article class="system-card">
          <h3>C2 - Bitcoin</h3>
          <p>Bitcoin computes a Merkle root over transaction hashes and stores it in the 80-byte block header.</p>
          <p>Header fields are version, previous block hash, merkle root, timestamp, bits, and nonce. SPV clients verify inclusion with logarithmic-size proofs.</p>
          <div class="flow">version | prev_block | <strong>merkle_root</strong> | timestamp | bits | nonce</div>
        </article>
        <article class="system-card">
          <h3>C3 - Certificate Transparency (RFC 6962)</h3>
          <p>CT logs are append-only Merkle history trees. The signed tree head (STH) is a signed root commitment from a log operator.</p>
          <p>Audit proofs show certificate inclusion. RFC 6962 specifies domain-separated hashes with 0x00 for leaves and 0x01 for internal nodes.</p>
        </article>
      </section>

      <section class="panel" id="section-d">
        <h2>Section D: Proof Size and Efficiency</h2>
        <div class="table-scroll" role="region" aria-label="Proof size by leaf count, scrollable" tabindex="0">
          <table>
            <caption class="sr-only">Tree depth, proof size, and proof bytes as the number of leaves grows.</caption>
            <thead>
              <tr><th scope="col">Leaves (n)</th><th scope="col">Tree depth</th><th scope="col">Proof size</th><th scope="col">Proof bytes</th></tr>
            </thead>
            <tbody>
              <tr><td>8</td><td>3</td><td>3 hashes</td><td>96 bytes</td></tr>
              <tr><td>16</td><td>4</td><td>4 hashes</td><td>128 bytes</td></tr>
              <tr><td>1,024</td><td>10</td><td>10 hashes</td><td>320 bytes</td></tr>
              <tr><td>1,048,576 (1M)</td><td>20</td><td>20 hashes</td><td>640 bytes</td></tr>
              <tr><td>1,073,741,824 (1B)</td><td>30</td><td>30 hashes</td><td>960 bytes</td></tr>
            </tbody>
          </table>
        </div>
        <div class="calculator">
          <label for="proof-n">Number of leaves</label>
          <input
            id="proof-n"
            type="number"
            inputmode="numeric"
            min="2"
            max="1000000000"
            value="${state.proofCalculatorN}"
            aria-describedby="proof-n-hint"
          />
          <p id="proof-n-hint" class="field-hint">Enter 2 to 1,000,000,000 leaves.</p>
          <div class="calculator-output" role="status" aria-live="polite">${renderCalculator()}</div>
        </div>
        <div class="table-scroll" role="region" aria-label="Membership proof approaches compared, scrollable" tabindex="0">
          <table>
            <caption class="sr-only">Comparison of dataset membership approaches by proof size.</caption>
            <thead>
              <tr><th scope="col">Approach</th><th scope="col">Proof size</th><th scope="col">Notes</th></tr>
            </thead>
            <tbody>
              <tr><td>Download all data</td><td>O(n)</td><td>No cryptography needed</td></tr>
              <tr><td>Bloom filter</td><td>O(n) space, O(1) query</td><td>Probabilistic, false positives possible</td></tr>
              <tr><td>Merkle inclusion proof</td><td>O(log n)</td><td>Cryptographic, no false positives</td></tr>
              <tr><td>Verkle proof</td><td>O(1) amortized</td><td>Uses polynomial commitments for smaller proofs; not implemented here</td></tr>
            </tbody>
          </table>
        </div>
      </section>
    </main>
<footer style="margin-top:3rem;padding:2rem 1rem;border-top:1px solid rgba(128,128,128,.25);text-align:center;font-size:.85rem;line-height:1.9;opacity:.85;font-family:ui-monospace,Menlo,Consolas,monospace">
  <div><strong>Related demos:</strong> <a href="https://systemslibrarian.github.io/crypto-lab-babel-hash/" style="color:#35d6bb">babel-hash</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-hash-zoo/" style="color:#35d6bb">hash-zoo</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/" style="color:#35d6bb">sphincs-ledger</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-lms-ledger/" style="color:#35d6bb">lms-ledger</a> &middot; <a href="https://systemslibrarian.github.io/crypto-lab-collision-vault/" style="color:#35d6bb">collision-vault</a></div>
  <div style="margin-top:.5rem"><a href="https://github.com/systemslibrarian/crypto-lab-merkle-vault" style="color:#35d6bb">Source on GitHub</a> &middot; <a href="https://crypto-lab.systemslibrarian.dev/" style="color:#35d6bb">More crypto-lab demos</a></div>
  <div style="margin-top:.75rem;opacity:.75">&ldquo;So whether you eat or drink or whatever you do, do it all for the glory of God.&rdquo; &mdash; 1 Corinthians 10:31</div>
</footer>
  `;

  const themeToggle = document.querySelector<HTMLButtonElement>('#theme-toggle');
  if (themeToggle) {
    const icon = themeToggle.querySelector<HTMLSpanElement>('.theme-toggle-icon');
    const currentTheme = document.documentElement.getAttribute('data-theme') ?? 'dark';
    const isDark = currentTheme === 'dark';
    if (icon) {
      icon.textContent = isDark ? '🌙' : '☀️';
    }
    // aria-pressed = "is dark mode active"; label states the action the click performs.
    themeToggle.setAttribute('aria-pressed', String(isDark));
    themeToggle.setAttribute('aria-label', isDark ? 'Switch to light theme' : 'Switch to dark theme');
    themeToggle.title = isDark ? 'Switch to light theme' : 'Switch to dark theme';

    themeToggle.addEventListener('click', () => {
      const active = document.documentElement.getAttribute('data-theme') ?? 'dark';
      const next = active === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('theme', next);
      announce(`${next === 'dark' ? 'Dark' : 'Light'} theme enabled.`);
      renderApp();
    });
  }

  document.querySelectorAll<HTMLButtonElement>('[data-preset]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const key = btn.dataset.preset ?? 'custom';
      const preset = presets.find((entry) => entry.key === key);
      if (!preset) {
        return;
      }
      state.activePreset = key;
      state.textareaValue = preset.items.join('\n');
      state.leaves = preset.items.slice();
      state.tree = null;
      state.originalTree = null;
      state.proof = null;
      state.proofSteps = [];
      state.proofValid = null;
      state.proofError = null;
      state.tampered = false;
      state.originalProofCheckAgainstTampered = null;
      state.tamperedPathHashes = new Set<string>();
    state.walkStep = -1;
      state.walkStep = -1;
      announce(`${preset.label} preset loaded with ${preset.items.length} leaves.`);
      renderApp();
    });
  });

  document.querySelectorAll<HTMLButtonElement>('[data-odd-mode]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const mode = (btn.dataset.oddMode as OddMode) ?? 'promote';
      if (mode === state.oddMode) {
        return;
      }
      state.oddMode = mode;
      // Rebuilding is required for the change to take effect; reset derived state.
      state.tree = null;
      state.originalTree = null;
      state.proof = null;
      state.proofSteps = [];
      state.proofValid = null;
      state.proofError = null;
      state.tampered = false;
      state.originalProofCheckAgainstTampered = null;
      state.tamperedPathHashes = new Set<string>();
    state.walkStep = -1;
      state.walkStep = -1;
      announce(
        mode === 'promote'
          ? 'RFC 6962 promote mode selected. Rebuild the tree to apply.'
          : 'Bitcoin duplicate mode selected. Rebuild the tree to apply.',
      );
      renderApp();
    });
  });

  const leafInput = document.querySelector<HTMLTextAreaElement>('#leaf-input');
  leafInput?.addEventListener('input', (event) => {
    const value = (event.currentTarget as HTMLTextAreaElement).value;
    state.textareaValue = value;
    state.leaves = parseLeavesFromTextarea(value);
    state.activePreset = 'custom';
    renderApp();
  });

  const buildButton = document.querySelector<HTMLButtonElement>('#build-tree');
  buildButton?.addEventListener('click', async () => {
    if (state.leaves.length < 2 || state.leaves.length > 16) {
      state.proofError = 'Leaf count must be between 2 and 16.';
      announce(`Cannot build tree. ${state.proofError}`);
      renderApp();
      return;
    }
    state.tree = await buildMerkleTree(state.leaves, state.oddMode);
    announce(`Tree built with ${state.leaves.length} leaves and root ${state.tree.root.hash.slice(0, 12)}.`);
    state.originalTree = state.tree;
    state.selectedLeafIndex = Math.min(state.selectedLeafIndex, state.leaves.length - 1);
    state.proof = null;
    state.proofSteps = [];
    state.proofValid = null;
    state.proofError = null;
    state.tampered = false;
    state.originalProofCheckAgainstTampered = null;
    state.tamperedPathHashes = new Set<string>();
    state.walkStep = -1;
    renderApp();
  });

  const generateButton = document.querySelector<HTMLButtonElement>('#generate-proof');
  generateButton?.addEventListener('click', async () => {
    if (!state.tree) {
      state.proofError = 'Build a tree first.';
      renderApp();
      return;
    }

    state.proof = await generateProof(state.tree, state.selectedLeafIndex);
    state.proofSteps = await computeProofSteps(state.proof);
    state.proofValid = await verifyProof(state.proof);
    state.proofError = null;
    state.walkStep = -1; // show the whole proof; learner can start the walk next
    announce(
      `Proof generated for leaf ${state.selectedLeafIndex} with ${state.proof.siblings.length} sibling hashes. Proof is ${state.proofValid ? 'valid' : 'invalid'}.`,
    );
    renderApp();
    scrollIntoViewIfNeeded('.proof-panel');
  });

  // "Walk the proof": step through one level at a time so the recursion is felt.
  document.querySelector<HTMLButtonElement>('#walk-start')?.addEventListener('click', () => {
    if (!state.proof) return;
    state.walkStep = 0;
    announce(
      `Walking the proof. Starting at the leaf hash. ${state.proofSteps.length} levels to climb.`,
    );
    renderApp();
    scrollIntoViewIfNeeded('.walk-readout');
  });

  document.querySelector<HTMLButtonElement>('#walk-next')?.addEventListener('click', () => {
    if (!state.proof) return;
    if (state.walkStep < state.proofSteps.length) {
      const combined = state.proofSteps[state.walkStep];
      state.walkStep += 1;
      const atTop = state.walkStep >= state.proofSteps.length;
      announce(
        atTop
          ? `Reached the top. Recomputed root ${combined.result.slice(0, 12)}.`
          : `Level ${state.walkStep}: combined with the sibling to get ${combined.result.slice(0, 12)}.`,
      );
      renderApp();
    }
  });

  document.querySelector<HTMLButtonElement>('#walk-all')?.addEventListener('click', () => {
    if (!state.proof) return;
    state.walkStep = -1; // reveal every level at once
    announce('Showing all proof levels at once.');
    renderApp();
  });

  const tamperButton = document.querySelector<HTMLButtonElement>('#tamper-leaf');
  tamperButton?.addEventListener('click', async () => {
    if (!state.tree || !state.originalTree) {
      return;
    }

    const target = state.selectedLeafIndex;
    state.tree = await tamperLeaf(state.originalTree, target, `${state.leaves[target]} [TAMPERED]`);
    state.leaves = state.leaves.map((leaf, index) =>
      index === target ? `${leaf} [TAMPERED]` : leaf,
    );
    state.tampered = true;

    const path = findPathToLeaf(state.tree.root, target) ?? [];
    state.tamperedPathHashes = new Set(path.map((node) => node.hash));

    if (state.proof) {
      state.originalProofCheckAgainstTampered = await verifyProof({
        ...state.proof,
        root: state.tree.root.hash,
      });
      state.proofValid = state.originalProofCheckAgainstTampered;
    }

    announce(
      `Leaf ${target} tampered. The root hash changed and the original proof is now invalid.`,
    );
    renderApp();
  });

  const restoreButton = document.querySelector<HTMLButtonElement>('#restore-tree');
  restoreButton?.addEventListener('click', () => {
    if (!state.originalTree) {
      return;
    }

    const preset = presets.find((entry) => entry.key === state.activePreset);
    const restored =
      state.activePreset !== 'custom' && preset
        ? preset.items
        : state.textareaValue
            .replaceAll(' [TAMPERED]', '')
            .split('\n')
            .map((line) => line.trim())
            .filter((line) => line.length > 0);

    state.leaves = restored;
    state.textareaValue = restored.join('\n');
    state.tree = state.originalTree;
    state.tampered = false;
    state.proof = null;
    state.proofSteps = [];
    state.proofValid = null;
    state.proofError = null;
    state.originalProofCheckAgainstTampered = null;
    state.tamperedPathHashes = new Set<string>();
    state.walkStep = -1;
    announce('Original data restored. The tree is back to its untampered state.');
    renderApp();
  });

  document.querySelectorAll<HTMLButtonElement>('[data-leaf-index]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const value = Number.parseInt(btn.dataset.leafIndex ?? '0', 10);
      const changed = value !== state.selectedLeafIndex;
      state.selectedLeafIndex = value;
      if (changed) {
        // The old proof was for a different leaf; clear it so the tree highlight
        // and the proof panel stay in sync. The learner regenerates for this leaf.
        state.proof = null;
        state.proofSteps = [];
        state.proofValid = null;
        state.walkStep = -1;
      }
      announce(`Leaf ${value} selected as proof target. Generate a proof to see its path.`);
      renderApp();
    });
  });

  document.querySelectorAll<HTMLButtonElement>('[data-copy]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const value = btn.dataset.copy ?? '';
      try {
        await navigator.clipboard.writeText(value);
        const original = btn.querySelector('span');
        if (original) {
          original.textContent = 'Copied';
        }
        btn.classList.add('copied');
        announce('Root hash copied to clipboard.');
        window.setTimeout(() => {
          if (original) {
            original.textContent = 'Copy';
          }
          btn.classList.remove('copied');
        }, 1600);
      } catch {
        announce('Copy failed. Your browser blocked clipboard access.');
      }
    });
  });

  const calculatorInput = document.querySelector<HTMLInputElement>('#proof-n');
  calculatorInput?.addEventListener('input', (event) => {
    const n = Number.parseInt((event.currentTarget as HTMLInputElement).value, 10);
    if (Number.isFinite(n)) {
      state.proofCalculatorN = n;
    }
    renderApp();
  });

  if (focusedId) {
    const el = document.getElementById(focusedId);
    if (el) {
      el.focus();
      if (cursorPos !== null) {
        try {
          (el as any).selectionStart = cursorPos;
          (el as any).selectionEnd = cursorPos;
        } catch {
          // Ignore
        }
      }
    }
  }

  // Draw parent→child connector lines once the new tree HTML is laid out. Two
  // rAFs so grid layout + any font metrics have settled before we measure boxes.
  requestAnimationFrame(() => requestAnimationFrame(() => drawTreeConnectors()));
}

// Redraw connectors when the viewport reflows (columns can shift width/wrap).
let connectorResizeQueued = false;
window.addEventListener('resize', () => {
  if (connectorResizeQueued) return;
  connectorResizeQueued = true;
  requestAnimationFrame(() => {
    connectorResizeQueued = false;
    drawTreeConnectors();
  });
});

/**
 * Recompute the CVE-2012-2459 malleability demonstration for both odd-node
 * conventions. Under Bitcoin 'duplicate', the leaf lists [a,b,c] and [a,b,c,c]
 * hash to the SAME root — an attacker can append a duplicate transaction
 * without changing the block's Merkle root. Under RFC 6962 'promote', they do
 * NOT collide, so the malleability is fixed.
 */
async function computeMalleability(): Promise<Record<OddMode, MalleabilityResult>> {
  const base = ['tx-a', 'tx-b', 'tx-c'];
  const padded = ['tx-a', 'tx-b', 'tx-c', 'tx-c'];
  const out = {} as Record<OddMode, MalleabilityResult>;
  for (const mode of ['promote', 'duplicate'] as OddMode[]) {
    const t3 = await buildMerkleTree(base, mode);
    const t4 = await buildMerkleTree(padded, mode);
    out[mode] = {
      rootThree: t3.root.hash,
      rootFour: t4.root.hash,
      collides: t3.root.hash === t4.root.hash,
    };
  }
  return out;
}

async function bootstrap(): Promise<void> {
  state.tree = await buildMerkleTree(state.leaves, state.oddMode);
  state.originalTree = state.tree;
  state.malleability = await computeMalleability();
  renderApp();
}

bootstrap();
