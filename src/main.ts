import './style.css';
import {
  buildMerkleTree,
  generateProof,
  tamperLeaf,
  verifyProof,
  type InclusionProof,
  type MerkleNode,
  type MerkleTree,
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

interface AppState {
  activePreset: string;
  textareaValue: string;
  leaves: string[];
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

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

async function hashInternal(leftHex: string, rightHex: string): Promise<string> {
  const input = concatBytes(
    new Uint8Array([0x01]),
    hexToBytes(leftHex),
    hexToBytes(rightHex),
  );
  const buf = await crypto.subtle.digest('SHA-256', input as Uint8Array<ArrayBuffer>);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
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
      if (node.left && node.right) {
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

function renderTree(): string {
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

  return levels
    .map((nodes, depth) => {
      const html = nodes
        .map((node) => {
          const isSelectableLeaf =
            node.isLeaf && !node.isDuplicated && node.leafIndex !== undefined;
          const isSelected =
            state.selectedLeafIndex === node.leafIndex && !node.isDuplicated;
          const hiddenMobile =
            depth > 0 &&
            depth < levels.length - 1 &&
            !isSelected &&
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

          // Full hash and role exposed to assistive tech; the visible label is truncated.
          const describe = `${caption}, hash ${node.hash}${isTampered ? ', tampered' : ''}`;

          if (isSelectableLeaf) {
            const label = `Select ${caption} for proof. ${describe}`;
            return `<button
                type="button"
                class="${treeNodeClass(node, depth, hiddenMobile)}"
                data-leaf-index="${node.leafIndex}"
                aria-pressed="${isSelected ? 'true' : 'false'}"
                aria-label="${escapeHtml(label)}">
              <span class="tree-caption">${caption}</span>
              <span class="tree-hash" aria-hidden="true">${node.hash.slice(0, 8)}...</span>
              ${leafData}
              ${tamperBadge}
            </button>`;
          }

          return `<div
              class="${treeNodeClass(node, depth, hiddenMobile)}"
              role="group"
              aria-label="${escapeHtml(describe)}">
            <span class="tree-caption">${caption}</span>
            <span class="tree-hash" aria-hidden="true">${node.hash.slice(0, 8)}...</span>
            ${tamperBadge}
          </div>`;
        })
        .join('');

      const levelLabel =
        depth === 0 ? 'Root level' : depth === levels.length - 1 ? 'Leaf level' : `Level ${depth}`;
      return `<div class="tree-level level-${depth}" role="group" aria-label="${levelLabel}">${html}</div>`;
    })
    .join('');
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
      (sibling, index) => `<li>
        <span class="proof-index">Level ${index + 1} (${sibling.position})</span>
        <span class="mono">${sibling.hash}</span>
      </li>`,
    )
    .join('');

  const steps = state.proofSteps
    .map(
      (step) => `<li>
        <span class="proof-index">Step ${step.level}</span>
        <span class="mono">H(0x01 || ${step.left.slice(0, 8)}... || ${step.right.slice(0, 8)}...) = ${step.result}</span>
      </li>`,
    )
    .join('');

  const status =
    state.proofValid === true
      ? '<p class="proof-valid"><span aria-hidden="true">✅</span> PROOF VALID</p>'
      : '<p class="proof-invalid"><span aria-hidden="true">❌</span> PROOF INVALID</p>';

  return `
    <div class="proof-block">
      <p><strong>Leaf hash:</strong></p>
      <p class="mono wrap">${state.proof.leafHash}</p>
      <p><strong>Siblings:</strong></p>
      <ol class="proof-list">${siblings}</ol>
      <p><strong>Root recomputation:</strong></p>
      <ol class="proof-list">${steps}</ol>
      <p class="root-row">
        <strong>Expected root:</strong>
        <span class="mono wrap" id="root-hash">${state.proof.root}</span>
        <button type="button" class="copy-btn" data-copy="${state.proof.root}" aria-label="Copy root hash to clipboard">
          <span aria-hidden="true">Copy</span>
        </button>
      </p>
      <div role="status" aria-live="polite" class="proof-status">${status}</div>
      <p class="proof-size">${proofSummary()}</p>
    </div>
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

  const duplicateNote =
    state.leaves.length % 2 === 1
      ? '<p class="notice">Odd leaf count detected. The last leaf will be duplicated before hashing (Bitcoin convention).</p>'
      : '<p class="notice">Even leaf count: no leaf duplication required at the first level.</p>';

  app!.innerHTML = `
    <main class="page" id="main" tabindex="-1">
      <header class="hero-header">
        <div class="hero-top">
          <p class="eyebrow">crypto-lab</p>
          <button id="theme-toggle" class="theme-toggle" type="button" aria-pressed="false">
            <span class="theme-toggle-icon" aria-hidden="true"></span>
          </button>
        </div>
        <h1>Merkle Vault</h1>
        <p class="lede">Build a binary Merkle tree with real SHA-256 via Web Crypto, generate inclusion proofs, and test tamper detection.</p>
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
        <label for="leaf-input">Leaf data (one item per line, 2-16 leaves)</label>
        <textarea id="leaf-input" rows="8">${escapeHtml(state.textareaValue)}</textarea>
        <div class="meta-row">
          <p>Leaf count: <strong>${state.leaves.length}</strong></p>
          ${duplicateNote}
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
      announce(`${preset.label} preset loaded with ${preset.items.length} leaves.`);
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
    state.tree = await buildMerkleTree(state.leaves);
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
    announce(
      `Proof generated for leaf ${state.selectedLeafIndex} with ${state.proof.siblings.length} sibling hashes. Proof is ${state.proofValid ? 'valid' : 'invalid'}.`,
    );
    renderApp();
    scrollIntoViewIfNeeded('.proof-panel');
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
    announce('Original data restored. The tree is back to its untampered state.');
    renderApp();
  });

  document.querySelectorAll<HTMLButtonElement>('[data-leaf-index]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const value = Number.parseInt(btn.dataset.leafIndex ?? '0', 10);
      state.selectedLeafIndex = value;
      announce(`Leaf ${value} selected as proof target.`);
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
}

async function bootstrap(): Promise<void> {
  state.tree = await buildMerkleTree(state.leaves);
  state.originalTree = state.tree;
  renderApp();
}

bootstrap();
