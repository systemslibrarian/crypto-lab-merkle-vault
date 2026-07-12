import { describe, it, expect } from 'vitest';
import {
  buildMerkleTree,
  generateProof,
  verifyProof,
  tamperLeaf,
  hashLeaf,
  hashInternal,
  EMPTY_TREE_ROOT,
  type MerkleTree,
  type OddMode,
} from '../src/merkle';

const SAMPLE = ['alice', 'bob', 'carol', 'dave', 'erin', 'frank', 'grace'];

async function sha256hex(data: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

describe('domain-separated hashing (RFC 6962 §2.1)', () => {
  it('leaf hash = SHA-256(0x00 || data)', async () => {
    const data = 'x';
    expect(await hashLeaf(data)).toBe(
      await sha256hex(concat(Uint8Array.of(0x00), utf8(data))),
    );
  });

  it('internal hash = SHA-256(0x01 || left || right)', async () => {
    const la = await hashLeaf('a');
    const lb = await hashLeaf('b');
    const laBytes = Uint8Array.from(la.match(/../g)!.map((h) => parseInt(h, 16)));
    const lbBytes = Uint8Array.from(lb.match(/../g)!.map((h) => parseInt(h, 16)));
    expect(await hashInternal(la, lb)).toBe(
      await sha256hex(concat(Uint8Array.of(0x01), laBytes, lbBytes)),
    );
  });

  it('leaf and internal spaces are disjoint (prefixes differ)', async () => {
    // Same 32-byte payload, different domain prefix => different digest. This
    // is exactly what defeats the second-preimage / node-confusion attack.
    const h = await hashLeaf('payload');
    const asLeaf = await hashLeaf(h);
    // Interpreting an internal-node concatenation cannot equal a leaf hash of
    // the same bytes because of the 0x00 vs 0x01 prefix.
    expect(asLeaf).not.toBe(h);
  });
});

describe('RFC 6962 known-answer vectors', () => {
  it('empty tree root is SHA-256("")', async () => {
    const tree = await buildMerkleTree([]);
    expect(tree.root.hash).toBe(EMPTY_TREE_ROOT);
    expect(tree.root.hash).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
    expect(tree.leafCount).toBe(0);
  });

  it('single empty leaf root is SHA-256(0x00)', async () => {
    const tree = await buildMerkleTree(['']);
    expect(tree.root.hash).toBe(
      '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
    );
  });

  it('single non-empty leaf root is its own leaf hash', async () => {
    const tree = await buildMerkleTree(['solo']);
    expect(tree.root.hash).toBe(await hashLeaf('solo'));
    expect(tree.depth).toBe(0);
  });
});

describe('tree construction matches an independent hand recomputation', () => {
  it('4 leaves', async () => {
    const tree = await buildMerkleTree(['a', 'b', 'c', 'd']);
    const la = await hashLeaf('a');
    const lb = await hashLeaf('b');
    const lc = await hashLeaf('c');
    const ld = await hashLeaf('d');
    const nab = await hashInternal(la, lb);
    const ncd = await hashInternal(lc, ld);
    const root = await hashInternal(nab, ncd);
    expect(tree.root.hash).toBe(root);
  });

  it('promotes a lone odd node (RFC 6962), NOT hash(c,c)', async () => {
    const tree = await buildMerkleTree(['a', 'b', 'c']); // default promote
    const la = await hashLeaf('a');
    const lb = await hashLeaf('b');
    const lc = await hashLeaf('c');
    const nab = await hashInternal(la, lb);
    const root = await hashInternal(nab, lc); // c promoted unchanged
    expect(tree.root.hash).toBe(root);
    expect(tree.oddMode).toBe('promote');
  });

  it('duplicate mode hashes the lone node with a copy of itself', async () => {
    const tree = await buildMerkleTree(['a', 'b', 'c'], 'duplicate');
    const la = await hashLeaf('a');
    const lb = await hashLeaf('b');
    const lc = await hashLeaf('c');
    const nab = await hashInternal(la, lb);
    const ncc = await hashInternal(lc, lc); // self-copy
    const root = await hashInternal(nab, ncc);
    expect(tree.root.hash).toBe(root);
  });

  it('is deterministic and order-sensitive', async () => {
    const t1 = await buildMerkleTree(['a', 'b', 'c']);
    const t2 = await buildMerkleTree(['a', 'b', 'c']);
    const t3 = await buildMerkleTree(['b', 'a', 'c']);
    expect(t1.root.hash).toBe(t2.root.hash);
    expect(t1.root.hash).not.toBe(t3.root.hash);
  });
});

describe('proof generation + verification round-trip', () => {
  for (const mode of ['promote', 'duplicate'] as OddMode[]) {
    for (const n of [1, 2, 3, 4, 5, 7, 8, 16]) {
      it(`[${mode}] every leaf of an ${n}-leaf tree yields a verifying proof`, async () => {
        const items = Array.from({ length: n }, (_, i) => `item-${i}`);
        const tree = await buildMerkleTree(items, mode);
        for (let i = 0; i < n; i++) {
          const proof = await generateProof(tree, i);
          expect(proof.root).toBe(tree.root.hash);
          expect(await verifyProof(proof), `leaf ${i} of ${n}`).toBe(true);
          // proof never longer than the tree height
          expect(proof.siblings.length).toBeLessThanOrEqual(tree.depth);
        }
      });
    }
  }

  it('power-of-two trees give every leaf exactly log2(n) steps', async () => {
    const tree = await buildMerkleTree(Array.from({ length: 8 }, (_, i) => `${i}`));
    for (let i = 0; i < 8; i++) {
      expect((await generateProof(tree, i)).siblings.length).toBe(3);
    }
  });

  it('out-of-range leaf index throws', async () => {
    const tree = await buildMerkleTree(['a', 'b']);
    await expect(generateProof(tree, 5)).rejects.toThrow();
    await expect(generateProof(tree, -1)).rejects.toThrow();
  });
});

describe('tamper / forgery detection', () => {
  it('a modified leaf changes the root and invalidates the old proof', async () => {
    const tree = await buildMerkleTree(SAMPLE);
    const proof = await generateProof(tree, 2);
    expect(await verifyProof(proof)).toBe(true);

    const tampered = await tamperLeaf(tree, 2, 'mallory');
    expect(tampered.root.hash).not.toBe(tree.root.hash);
    // The old proof, re-pointed at the new root, must fail.
    expect(await verifyProof({ ...proof, root: tampered.root.hash })).toBe(false);
  });

  it('rejects a flipped bit in a proof sibling', async () => {
    const tree = await buildMerkleTree(SAMPLE);
    const proof = await generateProof(tree, 2);
    const siblings = proof.siblings.map((s) => ({ ...s }));
    // Flip the first hex nibble of the first sibling.
    const first = siblings[0].hash;
    const flipped = (first[0] === '0' ? '1' : '0') + first.slice(1);
    siblings[0] = { ...siblings[0], hash: flipped };
    expect(await verifyProof({ ...proof, siblings })).toBe(false);
  });

  it('rejects a swapped sibling side', async () => {
    const tree = await buildMerkleTree(SAMPLE);
    const proof = await generateProof(tree, 1);
    const siblings = proof.siblings.map((s, i) =>
      i === 0 ? { ...s, position: s.position === 'left' ? ('right' as const) : ('left' as const) } : s,
    );
    expect(await verifyProof({ ...proof, siblings })).toBe(false);
  });

  it('rejects a proof against the wrong root', async () => {
    const tree = await buildMerkleTree(SAMPLE);
    const other = await buildMerkleTree(['x', 'y', 'z', 'w']);
    const proof = await generateProof(tree, 0);
    expect(await verifyProof({ ...proof, root: other.root.hash })).toBe(false);
  });
});

describe('odd-node handling: Bitcoin duplication (CVE-2012-2459) vs RFC 6962 promotion', () => {
  it('duplication makes [a,b,c] and [a,b,c,c] COLLIDE on the same root', async () => {
    const t3 = await buildMerkleTree(['a', 'b', 'c'], 'duplicate');
    const t4 = await buildMerkleTree(['a', 'b', 'c', 'c'], 'duplicate');
    expect(t3.root.hash).toBe(t4.root.hash); // the malleability bug
  });

  it('promotion (RFC 6962, the default) does NOT collide — the bug is fixed', async () => {
    const t3 = await buildMerkleTree(['a', 'b', 'c'], 'promote');
    const t4 = await buildMerkleTree(['a', 'b', 'c', 'c'], 'promote');
    expect(t3.root.hash).not.toBe(t4.root.hash);
  });

  it('a duplicate-mode proof at the odd boundary is flagged as using a self-copy sibling', async () => {
    // 3 leaves in duplicate mode: leaf 2 pairs with a copy of itself.
    const tree = await buildMerkleTree(['a', 'b', 'c'], 'duplicate');
    const proof = await generateProof(tree, 2);
    expect(proof.usesDuplicatedSibling).toBe(true);
    expect(proof.siblings.some((s) => s.isSelfCopy)).toBe(true);
  });

  it('promote-mode proofs never use a self-copy sibling', async () => {
    const tree = await buildMerkleTree(['a', 'b', 'c', 'd', 'e'], 'promote');
    for (let i = 0; i < 5; i++) {
      const proof = await generateProof(tree, i);
      expect(proof.usesDuplicatedSibling, `leaf ${i}`).toBe(false);
    }
  });
});

describe('fuzz: agreement with an independent recursive RFC 6962 reference', () => {
  // Deterministic LCG so any failure reproduces.
  let seed = 0x9e3779b9;
  const rand = (): number => {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed / 0x100000000;
  };
  const randInt = (n: number): number => Math.floor(rand() * n);

  // Independent reference: the RECURSIVE RFC 6962 §2.1 Merkle Tree Hash
  // (split at the largest power of two < n). Structurally different from
  // buildMerkleTree's iterative level pairing, so a shared bug can't hide.
  async function mthRFC6962(items: string[]): Promise<string> {
    if (items.length === 0) return EMPTY_TREE_ROOT;
    if (items.length === 1) return hashLeaf(items[0]);
    let k = 1;
    while (k * 2 < items.length) k *= 2;
    const left = await mthRFC6962(items.slice(0, k));
    const right = await mthRFC6962(items.slice(k));
    return hashInternal(left, right);
  }

  it('50 random promote-mode trees match the recursive reference; proofs verify', async () => {
    for (let t = 0; t < 50; t++) {
      const n = 1 + randInt(40);
      const items = Array.from({ length: n }, () => `x${randInt(1000)}-${randInt(1000)}`);
      const tree: MerkleTree = await buildMerkleTree(items, 'promote');
      expect(tree.root.hash, `n=${n}`).toBe(await mthRFC6962(items));

      const idx = randInt(n);
      const proof = await generateProof(tree, idx);
      expect(await verifyProof(proof), `proof leaf ${idx} of ${n}`).toBe(true);
    }
  });

  it('30 random duplicate-mode trees: every proof round-trips against the root', async () => {
    for (let t = 0; t < 30; t++) {
      const n = 1 + randInt(30);
      const items = Array.from({ length: n }, () => `d${randInt(1000)}-${randInt(1000)}`);
      const tree = await buildMerkleTree(items, 'duplicate');
      for (let i = 0; i < n; i++) {
        const proof = await generateProof(tree, i);
        expect(await verifyProof(proof), `dup n=${n} leaf ${i}`).toBe(true);
      }
    }
  });
});
