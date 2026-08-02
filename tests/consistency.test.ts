import { describe, it, expect } from 'vitest';
import { buildMerkleTree, hashInternal, hashLeaf, EMPTY_TREE_ROOT } from '../src/merkle';
import {
  consistencyProof,
  leafHashes,
  merkleTreeHash,
  rootOf,
  verifyConsistencyProof,
} from '../src/consistency';

const LOG = [
  'cert 0001 — example.com',
  'cert 0002 — example.org',
  'cert 0003 — example.net',
  'cert 0004 — sub.example.com',
  'cert 0005 — api.example.com',
  'cert 0006 — mail.example.org',
  'cert 0007 — cdn.example.net',
  'cert 0008 — shop.example.com',
  'cert 0009 — blog.example.org',
  'cert 0010 — status.example.net',
  'cert 0011 — dev.example.com',
];

describe('RFC 6962 Merkle Tree Hash', () => {
  it('matches SHA-256("") for the empty list', async () => {
    expect(await merkleTreeHash([])).toBe(EMPTY_TREE_ROOT);
  });

  it('is the leaf hash itself for a single entry', async () => {
    expect(await rootOf(['solo'])).toBe(await hashLeaf('solo'));
  });

  it('matches the hand-expanded definition for two and three entries', async () => {
    const [h0, h1, h2] = await leafHashes(['a', 'b', 'c']);
    expect(await rootOf(['a', 'b'])).toBe(await hashInternal(h0, h1));
    // n = 3 splits at k = 2: H(0x01 ‖ MTH([a,b]) ‖ MTH([c])).
    expect(await rootOf(['a', 'b', 'c'])).toBe(
      await hashInternal(await hashInternal(h0, h1), h2),
    );
  });

  it('agrees with the level-by-level tree builder on every size up to 24', async () => {
    // The two constructions are written differently — recursive split at the
    // largest power of two here, bottom-up pairing with promotion in merkle.ts.
    // This is the check that they are the same function, not an assumption.
    for (let n = 1; n <= 24; n += 1) {
      const entries = LOG.concat(
        Array.from({ length: 24 }, (_, i) => `filler ${i}`),
      ).slice(0, n);
      const tree = await buildMerkleTree(entries, 'promote');
      expect(await rootOf(entries), `n = ${n}`).toBe(tree.root.hash);
    }
  });
});

describe('consistency (append-only) proofs', () => {
  it('is empty when nothing was appended, and verifies', async () => {
    const proof = await consistencyProof(LOG, LOG.length);
    expect(proof).toEqual([]);
    const root = await rootOf(LOG);
    const check = await verifyConsistencyProof(LOG.length, LOG.length, root, root, proof);
    expect(check.ok).toBe(true);
  });

  it('verifies every prefix of every log size up to 20', async () => {
    const entries = LOG.concat(Array.from({ length: 12 }, (_, i) => `extra ${i}`));
    for (let n = 1; n <= 20; n += 1) {
      const newLog = entries.slice(0, n);
      const newRoot = await rootOf(newLog);
      for (let m = 1; m <= n; m += 1) {
        const oldRoot = await rootOf(newLog.slice(0, m));
        const proof = await consistencyProof(newLog, m);
        const check = await verifyConsistencyProof(m, n, oldRoot, newRoot, proof);
        expect(check.ok, `m = ${m}, n = ${n}: ${check.reason}`).toBe(true);
        expect(check.reconstructedOldRoot).toBe(oldRoot);
        expect(check.reconstructedNewRoot).toBe(newRoot);
      }
    }
  });

  it('stays logarithmic in the log size', async () => {
    const entries = Array.from({ length: 256 }, (_, i) => `entry ${i}`);
    const proof = await consistencyProof(entries, 100);
    // RFC 6962 bounds the proof at ceil(log2 n) + 1 hashes.
    expect(proof.length).toBeLessThanOrEqual(Math.ceil(Math.log2(256)) + 1);
    const check = await verifyConsistencyProof(
      100,
      256,
      await rootOf(entries.slice(0, 100)),
      await rootOf(entries),
      proof,
    );
    expect(check.ok).toBe(true);
  });

  it('catches a rewritten historical entry', async () => {
    const oldLog = LOG.slice(0, 6);
    const oldRoot = await rootOf(oldLog);
    // The log operator quietly edits entry 0, then appends two honest entries.
    const rewritten = oldLog.slice();
    rewritten[0] = 'cert 0001 — attacker.example';
    const newLog = rewritten.concat(['cert 0007 — new', 'cert 0008 — new']);
    const newRoot = await rootOf(newLog);
    const proof = await consistencyProof(newLog, oldLog.length);

    const check = await verifyConsistencyProof(
      oldLog.length,
      newLog.length,
      oldRoot,
      newRoot,
      proof,
    );
    expect(check.ok).toBe(false);
    // It rebuilds *a* prefix root — just not the one the auditor holds.
    expect(check.reconstructedOldRoot).toBe(await rootOf(rewritten));
    expect(check.reconstructedOldRoot).not.toBe(oldRoot);
    expect(check.reason).toContain('DIFFERENT old root');
  });

  it('catches a deleted historical entry even when the log still grows', async () => {
    const oldLog = LOG.slice(0, 6);
    const oldRoot = await rootOf(oldLog);
    const newLog = oldLog
      .filter((_, i) => i !== 1)
      .concat(['cert 0007 — new', 'cert 0008 — new', 'cert 0009 — new']);
    expect(newLog.length).toBeGreaterThan(oldLog.length);
    const check = await verifyConsistencyProof(
      oldLog.length,
      newLog.length,
      oldRoot,
      await rootOf(newLog),
      await consistencyProof(newLog, oldLog.length),
    );
    expect(check.ok).toBe(false);
  });

  it('catches reordered historical entries', async () => {
    const oldLog = LOG.slice(0, 6);
    const oldRoot = await rootOf(oldLog);
    const swapped = oldLog.slice();
    [swapped[0], swapped[1]] = [swapped[1], swapped[0]];
    const newLog = swapped.concat(['cert 0007 — new', 'cert 0008 — new']);
    const check = await verifyConsistencyProof(
      oldLog.length,
      newLog.length,
      oldRoot,
      await rootOf(newLog),
      await consistencyProof(newLog, oldLog.length),
    );
    expect(check.ok).toBe(false);
  });

  it('rejects a log that shrank', async () => {
    const check = await verifyConsistencyProof(
      8,
      5,
      await rootOf(LOG.slice(0, 8)),
      await rootOf(LOG.slice(0, 5)),
      [],
    );
    expect(check.ok).toBe(false);
    expect(check.reason).toContain('deleted');
  });

  it('rejects a same-size tree whose root changed', async () => {
    const a = await rootOf(LOG.slice(0, 6));
    const b = await rootOf(LOG.slice(0, 5).concat(['tampered']));
    const check = await verifyConsistencyProof(6, 6, a, b, []);
    expect(check.ok).toBe(false);
    expect(check.reason).toContain('rewrote history in place');
  });

  it('rejects a proof with a corrupted hash', async () => {
    const oldLog = LOG.slice(0, 5);
    const newLog = LOG.slice(0, 9);
    const proof = await consistencyProof(newLog, 5);
    expect(proof.length).toBeGreaterThan(0);
    const corrupted = proof.slice();
    corrupted[0] = corrupted[0].replace(/^./, (c) => (c === '0' ? '1' : '0'));
    const check = await verifyConsistencyProof(
      5,
      9,
      await rootOf(oldLog),
      await rootOf(newLog),
      corrupted,
    );
    expect(check.ok).toBe(false);
  });

  it('rejects out-of-range prefix sizes at generation time', async () => {
    await expect(consistencyProof(LOG, 0)).rejects.toThrow(RangeError);
    await expect(consistencyProof(LOG, LOG.length + 1)).rejects.toThrow(RangeError);
  });
});
