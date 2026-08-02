/**
 * consistency.ts — RFC 6962 §2.1.2 consistency (append-only) proofs.
 *
 * An inclusion proof answers "is this item in the tree the log published?".
 * A consistency proof answers the question a log auditor actually has: "is the
 * tree the log is publishing NOW an append-only extension of the one it
 * published BEFORE — or did it quietly rewrite history?" Certificate
 * Transparency runs on exactly this, and it is the one Merkle idea this demo
 * named in its own "When to Use It" list and never showed.
 *
 * The Merkle Tree Hash is the recursive RFC 6962 definition:
 *
 *   MTH({})     = SHA-256("")
 *   MTH({d0})   = SHA-256(0x00 ‖ d0)
 *   MTH(D[n])   = SHA-256(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n]))
 *                 where k is the largest power of two strictly less than n
 *
 * That is a different-looking construction from the level-by-level builder in
 * merkle.ts, which pairs bottom-up and promotes a lone node. The two agree on
 * every input — `tests/consistency.test.ts` checks that against the real tree
 * builder rather than taking it on faith — but this file follows the RFC's own
 * recursion so the proof algorithm below can be read straight against §2.1.2.
 *
 * Everything here hashes with RFC 6962 domain separation. A consistency proof
 * over a tree built without the prefixes would be defending a construction that
 * is already forgeable; see mountSecondPreimageAttack() in merkle.ts for that.
 */

import { EMPTY_TREE_ROOT, hashInternal, hashLeaf } from './merkle';

function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k * 2 < n) {
    k *= 2;
  }
  return k;
}

function isPowerOfTwo(n: number): boolean {
  return n > 0 && (n & (n - 1)) === 0;
}

export async function leafHashes(entries: string[]): Promise<string[]> {
  return Promise.all(entries.map((entry) => hashLeaf(entry)));
}

/** RFC 6962 Merkle Tree Hash over already-hashed leaves. */
export async function merkleTreeHash(hashes: string[]): Promise<string> {
  if (hashes.length === 0) {
    return EMPTY_TREE_ROOT;
  }
  if (hashes.length === 1) {
    return hashes[0];
  }
  const k = largestPowerOfTwoBelow(hashes.length);
  const left = await merkleTreeHash(hashes.slice(0, k));
  const right = await merkleTreeHash(hashes.slice(k));
  return hashInternal(left, right);
}

export async function rootOf(entries: string[]): Promise<string> {
  return merkleTreeHash(await leafHashes(entries));
}

/** RFC 6962 §2.1.2 SUBPROOF(m, D[n], b). */
async function subproof(m: number, hashes: string[], b: boolean): Promise<string[]> {
  const n = hashes.length;
  if (m === n) {
    // The proof for a prefix that is the whole tree is empty when the caller
    // already knows that root (b = true), and is the root itself otherwise.
    return b ? [] : [await merkleTreeHash(hashes)];
  }
  const k = largestPowerOfTwoBelow(n);
  if (m <= k) {
    const inner = await subproof(m, hashes.slice(0, k), b);
    inner.push(await merkleTreeHash(hashes.slice(k)));
    return inner;
  }
  const inner = await subproof(m - k, hashes.slice(k), false);
  inner.push(await merkleTreeHash(hashes.slice(0, k)));
  return inner;
}

/**
 * PROOF(m, D[n]): the hashes an auditor needs to confirm that the size-m tree
 * is a prefix of the size-n tree. Empty when m === n.
 */
export async function consistencyProof(entries: string[], m: number): Promise<string[]> {
  if (!Number.isInteger(m) || m < 1 || m > entries.length) {
    throw new RangeError(`Prefix size must be an integer in 1..${entries.length}, got ${m}`);
  }
  return subproof(m, await leafHashes(entries), true);
}

export interface ConsistencyCheck {
  ok: boolean;
  /** The old root the proof actually reconstructs — the point of the check. */
  reconstructedOldRoot: string | null;
  /** The new root the same hashes reconstruct. */
  reconstructedNewRoot: string | null;
  /** Why it failed, in the auditor's terms. Empty when ok. */
  reason: string;
}

/**
 * RFC 9162 §2.1.4.2 verification, reporting what it rebuilt as well as whether
 * it matched. A bare boolean would make the demo assert its own conclusion; the
 * reconstructed roots let the page show *why* a rewritten history is caught —
 * the proof rebuilds some other old root, not the one the auditor is holding.
 */
export async function verifyConsistencyProof(
  m: number,
  n: number,
  oldRoot: string,
  newRoot: string,
  proof: string[],
): Promise<ConsistencyCheck> {
  const fail = (reason: string): ConsistencyCheck => ({
    ok: false,
    reconstructedOldRoot: null,
    reconstructedNewRoot: null,
    reason,
  });

  if (!Number.isInteger(m) || !Number.isInteger(n) || m < 1) {
    return fail('Tree sizes must be positive integers.');
  }
  if (m > n) {
    return fail(
      `The log now claims ${n} entries, fewer than the ${m} it had already committed to. A log that shrinks has not appended — it has deleted.`,
    );
  }
  if (m === n) {
    return oldRoot === newRoot
      ? {
          ok: true,
          reconstructedOldRoot: oldRoot,
          reconstructedNewRoot: newRoot,
          reason: '',
        }
      : fail('Same tree size but a different root: the log rewrote history in place.');
  }

  let path = proof.slice();
  if (isPowerOfTwo(m)) {
    // RFC 9162: when m is a power of two the old root is itself the first node
    // on the path, and the log omits it because the auditor already has it.
    path = [oldRoot, ...path];
  }
  if (path.length === 0) {
    return fail('Empty consistency proof for a tree that grew.');
  }

  let fn = m - 1;
  let sn = n - 1;
  while (fn % 2 === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  let fr = path[0];
  let sr = path[0];
  for (let i = 1; i < path.length; i += 1) {
    const c = path[i];
    if (sn === 0) {
      return fail('Consistency proof is longer than the new tree can justify.');
    }
    if (fn % 2 === 1 || fn === sn) {
      fr = await hashInternal(c, fr);
      sr = await hashInternal(c, sr);
      while (fn !== 0 && fn % 2 === 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      sr = await hashInternal(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  if (sn !== 0) {
    return fail('Consistency proof is too short to reach the new root.');
  }
  if (fr !== oldRoot) {
    return {
      ok: false,
      reconstructedOldRoot: fr,
      reconstructedNewRoot: sr,
      reason:
        'The proof rebuilds a DIFFERENT old root from the one already committed — the first ' +
        String(m) +
        ' entries are not the entries the log published before.',
    };
  }
  if (sr !== newRoot) {
    return {
      ok: false,
      reconstructedOldRoot: fr,
      reconstructedNewRoot: sr,
      reason:
        'Replayed on top of the old root the auditor already holds, the proof does not rebuild ' +
        'the new root the log is advertising — so the tree the log is publishing now is not an ' +
        'extension of the tree it committed to before.',
    };
  }
  return { ok: true, reconstructedOldRoot: fr, reconstructedNewRoot: sr, reason: '' };
}
