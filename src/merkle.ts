/**
 * merkle.ts — Binary Merkle trees + inclusion proofs with real SHA-256.
 *
 * Every digest goes through crypto.subtle.digest (WebCrypto/SubtleCrypto).
 * Nothing here simulates or shortcuts the hash.
 *
 * Domain separation (RFC 6962 §2.1):
 *   leaf hash = SHA-256(0x00 || data)
 *   node hash = SHA-256(0x01 || left || right)
 * The 0x00 / 0x01 prefixes keep leaf hashes and internal-node hashes in
 * disjoint input spaces, defending the second-preimage / node-confusion attack.
 *
 * Odd-node handling is SELECTABLE (see OddMode):
 *   - 'promote'   (default, RFC 6962) — carry the lone node up UNCHANGED.
 *   - 'duplicate' (Bitcoin)           — hash the lone node with a copy of
 *                                        itself, SHA-256(0x01 || x || x).
 * The default is the safe RFC 6962 behavior. 'duplicate' exists so the demo
 * can show the CVE-2012-2459 block-malleability bug it caused (two different
 * leaf lists collide on the same root).
 */

export type OddMode = 'promote' | 'duplicate';

export interface MerkleNode {
  hash: string;
  left?: MerkleNode;
  right?: MerkleNode;
  isLeaf: boolean;
  leafIndex?: number;
  /**
   * True when this node is the self-copy of its sibling under Bitcoin
   * 'duplicate' mode (i.e. right === a clone of left). Only meaningful for the
   * duplicated child in an odd internal pairing.
   */
  isDuplicated?: boolean;
  /**
   * True when this is a pass-through node created by RFC 6962 'promote' mode:
   * a lone node carried up a level unchanged. It has exactly one child and the
   * same hash as that child. It contributes no sibling to a proof.
   */
  isPromoted?: boolean;
}

export interface MerkleTree {
  root: MerkleNode;
  leaves: MerkleNode[];
  depth: number;
  leafCount: number;
  oddMode: OddMode;
}

export interface ProofStep {
  hash: string;
  position: 'left' | 'right';
  /**
   * True when this sibling hash is a self-copy of the target's own subtree
   * (only happens in Bitcoin 'duplicate' mode at an odd boundary). Such a step
   * is the "odd-leaf duplication leak": the sibling carries no independent
   * data, so a verifier that ignores tree size can be tricked (CVE-2012-2459).
   */
  isSelfCopy: boolean;
}

export interface InclusionProof {
  leafIndex: number;
  leafHash: string;
  siblings: ProofStep[];
  root: string;
  oddMode: OddMode;
  /** True if any step in the proof is a self-copy sibling (see ProofStep). */
  usesDuplicatedSibling: boolean;
}

interface TreeMetadata {
  parents: WeakMap<MerkleNode, MerkleNode | null>;
  originalLeaves: string[];
  oddMode: OddMode;
}

/** RFC 6962 §2.1: the Merkle Tree Hash of the empty list is SHA-256(""). */
export const EMPTY_TREE_ROOT =
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

const metadataByRoot = new WeakMap<MerkleNode, TreeMetadata>();

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string length.');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const size = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

async function sha256hex(data: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', data as Uint8Array<ArrayBuffer>);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function hashLeaf(data: string): Promise<string> {
  const payload = new TextEncoder().encode(data);
  const prefixed = concatBytes(new Uint8Array([0x00]), payload);
  return sha256hex(prefixed);
}

export async function hashInternal(leftHex: string, rightHex: string): Promise<string> {
  const prefixed = concatBytes(
    new Uint8Array([0x01]),
    hexToBytes(leftHex),
    hexToBytes(rightHex),
  );
  return sha256hex(prefixed);
}

function getTreeMetadata(tree: MerkleTree): TreeMetadata {
  const metadata = metadataByRoot.get(tree.root);
  if (!metadata) {
    throw new Error('Merkle tree metadata missing. Build the tree with buildMerkleTree().');
  }
  return metadata;
}

/**
 * Build a Merkle tree from leaf payload strings.
 *
 * - 0 leaves: RFC 6962 empty-tree root = SHA-256("").
 * - 1 leaf:   the leaf hash is the root.
 * - odd internal levels: handled per `oddMode` (default RFC 6962 'promote').
 */
export async function buildMerkleTree(
  leaves: string[],
  oddMode: OddMode = 'promote',
): Promise<MerkleTree> {
  const parents = new WeakMap<MerkleNode, MerkleNode | null>();

  if (leaves.length === 0) {
    const root: MerkleNode = { hash: EMPTY_TREE_ROOT, isLeaf: false };
    parents.set(root, null);
    metadataByRoot.set(root, { parents, originalLeaves: [], oddMode });
    return { root, leaves: [], depth: 0, leafCount: 0, oddMode };
  }

  const hashedLeaves: MerkleNode[] = await Promise.all(
    leaves.map(async (leafData, index) => ({
      hash: await hashLeaf(leafData),
      isLeaf: true,
      leafIndex: index,
    })),
  );
  for (const leaf of hashedLeaves) {
    parents.set(leaf, null);
  }

  let currentLevel: MerkleNode[] = hashedLeaves.slice();
  let depth = 0;

  while (currentLevel.length > 1) {
    const nextLevel: MerkleNode[] = [];

    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      const hasRight = currentLevel[i + 1] !== undefined;

      if (!hasRight && oddMode === 'promote') {
        // RFC 6962: carry the lone node up unchanged. Model it as a
        // single-child pass-through so the parent map stays unambiguous and no
        // sibling is emitted for this rise.
        const promoted: MerkleNode = {
          hash: left.hash,
          left,
          isLeaf: false,
          isPromoted: true,
        };
        parents.set(promoted, null);
        parents.set(left, promoted);
        nextLevel.push(promoted);
        continue;
      }

      // Bitcoin 'duplicate' for the lone node: pair it with a self-copy.
      const right = hasRight
        ? currentLevel[i + 1]
        : { ...left, isDuplicated: true };

      const parent: MerkleNode = {
        hash: await hashInternal(left.hash, right.hash),
        left,
        right,
        isLeaf: false,
      };
      parents.set(parent, null);
      parents.set(left, parent);
      // The self-copy is a fresh node object; give it its own parent entry.
      parents.set(right, parent);
      nextLevel.push(parent);
    }

    currentLevel = nextLevel;
    depth += 1;
  }

  const root = currentLevel[0];
  metadataByRoot.set(root, {
    parents,
    originalLeaves: leaves.slice(),
    oddMode,
  });

  return { root, leaves: hashedLeaves, depth, leafCount: leaves.length, oddMode };
}

export async function generateProof(
  tree: MerkleTree,
  leafIndex: number,
): Promise<InclusionProof> {
  if (leafIndex < 0 || leafIndex >= tree.leafCount) {
    throw new Error('Leaf index out of range.');
  }

  const metadata = getTreeMetadata(tree);
  const targetLeaf = tree.leaves[leafIndex];
  const siblings: ProofStep[] = [];

  let current: MerkleNode | undefined = targetLeaf;
  while (current) {
    const parent: MerkleNode | null | undefined = metadata.parents.get(current) ?? null;
    if (!parent) {
      break;
    }

    // RFC 6962 promoted (pass-through) parents contribute NO sibling: the node
    // simply rises a level. Skip straight to the next real pairing.
    if (parent.isPromoted) {
      current = parent;
      continue;
    }

    const left = parent.left;
    const right = parent.right;
    if (!left || !right) {
      throw new Error('Malformed tree structure.');
    }

    if (left === current) {
      siblings.push({
        hash: right.hash,
        position: 'right',
        // In duplicate mode the right child is a self-copy of the left.
        isSelfCopy: right.isDuplicated === true,
      });
    } else if (right === current) {
      siblings.push({ hash: left.hash, position: 'left', isSelfCopy: false });
    } else {
      throw new Error('Malformed parent relationship.');
    }

    current = parent;
  }

  return {
    leafIndex,
    leafHash: targetLeaf.hash,
    siblings,
    root: tree.root.hash,
    oddMode: tree.oddMode,
    usesDuplicatedSibling: siblings.some((s) => s.isSelfCopy),
  };
}

export async function verifyProof(proof: InclusionProof): Promise<boolean> {
  let currentHash = proof.leafHash;

  for (const sibling of proof.siblings) {
    if (sibling.position === 'left') {
      currentHash = await hashInternal(sibling.hash, currentHash);
    } else {
      currentHash = await hashInternal(currentHash, sibling.hash);
    }
  }

  return currentHash === proof.root;
}

export async function tamperLeaf(
  tree: MerkleTree,
  leafIndex: number,
  newData: string,
): Promise<MerkleTree> {
  if (leafIndex < 0 || leafIndex >= tree.leafCount) {
    throw new Error('Leaf index out of range.');
  }

  const metadata = getTreeMetadata(tree);
  const nextLeaves = metadata.originalLeaves.slice();
  nextLeaves[leafIndex] = newData;
  return buildMerkleTree(nextLeaves, metadata.oddMode);
}
