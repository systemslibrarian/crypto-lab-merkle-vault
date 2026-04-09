export interface MerkleNode {
  hash: string;
  left?: MerkleNode;
  right?: MerkleNode;
  isLeaf: boolean;
  leafIndex?: number;
  isDuplicated?: boolean;
}

export interface MerkleTree {
  root: MerkleNode;
  leaves: MerkleNode[];
  depth: number;
  leafCount: number;
}

export interface InclusionProof {
  leafIndex: number;
  leafHash: string;
  siblings: Array<{ hash: string; position: 'left' | 'right' }>;
  root: string;
}

interface TreeMetadata {
  parents: WeakMap<MerkleNode, MerkleNode | null>;
  originalLeaves: string[];
}

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

async function hashLeaf(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const payload = encoder.encode(data);
  const prefixed = concatBytes(new Uint8Array([0x00]), payload);
  return sha256hex(prefixed);
}

async function hashInternal(leftHex: string, rightHex: string): Promise<string> {
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

export async function buildMerkleTree(leaves: string[]): Promise<MerkleTree> {
  if (leaves.length < 2) {
    throw new Error('At least 2 leaves are required.');
  }

  const hashedLeaves: MerkleNode[] = await Promise.all(
    leaves.map(async (leafData, index) => ({
      hash: await hashLeaf(leafData),
      isLeaf: true,
      leafIndex: index,
    })),
  );

  const parents = new WeakMap<MerkleNode, MerkleNode | null>();
  for (const leaf of hashedLeaves) {
    parents.set(leaf, null);
  }

  let currentLevel: MerkleNode[] = hashedLeaves.slice();
  let depth = 0;

  while (currentLevel.length > 1) {
    const nextLevel: MerkleNode[] = [];

    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      const rightSource = currentLevel[i + 1] ?? currentLevel[i];
      const right = currentLevel[i + 1]
        ? rightSource
        : {
            ...rightSource,
            isDuplicated: true,
          };

      const parent: MerkleNode = {
        hash: await hashInternal(left.hash, right.hash),
        left,
        right,
        isLeaf: false,
      };

      parents.set(parent, null);
      parents.set(left, parent);
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
  });

  return {
    root,
    leaves: hashedLeaves,
    depth,
    leafCount: leaves.length,
  };
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
  const siblings: InclusionProof['siblings'] = [];

  let current: MerkleNode | undefined = targetLeaf;
  while (current) {
    const parent: MerkleNode | null | undefined = metadata.parents.get(current) ?? null;
    if (!parent) {
      break;
    }

    const left = parent.left;
    const right = parent.right;

    if (!left || !right) {
      throw new Error('Malformed tree structure.');
    }

    if (left === current) {
      siblings.push({ hash: right.hash, position: 'right' });
    } else if (right === current) {
      siblings.push({ hash: left.hash, position: 'left' });
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
  return buildMerkleTree(nextLeaves);
}
