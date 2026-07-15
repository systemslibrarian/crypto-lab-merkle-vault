# crypto-lab-merkle-vault

[![crypto-lab portfolio](https://img.shields.io/badge/crypto--lab-portfolio-blue?style=flat-square)](https://systemslibrarian.github.io/crypto-lab/)
[![Deploy to GitHub Pages](https://github.com/systemslibrarian/crypto-lab-merkle-vault/actions/workflows/pages.yml/badge.svg)](https://github.com/systemslibrarian/crypto-lab-merkle-vault/actions/workflows/pages.yml)

## What It Is

crypto-lab-merkle-vault implements binary Merkle trees and inclusion proofs using SHA-256 via the Web Crypto API. A Merkle tree is a binary hash tree where leaf nodes contain hashes of data items and internal nodes contain hashes of their children, producing a single root hash that cryptographically commits to the entire dataset. An inclusion proof demonstrates that a specific item is in the tree using only O(log n) hashes - for a million-item dataset, 20 hashes suffice. The security model is collision resistance of SHA-256: an attacker cannot produce a valid proof for an item not in the tree without finding a SHA-256 collision. Domain separation prefixes (0x00 for leaves, 0x01 for internal nodes) prevent second preimage attacks on the tree structure per RFC 6962.

The live tree is **drawn** — SVG connector lines run from every parent node to its two children — and generating a proof **highlights the exact sibling consumed at each level** as the target leaf climbs to the root. A step-by-step **"walk the proof"** mode advances one level at a time, showing the running hash, the sibling being combined, and the resulting parent, with the corresponding tree nodes lighting up in sync — so O(log n) siblings become an internalized mechanism rather than a text list. When the climb reaches the top, the recomputed root and the committed root are shown **side by side and asserted equal byte-for-byte** (turning green on a match, red after a tamper) instead of a bare "VALID" line.

**Odd-node handling is selectable, and the default is the safe one.** When a level has an odd number of nodes, the demo defaults to the RFC 6962 rule — the lone node is *promoted* (carried up unchanged), never duplicated. A "Bitcoin — duplicate" mode is also provided, which instead hashes the lone node with a copy of itself. That Bitcoin convention is the exact CVE-2012-2459 block-malleability pattern: the leaf lists `[a,b,c]` and `[a,b,c,c]` hash to the *same* root. The app computes both roots live from real SHA-256 so you can see the collision appear in Bitcoin mode and disappear in RFC 6962 mode. To keep the core build/prove/tamper loop uncluttered for a first read, the odd-node selector and this malleability demonstration live in a collapsed **"Advanced"** subsection beneath the main loop. This is why the "per RFC 6962" framing above is honest for the default construction, and the vulnerable mode is clearly labelled as such.

## When to Use It

- Use Merkle trees when you need to commit to a large dataset and later prove membership of individual items efficiently - blockchain transactions, certificate logs, software package manifests.
- Use inclusion proofs when verifiers cannot download the full dataset but need cryptographic assurance that a specific item is present.
- Use append-only Merkle logs (as in Certificate Transparency) when you need a tamper-evident audit trail where deletions are detectable.
- Do not use Merkle trees for exclusion proofs without additional structure - proving an item is NOT in a tree requires sorted Merkle trees or accumulators.
- Do not omit domain separation prefixes - the second preimage attack on trees without 0x00/0x01 prefixes is a real structural vulnerability, not a theoretical concern.
- Do NOT treat this as production code - it is a teaching demo for exploring Merkle tree structure and proofs, not a hardened transparency-log library.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-merkle-vault](https://systemslibrarian.github.io/crypto-lab-merkle-vault/)**

Enter up to 16 items (or use the library catalog, Git commits, or transaction presets), build the tree with real SHA-256, select any leaf, and generate an inclusion proof. The tree is drawn with parent→child connector lines, and generating a proof highlights the sibling pulled in at each level. Press **"Walk the proof"** to climb one level at a time — the running hash, the sibling being combined, and the resulting parent are shown while the matching tree nodes light up. At the top, the recomputed root is asserted equal to the committed root byte-for-byte. Click "Tamper leaf" to modify one item and watch the root change, the highlighted proof path flag as tampered, and the equality assertion turn red. The gated **Advanced** subsection exposes the odd-node convention (RFC 6962 promote vs Bitcoin duplicate): in Bitcoin mode a proof that lands on a self-copied position is flagged as an "odd-leaf duplication leak," and the live malleability panel recomputes `root([a,b,c])` vs `root([a,b,c,c])` under both conventions. The proof size calculator shows how O(log n) scales to billions of items.

## What Can Go Wrong

- Missing domain separation: without 0x00/0x01 prefixes, an internal node hash can be presented as a leaf hash, constructing a valid-looking proof for data not in the tree (second preimage attack on tree structure).
- Odd-leaf duplication leaks: duplicating the last leaf to even the tree can allow an attacker to forge proofs for the duplicated position - implementations should track which positions are real vs. duplicated. This demo lets you switch into that (Bitcoin) mode and see it: `[a,b,c]` and `[a,b,c,c]` collide on one root (CVE-2012-2459), and any proof step that is a self-copy is flagged. The RFC 6962 default (promote, not duplicate) removes the leak entirely.
- Root confusion across trees: a valid inclusion proof is only meaningful relative to a specific root. Without binding the root to a signed, timestamped commitment, an attacker can substitute a different tree with the same structure.
- Hash function weakness: Merkle tree security reduces entirely to collision resistance of the underlying hash. SHA-1-based Merkle trees (early Git) are weakened by SHAttered - Git is migrating to SHA-256.
- Unbalanced trees and depth confusion: non-binary or unbalanced tree implementations can produce ambiguous proof paths where the same proof validates against multiple roots.

## Real-World Usage

- Git object model: every Git commit contains the SHA-256 (or SHA-1) root of a tree object that hashes all files and subdirectories, making the entire repository history tamper-evident.
- Bitcoin SPV: lightweight Bitcoin clients verify transaction inclusion using Merkle proofs against the block header's Merkle root, downloading only 80-byte headers rather than full blocks.
- Certificate Transparency (RFC 6962): all TLS certificates must be logged in public Merkle logs; Chrome and Safari require valid CT inclusion proofs before trusting any certificate.
- Package managers: npm, Yarn, and Cargo use hash trees to verify package integrity - a package manifest commits to all file hashes, and the package registry signs the root.
- Ethereum state trie: Ethereum's Patricia-Merkle trie commits to the entire world state (all account balances and contract storage) in each block header.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-merkle-vault
cd crypto-lab-merkle-vault
npm install
npm run dev      # dev server
npm test         # crypto unit tests (KATs, round-trip, forgery, CVE-2012-2459, fuzz)
npm run test:a11y  # WCAG A/AA accessibility gate (axe-core)
```

## Related Demos

- [crypto-lab-babel-hash](https://systemslibrarian.github.io/crypto-lab-babel-hash/) - SHA-256, SHA3-256, BLAKE3 internals behind the tree.
- [crypto-lab-hash-zoo](https://systemslibrarian.github.io/crypto-lab-hash-zoo/) - Merkle-Damgard hash construction and properties.
- [crypto-lab-sphincs-ledger](https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/) - SLH-DSA hash-based signatures built on Merkle trees.
- [crypto-lab-lms-ledger](https://systemslibrarian.github.io/crypto-lab-lms-ledger/) - LMS/HSS stateful hash-based signatures using Merkle authentication paths.
- [crypto-lab-collision-vault](https://systemslibrarian.github.io/crypto-lab-collision-vault/) - what happens when the underlying hash's collision resistance fails.

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
