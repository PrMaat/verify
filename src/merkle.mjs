/**
 * Merkle inclusion proof verifier — PrMaat Verification Spec v0.1 §6.
 *
 * Tree shape:
 *   - Standard binary Merkle, RFC-9162-style.
 *   - Leaf hash:    sha256( 0x00 || canonical_bytes_of_event_with_proof )
 *   - Internal:     sha256( 0x01 || left || right )
 *
 * A proof bundle's `inclusion-proof.json` looks like:
 *   {
 *     "leaf":  "<hex sha256>",        // optional — recomputed from event if absent
 *     "path":  [                      // sibling hashes from leaf to root
 *       { "side": "left",  "hash": "<hex>" },
 *       { "side": "right", "hash": "<hex>" }
 *     ],
 *     "root":  "<hex sha256>",        // expected root, must match daily VC
 *     "leafIndex":  12,                // 0-based index in the leaf array (informational)
 *     "treeSize":   42                 // total leaves on this day (informational)
 *   }
 *
 * Verifier walks the path from leaf upward, hashing with the spec'd
 * domain separators, and asserts the computed root matches `root`.
 */
import { createHash } from "node:crypto";

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

function sha256(buf) {
  return createHash("sha256").update(buf).digest();
}

function hexToBuf(hex) {
  if (typeof hex !== "string" || !/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error(`INCLUSION_MISMATCH: invalid hex ${String(hex).slice(0, 32)}`);
  }
  return Buffer.from(hex, "hex");
}

function bufToHex(buf) {
  return Buffer.from(buf).toString("hex");
}

/**
 * Compute the leaf hash from canonical bytes of the event-with-proof.
 * @param {Uint8Array | Buffer} canonicalBytes
 * @returns {Buffer}
 */
export function leafHash(canonicalBytes) {
  return sha256(Buffer.concat([LEAF_PREFIX, Buffer.from(canonicalBytes)]));
}

/**
 * Walk the path and return the computed root.
 *
 * @param {Buffer} leaf - precomputed leaf hash
 * @param {Array<{side: "left"|"right", hash: string}>} path
 * @returns {Buffer}
 */
export function computeRoot(leaf, path) {
  let current = Buffer.from(leaf);
  for (const step of path) {
    if (!step || (step.side !== "left" && step.side !== "right")) {
      throw new Error("INCLUSION_MISMATCH: path step must declare side: left|right");
    }
    const sibling = hexToBuf(step.hash);
    current = step.side === "left"
      // sibling is on the left → sibling || current
      ? sha256(Buffer.concat([NODE_PREFIX, sibling, current]))
      // sibling is on the right → current || sibling
      : sha256(Buffer.concat([NODE_PREFIX, current, sibling]));
  }
  return current;
}

/**
 * Verify that `eventCanonicalBytes` is included in the Merkle tree
 * whose root is `expectedRoot`, given `path`.
 *
 * @param {Uint8Array | Buffer} eventCanonicalBytes
 * @param {{path: Array, root: string, leaf?: string}} proof
 * @returns {true}
 * @throws {Error} with code prefix INCLUSION_MISMATCH on failure
 */
export function verifyInclusion(eventCanonicalBytes, proof) {
  if (!proof || !Array.isArray(proof.path) || typeof proof.root !== "string") {
    throw new Error("INCLUSION_MISMATCH: proof must have {path: [], root: string}");
  }
  const computedLeaf = leafHash(eventCanonicalBytes);
  if (proof.leaf) {
    const declared = hexToBuf(proof.leaf);
    if (!declared.equals(computedLeaf)) {
      throw new Error("INCLUSION_MISMATCH: declared leaf hash does not match canonical bytes");
    }
  }
  const computedRoot = computeRoot(computedLeaf, proof.path);
  const expectedRoot = hexToBuf(proof.root);
  if (!computedRoot.equals(expectedRoot)) {
    throw new Error(`INCLUSION_MISMATCH: computed root ${bufToHex(computedRoot)} != expected ${bufToHex(expectedRoot)}`);
  }
  return true;
}
