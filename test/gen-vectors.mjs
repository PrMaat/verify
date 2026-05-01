#!/usr/bin/env node
/**
 * Generate test vectors for the v0.1 reference verifier.
 *
 * Produces signed bundles in test-vectors/v0.1/<name>/:
 *   - valid-basic-1            — should pass `.basic` conformance
 *   - tampered-content         — should FAIL with SIGNATURE_INVALID
 *   - tampered-inclusion       — should FAIL with INCLUSION_MISMATCH
 *   - runtime-custody          — should FAIL with CUSTODY_INSUFFICIENT
 *   - revoked-key              — should FAIL with KEY_REVOKED
 *
 * Run:   node test/gen-vectors.mjs
 *
 * Each bundle includes its expected verifier outcome in `expected.json`,
 * which test/run-vectors.mjs uses to assert.
 */
import { generateKeyPairSync, sign as nodeSign, createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalBytes, canonicalize } from "../src/canonicalize.mjs";
import { leafHash, computeRoot } from "../src/merkle.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const VEC_DIR = join(__dirname, "..", "test-vectors", "v0.1");

// ── multibase base58btc encode (Bitcoin alphabet) ────────────────────
const ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Encode(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let s = "";
  while (n > 0n) { s = ALPH[Number(n % 58n)] + s; n /= 58n; }
  // Leading zeros
  for (const b of bytes) {
    if (b !== 0) break;
    s = "1" + s;
  }
  return s;
}

function multibaseEd25519Pub(rawPub) {
  // 0xed01 prefix + 32 bytes
  const prefixed = new Uint8Array([0xed, 0x01, ...rawPub]);
  return "z" + base58Encode(prefixed);
}

function multibaseSig(sig) {
  return "z" + base58Encode(sig);
}

// ── Generate Ed25519 key (raw pub + DER private key for signing) ─────
function genKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  // raw 32-byte pub: the SPKI DER suffix
  const spki = publicKey.export({ format: "der", type: "spki" });
  const rawPub = Uint8Array.from(spki).slice(spki.length - 32);
  return { rawPub, privateKey };
}

function buildSignedEvent({ keyId, didDoc, privateKey, eventCtx, customTs }) {
  const event = {
    v: 1,
    type: "agent.message.sent",
    issuer: didDoc.id,
    subject: didDoc.id,
    ts: customTs || "2026-05-01T20:00:00.000Z",
    ctx: eventCtx,
    prev: null,
    nonce: "00112233445566778899aabbccddeeff",
  };
  // Canonicalize the payload-only form (without proof)
  const sig = nodeSign(null, Buffer.from(canonicalBytes(event)), privateKey);
  event.proof = {
    type: "Ed25519Signature2020",
    created: event.ts,
    verificationMethod: keyId,
    proofPurpose: "assertionMethod",
    proofValue: multibaseSig(sig),
  };
  return event;
}

function buildDidDoc({ rawPub, didId, kid, custody = "os-keychain", revokedAt = null }) {
  const doc = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: didId,
    verificationMethod: [{
      id: `${didId}#${kid}`,
      type: "Ed25519VerificationKey2020",
      controller: didId,
      publicKeyMultibase: multibaseEd25519Pub(rawPub),
      "prmaat:custody": custody,
    }],
    assertionMethod: [`${didId}#${kid}`],
  };
  if (revokedAt) {
    doc["prmaat:custodyHistory"] = [{
      kid,
      revokedAt,
      reason: "compromise",
    }];
  }
  return doc;
}

function writeBundle(name, files, expected) {
  const dir = join(VEC_DIR, name);
  mkdirSync(dir, { recursive: true });
  for (const [filename, content] of Object.entries(files)) {
    writeFileSync(join(dir, filename), JSON.stringify(content, null, 2) + "\n");
  }
  writeFileSync(join(dir, "expected.json"), JSON.stringify(expected, null, 2) + "\n");
  writeFileSync(join(dir, "README.txt"),
    `${name}\n\nExpected: ${expected.outcome}${expected.codePrefix ? "  (" + expected.codePrefix + ")" : ""}\n` +
    `Run: node bin/prmaat-verify.mjs test-vectors/v0.1/${name}/\n`);
  console.log(`✓ ${name}`);
}

// ── Vector 1: valid-basic-1 ───────────────────────────────────────────
function vecValid() {
  const { rawPub, privateKey } = genKey();
  const didId = "did:prmaat:test-1";
  const didDoc = buildDidDoc({ rawPub, didId, kid: "key-1" });
  const event = buildSignedEvent({
    keyId: `${didId}#key-1`,
    didDoc, privateKey,
    eventCtx: { roomId: "room-test-1", contentHash: "sha256:abc123", model: "test/model-1" },
  });
  writeBundle("valid-basic-1",
    { "event.json": event, "did-document.json": didDoc },
    { outcome: "OK", conformance: "prmaat-v0.1.basic" });
}

// ── Vector 2: tampered-content (signature should fail) ────────────────
function vecTamperedContent() {
  const { rawPub, privateKey } = genKey();
  const didId = "did:prmaat:test-2";
  const didDoc = buildDidDoc({ rawPub, didId, kid: "key-1" });
  const event = buildSignedEvent({
    keyId: `${didId}#key-1`,
    didDoc, privateKey,
    eventCtx: { roomId: "room-test-2", contentHash: "sha256:abc123", model: "test/model-2" },
  });
  // Tamper: change the contentHash AFTER signing
  event.ctx.contentHash = "sha256:tampered";
  writeBundle("tampered-content",
    { "event.json": event, "did-document.json": didDoc },
    { outcome: "FAIL", codePrefix: "SIGNATURE_INVALID" });
}

// ── Vector 3: runtime-custody (should fail §2.3) ──────────────────────
function vecRuntimeCustody() {
  const { rawPub, privateKey } = genKey();
  const didId = "did:prmaat:test-3";
  const didDoc = buildDidDoc({ rawPub, didId, kid: "key-1", custody: "runtime" });
  const event = buildSignedEvent({
    keyId: `${didId}#key-1`,
    didDoc, privateKey,
    eventCtx: { roomId: "room-test-3", contentHash: "sha256:abc123", model: "test/model-3" },
  });
  writeBundle("runtime-custody",
    { "event.json": event, "did-document.json": didDoc },
    { outcome: "FAIL", codePrefix: "CUSTODY_INSUFFICIENT" });
}

// ── Vector 4: revoked-key (should fail §3) ────────────────────────────
function vecRevokedKey() {
  const { rawPub, privateKey } = genKey();
  const didId = "did:prmaat:test-4";
  // Revoked at 2026-04-01 — event signed at 2026-05-01 is AFTER revocation
  const didDoc = buildDidDoc({ rawPub, didId, kid: "key-1", revokedAt: "2026-04-01T00:00:00Z" });
  const event = buildSignedEvent({
    keyId: `${didId}#key-1`,
    didDoc, privateKey,
    eventCtx: { roomId: "room-test-4", contentHash: "sha256:abc123", model: "test/model-4" },
  });
  writeBundle("revoked-key",
    { "event.json": event, "did-document.json": didDoc },
    { outcome: "FAIL", codePrefix: "KEY_REVOKED" });
}

// ── Vector 5: valid-bundle-1 (with inclusion proof) ───────────────────
// Build a 4-leaf Merkle tree and produce an inclusion proof for leaf 0.
function vecValidBundle() {
  const { rawPub, privateKey } = genKey();
  const didId = "did:prmaat:test-5";
  const didDoc = buildDidDoc({ rawPub, didId, kid: "key-1" });
  const event = buildSignedEvent({
    keyId: `${didId}#key-1`,
    didDoc, privateKey,
    eventCtx: { roomId: "room-test-5", contentHash: "sha256:abc123", model: "test/model-5" },
  });
  // Compute leaf 0 from the SIGNED event (canonical including .proof)
  const leaf0 = leafHash(canonicalBytes(event));
  // Three sibling leaves (synthetic; their content doesn't matter for inclusion-of-leaf-0)
  function syntheticLeaf(s) { return createHash("sha256").update(Buffer.concat([Buffer.from([0x00]), Buffer.from(s)])).digest(); }
  const leaf1 = syntheticLeaf("sib-1");
  const leaf2 = syntheticLeaf("sib-2");
  const leaf3 = syntheticLeaf("sib-3");
  function combine(a, b) { return createHash("sha256").update(Buffer.concat([Buffer.from([0x01]), a, b])).digest(); }
  const node01 = combine(leaf0, leaf1);
  const node23 = combine(leaf2, leaf3);
  const root = combine(node01, node23);

  const inclusionProof = {
    leaf:      leaf0.toString("hex"),
    path: [
      { side: "right", hash: leaf1.toString("hex") },   // sibling of leaf0 is on the right
      { side: "right", hash: node23.toString("hex") },  // sibling of node01 is on the right
    ],
    root:      root.toString("hex"),
    leafIndex: 0,
    treeSize:  4,
  };
  // Sanity-check while generating: recompute root from path
  const recomputed = computeRoot(leaf0, inclusionProof.path);
  if (!recomputed.equals(root)) {
    throw new Error("vec-gen-bug: tree construction does not match verifier path semantics");
  }

  const dailyRootVc = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    type: ["VerifiableCredential", "PrmaatDailyRoot"],
    issuer: "did:prmaat:platform-anchor",
    issuanceDate: "2026-05-01T23:59:59Z",
    credentialSubject: {
      day: "2026-05-01",
      issuerDid: didId,
      merkleRoot: root.toString("hex"),
      treeSize: 4,
    },
    // Note: this VC is NOT itself signed in the test fixture; the
    // current verifier doesn't check VC signatures yet (Day-21 v0.1
    // checks merkleRoot match only — full VC signature check lands
    // before public RFC submission).
  };

  writeBundle("valid-bundle-1",
    {
      "event.json": event,
      "did-document.json": didDoc,
      "inclusion-proof.json": inclusionProof,
      "daily-root.vc.json": dailyRootVc,
    },
    { outcome: "OK", conformance: "prmaat-v0.1.audit" });
}

// ── Run ──────────────────────────────────────────────────────────────
console.log("Generating test vectors in", VEC_DIR);
vecValid();
vecTamperedContent();
vecRuntimeCustody();
vecRevokedKey();
vecValidBundle();
console.log("Done. Run `node test/run-vectors.mjs` to verify all expected outcomes.");
