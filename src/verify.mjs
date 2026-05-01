/**
 * Core verifier — PrMaat Verification Spec v0.1 §5 + §2.3.
 *
 * Inputs:
 *   - event:           the signed event JSON (matches §4 schema)
 *   - didDocument:     resolved DID Document for the issuer
 *   - inclusionProof:  optional, §6 Merkle proof
 *
 * Outputs:
 *   { ok: boolean, code?: string, detail?: string, conformance?: string }
 *
 * Failure codes are stable identifiers from spec §10. Verifier
 * implementations across languages MUST use the same codes so
 * downstream tooling (CI gates, audit reports) can match by code.
 */
import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";
import { Buffer } from "node:buffer";
import { canonicalBytes } from "./canonicalize.mjs";
import { verifyInclusion } from "./merkle.mjs";

// ── multibase + multikey helpers (just enough for ed25519) ────────────
//
// PrMaat v0.1 default keys are Ed25519VerificationKey2020 expressed as
// `publicKeyMultibase`. The string starts with `z` (base58btc) and the
// payload starts with the 0xed01 multicodec for Ed25519-pub, followed
// by 32 bytes of public key material.
const ED25519_PUB_PREFIX = new Uint8Array([0xed, 0x01]);

function base58Decode(str) {
  // Minimal base58btc decoder (no deps). Bitcoin alphabet.
  const ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const map = new Map();
  for (let i = 0; i < ALPH.length; i++) map.set(ALPH[i], i);
  let bytes = [0];
  for (const ch of str) {
    const v = map.get(ch);
    if (v === undefined) {
      throw new Error("SIGNATURE_INVALID: malformed base58btc in publicKeyMultibase");
    }
    let carry = v;
    for (let j = 0; j < bytes.length; j++) {
      const x = bytes[j] * 58 + carry;
      bytes[j] = x & 0xff;
      carry = x >> 8;
    }
    while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  // Leading zeros (each '1' → 0x00 prefix)
  for (const ch of str) {
    if (ch !== "1") break;
    bytes.push(0);
  }
  bytes.reverse();
  return new Uint8Array(bytes);
}

function decodeMultibasePublicKey(mb) {
  if (typeof mb !== "string" || mb.length < 2) {
    throw new Error("SIGNATURE_INVALID: publicKeyMultibase must be a non-empty string");
  }
  if (mb[0] !== "z") {
    throw new Error("SIGNATURE_INVALID: only base58btc multibase ('z' prefix) supported in v0.1");
  }
  const decoded = base58Decode(mb.slice(1));
  if (decoded.length !== ED25519_PUB_PREFIX.length + 32 ||
      decoded[0] !== ED25519_PUB_PREFIX[0] ||
      decoded[1] !== ED25519_PUB_PREFIX[1]) {
    throw new Error("SIGNATURE_INVALID: not an Ed25519 publicKeyMultibase (expected 0xed01 + 32 bytes)");
  }
  return decoded.slice(2);
}

// ── Find verification method in DID Document ─────────────────────────
function findVerificationMethod(didDoc, vmId) {
  if (!didDoc || !Array.isArray(didDoc.verificationMethod)) {
    throw new Error("KEY_NOT_IN_DOC: did document missing verificationMethod array");
  }
  // Allow either full URI or fragment match
  const fragment = vmId.includes("#") ? vmId.split("#")[1] : vmId;
  const vm = didDoc.verificationMethod.find(v =>
    v.id === vmId || v.id?.endsWith("#" + fragment) || v.id === "#" + fragment
  );
  if (!vm) {
    throw new Error(`KEY_NOT_IN_DOC: verificationMethod ${vmId} not found in DID document`);
  }
  return vm;
}

// ── Custody check (§2.3) ─────────────────────────────────────────────
const COMPLIANT_CUSTODY = new Set(["hw", "os-keychain", "bridge-isolated"]);

function checkCustody(vm) {
  // PrMaat extension: vm["prmaat:custody"] OR didDoc-level extension.
  const custody = vm["prmaat:custody"];
  if (custody === undefined || custody === null) {
    throw new Error('CUSTODY_INSUFFICIENT: verificationMethod missing "prmaat:custody" — defaults to "unknown" per §2.3');
  }
  if (!COMPLIANT_CUSTODY.has(custody)) {
    throw new Error(`CUSTODY_INSUFFICIENT: custody="${custody}" — only ${[...COMPLIANT_CUSTODY].join(", ")} pass v0.1.audit per §2.3`);
  }
  return custody;
}

// ── Rotation/revocation timeline (§3) ────────────────────────────────
function checkTimeline(vm, didDoc, eventTs) {
  const eventTime = Date.parse(eventTs);
  if (isNaN(eventTime)) {
    throw new Error("CANONICALIZATION_INVALID: event.ts is not a valid timestamp");
  }
  // VM may declare its own validFrom/until
  if (vm.validFrom && Date.parse(vm.validFrom) > eventTime) {
    throw new Error(`KEY_ROTATED_BEFORE_EVENT: verificationMethod validFrom ${vm.validFrom} > event.ts ${eventTs}`);
  }
  if (vm.validUntil && Date.parse(vm.validUntil) < eventTime) {
    throw new Error(`KEY_ROTATED_BEFORE_EVENT: verificationMethod validUntil ${vm.validUntil} < event.ts ${eventTs}`);
  }
  // Custody history (PrMaat extension on DID doc)
  const history = didDoc["prmaat:custodyHistory"] || [];
  for (const entry of history) {
    if (entry.kid === vm.id || (vm.id?.endsWith("#" + entry.kid))) {
      if (entry.revokedAt && Date.parse(entry.revokedAt) <= eventTime) {
        throw new Error(`KEY_REVOKED: verificationMethod revoked at ${entry.revokedAt} <= event.ts ${eventTs}`);
      }
    }
  }
  return true;
}

/**
 * Verify a signed event against a DID document.
 *
 * @param {object} args
 * @param {object} args.event - JSON event matching §4 (with `.proof`)
 * @param {object} args.didDocument
 * @param {object} [args.inclusionProof]  - if present, also runs §6
 * @param {string} [args.expectedRoot]    - daily root from VC (§6.2);
 *                                            required if inclusionProof is set
 * @returns {{ok: true, conformance: string}}
 * @throws {Error} on any failure with stable code prefix from §10
 */
export function verifySignedEvent({ event, didDocument, inclusionProof, expectedRoot }) {
  if (!event || typeof event !== "object") {
    throw new Error("BUNDLE_INCOMPLETE: event must be an object");
  }
  if (!event.proof || typeof event.proof !== "object") {
    throw new Error("BUNDLE_INCOMPLETE: event.proof missing — not a signed event");
  }
  if (event.proof.type !== "Ed25519Signature2020") {
    throw new Error(`SIGNATURE_INVALID: only Ed25519Signature2020 supported in v0.1 (got "${event.proof.type}")`);
  }
  if (!event.proof.proofValue || typeof event.proof.proofValue !== "string") {
    throw new Error("SIGNATURE_INVALID: missing proof.proofValue");
  }
  if (!event.proof.verificationMethod) {
    throw new Error("SIGNATURE_INVALID: missing proof.verificationMethod");
  }
  if (!event.ts) {
    throw new Error("CANONICALIZATION_INVALID: missing event.ts");
  }

  // Detach proof from canonicalization (sign over event WITHOUT proof)
  const { proof, ...payload } = event;
  const canonical = canonicalBytes(payload);

  // Find the verification method
  const vm = findVerificationMethod(didDocument, event.proof.verificationMethod);

  // §2.3 custody check
  const custody = checkCustody(vm);

  // §3 timeline
  checkTimeline(vm, didDocument, event.ts);

  // §5 signature verification
  if (!vm.publicKeyMultibase) {
    throw new Error("SIGNATURE_INVALID: verificationMethod has no publicKeyMultibase (only multibase supported in v0.1)");
  }
  const pubKeyRaw = decodeMultibasePublicKey(vm.publicKeyMultibase);

  // Decode signature from multibase (also 'z' base58btc)
  const sigMb = event.proof.proofValue;
  if (typeof sigMb !== "string" || sigMb[0] !== "z") {
    throw new Error("SIGNATURE_INVALID: proofValue must be base58btc multibase ('z' prefix)");
  }
  const sigBytes = base58Decode(sigMb.slice(1));
  if (sigBytes.length !== 64) {
    throw new Error(`SIGNATURE_INVALID: Ed25519 signature must be 64 bytes (got ${sigBytes.length})`);
  }

  // Build a public key object that node:crypto can verify with.
  // Ed25519 key in node uses raw subjectPublicKeyInfo (DER) — we wrap
  // the raw 32-byte key in the standard Ed25519 SPKI prefix.
  const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
  const spki = Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(pubKeyRaw)]);
  const keyObject = createPublicKey({ key: spki, format: "der", type: "spki" });

  const sigOk = nodeVerify(null, Buffer.from(canonical), keyObject, Buffer.from(sigBytes));
  if (!sigOk) {
    throw new Error("SIGNATURE_INVALID: Ed25519 verification failed (canonical bytes do not match signed bytes)");
  }

  // §6 inclusion proof (if provided)
  let conformance = "prmaat-v0.1.basic";
  if (inclusionProof) {
    if (typeof expectedRoot !== "string") {
      throw new Error("BUNDLE_INCOMPLETE: inclusionProof provided but no expectedRoot from daily VC");
    }
    const inclusionInput = canonicalBytes(event); // canonicalize WITH proof for leaf hash
    const proofWithRoot = { ...inclusionProof, root: inclusionProof.root || expectedRoot };
    if (proofWithRoot.root !== expectedRoot) {
      throw new Error(`INCLUSION_MISMATCH: proof.root ${proofWithRoot.root.slice(0,16)}… does not match daily VC root ${expectedRoot.slice(0,16)}…`);
    }
    verifyInclusion(inclusionInput, proofWithRoot);
    conformance = "prmaat-v0.1.audit";
  }

  return { ok: true, conformance, custody };
}
