/**
 * Canonicalization for PrMaat Verification Spec v0.1 §4.
 *
 * Deterministic JSON form for signing/verifying:
 *   - Keys sorted lexicographically at every level.
 *   - UTF-8 NFC strings.
 *   - No insignificant whitespace.
 *   - Numbers in shortest decimal form that round-trips IEEE 754 doubles.
 *
 * The signature is computed over canonicalized BYTES — verifiers must
 * re-canonicalize before checking, never trust the wire form.
 *
 * This is a tiny, dep-free implementation. JCS (RFC 8785) is the eventual
 * target; for v0.1 we ship a strict subset that's compatible with JCS for
 * the input shapes the spec uses (no fancy escapes, no trailing zeros).
 */

function canonicalizeValue(v) {
  if (v === null) return "null";
  if (v === undefined) {
    throw new Error("CANONICALIZATION_INVALID: undefined values not allowed");
  }
  const t = typeof v;
  if (t === "boolean") return v ? "true" : "false";
  if (t === "number") {
    if (!Number.isFinite(v)) {
      throw new Error("CANONICALIZATION_INVALID: non-finite numbers (NaN, Infinity) are not allowed");
    }
    // Use the shortest decimal that round-trips. JS String(num) does the
    // right thing for IEEE 754 doubles in v8 / node.
    return String(v);
  }
  if (t === "string") {
    // Normalize to NFC and JSON-encode with strict escaping.
    return JSON.stringify(v.normalize("NFC"));
  }
  if (Array.isArray(v)) {
    return "[" + v.map(canonicalizeValue).join(",") + "]";
  }
  if (t === "object") {
    const keys = Object.keys(v).sort();
    const parts = keys.map(k => JSON.stringify(k.normalize("NFC")) + ":" + canonicalizeValue(v[k]));
    return "{" + parts.join(",") + "}";
  }
  throw new Error(`CANONICALIZATION_INVALID: unsupported type ${t}`);
}

/**
 * Canonicalize a JSON-serialisable value to its spec-§4 string form.
 * @param {*} obj
 * @returns {string}
 */
export function canonicalize(obj) {
  return canonicalizeValue(obj);
}

/**
 * Canonicalize and return UTF-8 bytes (what the signature is computed over).
 * @param {*} obj
 * @returns {Uint8Array}
 */
export function canonicalBytes(obj) {
  return new TextEncoder().encode(canonicalize(obj));
}
