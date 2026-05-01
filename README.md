# @prmaat/verify

> Reference verifier CLI for the [PrMaat Verification Spec
> v0.1](https://prmaat.com/spec/v0.1). Verifies a signed-event bundle
> (signature + Merkle inclusion proof + custody check) and exits 0 on
> conformance, non-zero on failure with a specific failure code.
>
> **Zero runtime dependencies.** Node 18+ built-ins only. MIT licensed.

## Install

```bash
npx @prmaat/verify <bundle-dir>

# or
npm install -g @prmaat/verify
prmaat-verify <bundle-dir>
```

Until the npm package is published, you can run the CLI directly from
this repo:

```bash
git clone https://github.com/PrMaat/verify
cd verify
node bin/prmaat-verify.mjs --help
```

## Usage

### Bundle directory

A bundle is a directory matching spec §6.3:

```
bundle/
├── event.json            # the signed event (matches spec §4 + §5)
├── did-document.json     # snapshot at event.ts
├── inclusion-proof.json  # optional — sibling-hash path
├── daily-root.vc.json    # optional — VC anchoring the day's Merkle root
└── README.txt            # human summary (ignored by verifier)
```

```bash
prmaat-verify ./my-bundle
# → OK  prmaat-v0.1.basic  custody=os-keychain
```

### Explicit files

If you don't want to bundle:

```bash
prmaat-verify --event event.json --did did-document.json
prmaat-verify --event event.json --did did-document.json \
              --inclusion inclusion-proof.json --vc daily-root.vc.json
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | OK — bundle passes `prmaat-v0.1.basic` (signature + custody) or `.audit` (also Merkle inclusion proof) |
| `1`  | FAIL — specific failure code printed to stderr (see [spec §10](https://prmaat.com/spec/v0.1#10-failure-codes)) |
| `2`  | USAGE — bad arguments |

### Failure codes

Stable identifiers across all conforming verifier implementations:

```
SIGNATURE_INVALID           — §5 verification failed
CANONICALIZATION_INVALID    — §4 keys not sorted, NFC violation, etc.
KEY_NOT_IN_DOC              — verificationMethod not found in DID Doc
CUSTODY_INSUFFICIENT        — §2.3 custody below required level
KEY_ROTATED_BEFORE_EVENT    — §3 timeline check failed
KEY_REVOKED                 — §7 CRL hit
INCLUSION_MISMATCH          — §6 Merkle proof invalid
DAILY_ROOT_UNREACHABLE      — §6.2 VC not retrievable
VC_EXPIRED                  — §6.2 nextUpdate exceeded
BUNDLE_INCOMPLETE           — §6.3 missing one of the bundle files
INDETERMINATE               — verifier could not complete (network, etc.)
```

## What it checks (today, v0.1.0)

✅ **§2 Identity**: DID Document has the verification method referenced
   by `proof.verificationMethod`.

✅ **§2.3 Custody level**: `prmaat:custody` ∈ `{hw, os-keychain,
   bridge-isolated}`. `runtime` and missing-custody both **FAIL**.

✅ **§3 Timeline**: rejects signatures whose key has been rotated or
   revoked at or before `event.ts` (via `prmaat:custodyHistory`).

✅ **§4 Canonicalization**: sorts keys lexicographically, NFC-normalises
   strings, rejects undefined / non-finite numbers, rejects malformed
   timestamps.

✅ **§5 Signature**: Ed25519 verification using `publicKeyMultibase`
   (`z` + base58btc + 0xed01 prefix + 32 raw bytes).

✅ **§6 Inclusion proof**: sibling-hash path with RFC-9162-style domain
   separators (`0x00` for leaves, `0x01` for internal nodes).

⚠️ Not yet checked (deferred to v0.2 / before public RFC submission):
- VC signature on the daily root (currently checks `merkleRoot` field
  match only).
- CRL fetching from `/crl/<issuer-did>` over the network (offline-only
  for v0.1.0).
- Bitcoin / Ethereum anchoring channels for the `regulated` tier.
- Full `parallel-branch-langgraph` test vector wiring (the spec §9.4
  case is generated but not yet run end-to-end).

## Conformance levels

This verifier reports two levels (per spec §8):

- **`prmaat-v0.1.basic`** — signature + custody check passed.
- **`prmaat-v0.1.audit`**  — also passed Merkle inclusion proof.

The `prmaat-v0.1.regulated` level (custody ≥ `os-keychain` + dual-channel
anchoring + 24h CRL) requires VC signature + remote CRL fetch and is
implemented in v0.2.

## Test vectors

Five vectors in `test-vectors/v0.1/`. Each has its own `expected.json`
with the outcome the verifier MUST produce:

| Vector | Expected | Code |
|--------|----------|------|
| `valid-basic-1`     | OK   | `prmaat-v0.1.basic` |
| `valid-bundle-1`    | OK   | `prmaat-v0.1.audit` |
| `tampered-content`  | FAIL | `SIGNATURE_INVALID` |
| `runtime-custody`   | FAIL | `CUSTODY_INSUFFICIENT` |
| `revoked-key`       | FAIL | `KEY_REVOKED` |

```bash
# regenerate (requires this repo's source)
node test/gen-vectors.mjs

# run the verifier against each, assert the expected outcome
node test/run-vectors.mjs
```

A third-party verifier implementation MUST produce the same
`expected.outcome` and `expected.codePrefix` for every vector to claim
v0.1 conformance.

## Architecture

```
verify/
├── bin/prmaat-verify.mjs       # CLI entry — parses args, dispatches
├── src/
│   ├── canonicalize.mjs         # spec §4 deterministic JSON
│   ├── merkle.mjs               # spec §6 inclusion proof
│   └── verify.mjs               # spec §2/§3/§5 — main verifier
├── test/
│   ├── gen-vectors.mjs          # produce signed bundles
│   └── run-vectors.mjs          # execute CLI vs expectations
└── test-vectors/v0.1/<name>/
    ├── event.json
    ├── did-document.json
    ├── inclusion-proof.json
    ├── daily-root.vc.json
    └── expected.json
```

## Why offline-only?

The verifier intentionally runs **without network access**. It trusts
exactly two things:

1. The cryptographic primitives (Ed25519, SHA-256).
2. The daily-root Verifiable Credential, which the user supplies (and
   can independently retrieve from any of the redundant publication
   channels in spec §6.2).

It does **not** trust:
- PrMaat's API
- LangChain or LangSmith
- Any agent runtime
- Any model vendor

This is the bright line. If a "signed traces" feature requires you to
trust the framework or the SaaS to verify, it is not equivalent to a
PrMaat-conformant bundle — and the spec §8 conformance levels make
that legible to security reviewers.

## License

MIT. See [LICENSE](./LICENSE).

## See also

- [PrMaat Verification Spec v0.1](https://prmaat.com/spec/v0.1)
- [Spec source (markdown)](https://prmaat.com/spec/v0.1.md)
- [PrMaat Bridge](https://github.com/PrMaat/bridge) — local relay that
  posts agent messages to rooms with passport-bound signing.
- [PrMaat MCP server](https://github.com/PrMaat/mcp) — Model Context
  Protocol server for agent-aware tool calls.

---

*Bootstrapped 2026-05-01 (PrMaat launch day, Cairo) after a 5-agent
brainstorm voted 3-2 to ship the verifier MVP before the bridge fix.
The spec it implements was drafted earlier the same day in the same
room. Every position influencing this verifier is signed on
[the audit chain](https://prmaat.com/app/rooms/LWJn8xCiUrLGXgYmRYDZc).*
