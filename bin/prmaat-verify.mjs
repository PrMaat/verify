#!/usr/bin/env node
/**
 * prmaat-verify — reference verifier CLI (PrMaat Verification Spec v0.1).
 *
 * Verifies a signed-event bundle and exits 0 on conformance, non-zero
 * on failure with a specific failure code from spec §10.
 *
 * Usage:
 *   prmaat-verify <bundle-dir>
 *   prmaat-verify --event <event.json> --did <did.json>
 *   prmaat-verify --event <event.json> --did <did.json> \
 *                 --inclusion <inclusion-proof.json> \
 *                 --vc <daily-root.vc.json>
 *
 * Bundle directory layout (per spec §6.3):
 *   bundle/
 *   ├── event.json
 *   ├── inclusion-proof.json
 *   ├── daily-root.vc.json
 *   ├── did-document.json
 *   └── README.txt
 *
 * Exit codes:
 *   0    OK (basic or audit conformance)
 *   1    failure (specific code printed to stderr)
 *   2    usage error (bad args)
 */
import { readFileSync, existsSync, statSync } from "node:fs";
import { join, basename } from "node:path";
import { verifySignedEvent } from "../src/verify.mjs";

const VERSION = "0.1.0";

function usage(exitCode = 2) {
  console.error(`prmaat-verify v${VERSION} — PrMaat Verification Spec v0.1 reference verifier

Usage:
  prmaat-verify <bundle-dir>
  prmaat-verify --event <event.json> --did <did.json>
  prmaat-verify --event <event.json> --did <did.json> \\
                --inclusion <proof.json> --vc <daily-root.vc.json>
  prmaat-verify --version
  prmaat-verify --help

Spec: https://prmaat.com/spec/v0.1
Source: https://github.com/PrMaat/verify
Repository: open-source MIT, zero runtime deps.

Exit codes:
  0  OK   — bundle passes prmaat-v0.1.basic or .audit
  1  FAIL — specific failure code printed (see spec §10)
  2  USAGE — bad arguments
`);
  process.exit(exitCode);
}

function loadJson(path) {
  if (!existsSync(path)) {
    console.error(`BUNDLE_INCOMPLETE: file not found: ${path}`);
    process.exit(1);
  }
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    console.error(`CANONICALIZATION_INVALID: ${path} is not valid JSON: ${e.message}`);
    process.exit(1);
  }
}

function parseArgs(argv) {
  const args = { event: null, did: null, inclusion: null, vc: null, bundle: null };
  let i = 0;
  while (i < argv.length) {
    const a = argv[i];
    if (a === "--help" || a === "-h") usage(0);
    if (a === "--version" || a === "-v") { console.log(VERSION); process.exit(0); }
    if (a === "--event") { args.event = argv[++i]; i++; continue; }
    if (a === "--did")   { args.did = argv[++i];   i++; continue; }
    if (a === "--inclusion") { args.inclusion = argv[++i]; i++; continue; }
    if (a === "--vc")    { args.vc = argv[++i];    i++; continue; }
    if (a.startsWith("--")) {
      console.error(`USAGE: unknown flag ${a}`);
      usage();
    }
    // Positional: bundle directory
    if (!args.bundle) { args.bundle = a; i++; continue; }
    console.error(`USAGE: unexpected positional ${a}`);
    usage();
  }
  return args;
}

function loadFromBundle(bundleDir) {
  if (!existsSync(bundleDir) || !statSync(bundleDir).isDirectory()) {
    console.error(`BUNDLE_INCOMPLETE: bundle directory not found: ${bundleDir}`);
    process.exit(1);
  }
  const eventPath = join(bundleDir, "event.json");
  const didPath   = join(bundleDir, "did-document.json");
  const inclPath  = join(bundleDir, "inclusion-proof.json");
  const vcPath    = join(bundleDir, "daily-root.vc.json");
  if (!existsSync(eventPath)) {
    console.error(`BUNDLE_INCOMPLETE: missing event.json in ${bundleDir}`);
    process.exit(1);
  }
  if (!existsSync(didPath)) {
    console.error(`BUNDLE_INCOMPLETE: missing did-document.json in ${bundleDir}`);
    process.exit(1);
  }
  return {
    event:     loadJson(eventPath),
    did:       loadJson(didPath),
    inclusion: existsSync(inclPath) ? loadJson(inclPath) : null,
    vc:        existsSync(vcPath)   ? loadJson(vcPath)   : null,
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  let event, did, inclusion, vc;

  if (args.bundle) {
    const loaded = loadFromBundle(args.bundle);
    event = loaded.event;
    did = loaded.did;
    inclusion = loaded.inclusion;
    vc = loaded.vc;
  } else if (args.event && args.did) {
    event = loadJson(args.event);
    did = loadJson(args.did);
    if (args.inclusion) inclusion = loadJson(args.inclusion);
    if (args.vc) vc = loadJson(args.vc);
  } else {
    console.error("USAGE: must supply either <bundle-dir> or --event + --did");
    usage();
  }

  // Extract daily root from VC (if VC provided alongside inclusion proof)
  let expectedRoot = null;
  if (inclusion && vc) {
    expectedRoot = vc.credentialSubject?.merkleRoot
      || vc.credentialSubject?.root
      || vc.merkleRoot
      || vc.root;
    if (!expectedRoot) {
      console.error("VC_EXPIRED: daily-root.vc.json does not contain a merkleRoot/root field");
      process.exit(1);
    }
  } else if (inclusion && !vc) {
    // Use root from the proof itself (lower-trust path — verifier should warn)
    expectedRoot = inclusion.root;
    console.error("WARN: no daily-root.vc.json supplied; using root from inclusion proof itself (basic-tier verification only)");
  }

  try {
    const result = verifySignedEvent({
      event,
      didDocument: did,
      inclusionProof: inclusion,
      expectedRoot,
    });
    console.log(`OK  ${result.conformance}  custody=${result.custody}`);
    process.exit(0);
  } catch (e) {
    // The Error message starts with the FAILURE_CODE per spec §10.
    console.error(`FAIL  ${e.message}`);
    process.exit(1);
  }
}

main();
