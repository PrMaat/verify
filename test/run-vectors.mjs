#!/usr/bin/env node
/**
 * Run every test vector in test-vectors/v0.1/ through prmaat-verify
 * and assert each one matches its expected.json outcome.
 *
 * Run:  node test/run-vectors.mjs
 * Exit: 0 if all pass, 1 if any fail.
 */
import { execFile } from "node:child_process";
import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileP = promisify(execFile);
const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const CLI = join(ROOT, "bin", "prmaat-verify.mjs");
const VEC = join(ROOT, "test-vectors", "v0.1");

let pass = 0, fail = 0;
const failures = [];

async function runOne(name) {
  const dir = join(VEC, name);
  const expectedPath = join(dir, "expected.json");
  if (!existsSync(expectedPath)) {
    console.log(`! ${name} — no expected.json, skipping`);
    return;
  }
  const expected = JSON.parse(readFileSync(expectedPath, "utf8"));
  let stdout = "", stderr = "", code = 0;
  try {
    const r = await execFileP(process.execPath, [CLI, dir]);
    stdout = r.stdout;
    stderr = r.stderr;
    code = 0;
  } catch (e) {
    stdout = e.stdout || "";
    stderr = e.stderr || "";
    code = e.code ?? 1;
  }

  const got = code === 0 ? "OK" : "FAIL";
  if (got !== expected.outcome) {
    fail++;
    failures.push({ name, expected: expected.outcome, got, stdout, stderr });
    console.log(`✗ ${name}  expected=${expected.outcome}  got=${got}  detail=${(stderr || stdout).trim().slice(0, 160)}`);
    return;
  }
  if (expected.codePrefix) {
    if (!stderr.includes(expected.codePrefix)) {
      fail++;
      failures.push({ name, expected: expected.codePrefix, got: stderr.trim(), stdout, stderr });
      console.log(`✗ ${name}  expected code ${expected.codePrefix}  got=${stderr.trim().slice(0, 160)}`);
      return;
    }
  }
  if (expected.conformance) {
    if (!stdout.includes(expected.conformance)) {
      fail++;
      failures.push({ name, expected: expected.conformance, got: stdout.trim(), stdout, stderr });
      console.log(`✗ ${name}  expected conformance ${expected.conformance}  got=${stdout.trim().slice(0, 160)}`);
      return;
    }
  }
  pass++;
  console.log(`✓ ${name}  ${(stdout || stderr).trim().slice(0, 100)}`);
}

async function main() {
  if (!existsSync(VEC)) {
    console.error(`No test-vectors/v0.1 directory found. Run: node test/gen-vectors.mjs`);
    process.exit(1);
  }
  const dirs = readdirSync(VEC).filter(d => statSync(join(VEC, d)).isDirectory()).sort();
  for (const d of dirs) await runOne(d);
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main();
