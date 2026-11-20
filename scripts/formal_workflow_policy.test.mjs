// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const root = new URL("../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root), "utf8");

test("formal proofs are required for every candidate without carried-forward results", () => {
  const config = JSON.parse(read(".github/release-readiness.json"));
  assert.equal(config.lanes.formal.mode, "required");
  assert.deepEqual(config.lanes.formal.paths ?? [], []);
  const workflow = read(".github/workflows/formal-verification.yml");
  assert.match(workflow, /\non:\n  workflow_call:\n    outputs:\n      verified_sha:\n        value: \$\{\{ jobs\.proofs\.outputs\.verified_sha \}\}/u);
  assert.doesNotMatch(workflow, /workflow_dispatch:/u);
});

test("every proof checkout selects the dispatched revision", () => {
  const workflow = read(".github/workflows/formal-verification.yml");
  const checkouts = [...workflow.matchAll(/uses: actions\/checkout@[0-9a-f]{40}[^\n]*\n\s+with:\n((?:[ \t]+[^\n]*\n)+)/gu)];
  assert.ok(checkouts.length > 0);
  for (const [, inputs] of checkouts) {
    assert.match(inputs, /ref: \$\{\{ github[.]sha \}\}/u);
    assert.match(inputs, /persist-credentials: false/u);
  }
});

test("required CI waits for formal verification and checks its candidate SHA", () => {
  const workflow = read(".github/workflows/ci.yml");
  assert.match(workflow, /uses: \.\/\.github\/workflows\/formal-verification[.]yml/u);
  assert.match(workflow, /needs: \[[^\]\n]*\bformal\b[^\]\n]*\]/u);
  assert.ok(workflow.includes('$needs[$lane].outputs.verified_sha != $sha'));
});

test("required formal verification retains the complete proof runners", () => {
  const workflow = read(".github/workflows/formal-verification.yml");
  for (const runner of ["scripts/verify_tamarin.sh", "scripts/verify_reference_encoder_proofs.sh", "scripts/verify_formal_scope.sh"]) assert.ok(workflow.includes(runner));
  assert.match(workflow, /git rev-parse --verify HEAD/u);
  assert.match(workflow, /needs: \[tamarin, kani-reference, kani-verification\]/u);
});

test("formal policy rejects omitted proofs, tolerated failures, and a wrong-SHA receipt", (t) => {
  const temporary = mkdtempSync(join(tmpdir(), "crypto-formal-policy-"));
  t.after(() => rmSync(temporary, { recursive: true, force: true }));
  const path = ".github/workflows/formal-verification.yml";
  mkdirSync(join(temporary, ".github/workflows"), { recursive: true });
  const source = read(path);
  const check = (workflow) => {
    writeFileSync(join(temporary, path), workflow);
    return spawnSync(process.execPath, ["--input-type=module", "-e", `
      import { createReleaseReadinessContext } from ${JSON.stringify(new URL("./release-readiness/core.mjs", import.meta.url).href)};
      const context = createReleaseReadinessContext({ scriptUrl: ${JSON.stringify(import.meta.url)}, repoRoot: process.argv[1] });
      context.assertFormalVerificationWorkflow(${JSON.stringify(path)}, "proofs");
    `, temporary], { encoding: "utf8", timeout: 10_000 });
  };
  const accepted = check(source);
  assert.equal(accepted.status, 0, accepted.stderr);
  for (const changed of [
    source.replace("needs: [tamarin, kani-reference, kani-verification]", "needs: [tamarin, kani-reference]"),
    source.replace("verified_sha: ${{ github.sha }}", 'verified_sha: "' + "a".repeat(40) + '"'),
    source.replace("  tamarin:\n", "  tamarin:\n    continue-on-error: true\n"),
  ]) {
    assert.notEqual(changed, source);
    const rejected = check(changed);
    assert.equal(rejected.error, undefined);
    assert.equal(rejected.status, 1, rejected.stderr);
  }
});

test("proof commands retain portable zeroization and inherited compiler flags", () => {
  const temporary = mkdtempSync(join(tmpdir(), "crypto-proof-flags-"));
  try {
    const capture = join(temporary, "flags");
    for (const command of ["cargo", "python3"]) {
      const path = join(temporary, command);
      writeFileSync(path, '#!/bin/sh\nprintf "%s\\n" "$RUSTFLAGS" >> "$PROOF_FLAGS_CAPTURE"\n');
      chmodSync(path, 0o700);
    }
    for (const inheritedFlags of ["", "-C debuginfo=0"]) {
      for (const scope of ["plaintext-release", "hpke-state"]) {
        const result = spawnSync("/bin/bash", ["scripts/verify_formal_scope.sh"], {
          env: { ...process.env, PATH: `${temporary}:${process.env.PATH}`, FORMAL_SCOPE: scope,
            RUSTFLAGS: inheritedFlags, PROOF_FLAGS_CAPTURE: capture },
          encoding: "utf8",
        });
        assert.equal(result.status, 0, result.stderr);
      }
    }
    const flags = readFileSync(capture, "utf8").trim().split("\n");
    assert.equal(flags.length, 10);
    assert.deepEqual(flags.slice(0, 5), Array(5).fill("--cfg miri"));
    assert.deepEqual(flags.slice(5), Array(5).fill("-C debuginfo=0 --cfg miri"));
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});
