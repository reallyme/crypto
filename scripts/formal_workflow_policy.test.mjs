// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const root = new URL("../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root), "utf8");

test("formal proofs require an explicit manual dispatch", () => {
  const config = JSON.parse(read(".github/release-readiness.json"));
  assert.equal(config.lanes.formal.mode, "manual");
  assert.match(read(".github/workflows/formal-verification.yml"), /\non:\n  workflow_dispatch:\n\npermissions:/u);
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

test("required CI omits the manual proof workflow", () => {
  assert.doesNotMatch(read(".github/workflows/ci.yml"), /uses: [^\n]*formal-verification[.]yml/u);
});

test("manual dispatch retains the complete proof runners", () => {
  const workflow = read(".github/workflows/formal-verification.yml");
  for (const runner of ["scripts/verify_tamarin.sh", "scripts/verify_reference_encoder_proofs.sh", "scripts/verify_formal_scope.sh"]) assert.ok(workflow.includes(runner));
  assert.match(workflow, /git rev-parse --verify HEAD/u);
  assert.doesNotMatch(workflow, /verified_sha:/u);
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
    for (const scope of ["plaintext-release", "hpke-state"]) {
      const result = spawnSync("/bin/bash", ["scripts/verify_formal_scope.sh"], {
        env: { ...process.env, PATH: `${temporary}:${process.env.PATH}`, FORMAL_SCOPE: scope,
          RUSTFLAGS: "-C debuginfo=0", PROOF_FLAGS_CAPTURE: capture },
        encoding: "utf8",
      });
      assert.equal(result.status, 0, result.stderr);
    }
    const flags = readFileSync(capture, "utf8").trim().split("\n");
    assert.equal(flags.length, 5);
    for (const value of flags) assert.equal(value, "-C debuginfo=0 --cfg miri");
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});
