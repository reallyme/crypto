// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createReleaseReadinessContext } from "./release-readiness/core.mjs";

const context = createReleaseReadinessContext({ scriptUrl: import.meta.url });
const workflowPath = ".github/workflows/external-vectors-audit.yml";
const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

test("HPKE corpus adapters participate in ordinary native workspace tests", () => {
  for (const [name, count] of [["rfc9180_hpke", 5], ["hpke_pq", 3]]) {
    const source = read(`tools/external-vector-audit/tests/${name}.rs`);
    assert.match(source, /^#!\[cfg\(feature = "native"\)\]/mu);
    assert.doesNotMatch(source, /#\[ignore/u);
    assert.equal([...source.matchAll(/^#\[test\]/gmu)].length, count);
  }
});

test("HPKE source changes trigger an unconditional corpus run before the scheduled audit", () => {
  const source = read(workflowPath);
  assert.match(source, /pull_request:\n\s+paths:\n\s+- "crates\/hpke\/\*\*"/u);
  const matches = context.extractWorkflowSteps(workflowPath).filter(
    ({ name }) => name === "Execute HPKE RFC 9180 and PQ draft corpora",
  );
  assert.equal(matches.length, 1);
  const [step] = matches;
  assert.equal(step.job, "integrity");
  assert.equal(step.condition, null);
  assert.equal(step.continueOnError, null);
  assert.equal(step.run, "cargo test --locked -p external-vector-audit --no-default-features --features native --test rfc9180_hpke --test hpke_pq");
  const integrity = source.split("  integrity:\n")[1]?.split("  deep-audit:\n")[0];
  assert.ok(integrity);
  assert.doesNotMatch(integrity, /^ {4}(?:if|continue-on-error):/mu);
  assert.doesNotMatch(source, /--test rfc9180_hpke -- --ignored/u);
});

test("the supplementary adapter runner selects normal HPKE tests and ignored heavy tests", (testContext) => {
  const directory = mkdtempSync(join(tmpdir(), "hpke-vector-ci-"));
  testContext.after(() => rmSync(directory, { recursive: true, force: true }));
  mkdirSync(join(directory, "scripts"));
  copyFileSync(new URL("./check_external_vector_adapters.sh", import.meta.url), join(directory, "scripts/adapters.sh"));
  writeFileSync(join(directory, "scripts/run_exact_cargo_test.sh"), `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\0' "$@" >> "$ADAPTER_CAPTURE"
printf '\\n' >> "$ADAPTER_CAPTURE"
`);
  const capture = join(directory, "arguments");
  const result = spawnSync("bash", ["scripts/adapters.sh"], {
    cwd: directory, encoding: "utf8", timeout: 10_000,
    env: { ...process.env, ADAPTER_CAPTURE: capture },
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  const invocations = readFileSync(capture, "utf8").trimEnd().split("\0\n").map((line) => line.split("\0"));
  let hpke = 0;
  let ignored = 0;
  for (const args of invocations) {
    const target = args[args.indexOf("--test") + 1];
    if (target === "rfc9180_hpke" || target === "hpke_pq") {
      assert.equal(args.includes("--ignored"), false);
      hpke += 1;
    } else {
      assert.equal(args[0], "--ignored");
      ignored += 1;
    }
  }
  assert.equal(hpke, 8);
  assert.equal(ignored, 11);
});
