// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { REQUIRED_WORKFLOW_GATES, workflowGateViolation } from "./workflow_gate_policy.mjs";

const requiredCommand = "cargo clippy --workspace -- -D warnings";
const workflow = `jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - name: Check code
        run: |
          ${requiredCommand}
`;

test("required release gate remains unconditional", () => {
  assert.equal(workflowGateViolation(workflow, [requiredCommand]), null);
});

test("reviewed release workflows have executable required gates", () => {
  for (const [path, commands] of REQUIRED_WORKFLOW_GATES) {
    const source = readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
    assert.equal(workflowGateViolation(source, commands), null, path);
  }
});

test("quoted and unquoted conditional keys cannot soften a release gate", () => {
  for (const key of ["if", "continue-on-error", '"if"', '"continue-on-error"', "'if'", "'continue-on-error'"]) {
    const changed = workflow.replace("        run: |", `        ${key}: true\n        run: |`);
    assert.equal(workflowGateViolation(changed, [requiredCommand]), "conditional-gate");
  }
});

test("required command failures cannot be masked by shell success operators", () => {
  for (const suffix of [" || true", " || :", " ; true", " || true # ignored"]) {
    const changed = workflow.replace(requiredCommand, `${requiredCommand}${suffix}`);
    assert.equal(workflowGateViolation(changed, [requiredCommand]), "masked-required-command");
  }
  const prefixed = workflow.replace(requiredCommand, `true || ${requiredCommand}`);
  assert.equal(workflowGateViolation(prefixed, [requiredCommand]), "masked-required-command");
});

test("a required command must occur in an executable workflow step", () => {
  assert.equal(workflowGateViolation(workflow, ["cargo deny check"]), "missing-required-command");
  const changed = workflow.replace("        run: |", "        description: |");
  assert.equal(workflowGateViolation(changed, [requiredCommand]), "required-command-outside-run");
});
