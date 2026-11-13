// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
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

test("every SDK keeps one unconditional source-policy owner", () => {
  const path = ".github/workflows/rust-ci.yml";
  const source = readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
  const commands = REQUIRED_WORKFLOW_GATES.find(([name]) => name === path)[1];
  for (const mode of ["typescript", "swift", "kotlin"]) {
    const command = `node scripts/run_pinned_release_readiness.mjs --${mode}-source`;
    assert.equal(source.split(command).length - 1, 1, mode);
    assert.ok(commands.includes(command), mode);
    assert.equal(workflowGateViolation(source.replace(command, "echo omitted"), commands),
      "missing-required-command", mode);
  }
  assert.match(source, /name: typescript package \+ browser conformance/u);
  assert.ok(source.indexOf("--typescript-source") < source.indexOf("run: node packages/ts/scripts/browser-wasm-test.mjs"));
  assert.doesNotMatch(source, /npm --prefix packages\/ts run test:browser/u);
  const kotlin = source.slice(source.indexOf("\n  kotlin:\n"));
  assert.ok(kotlin.indexOf("Install pinned Android SDK packages") < kotlin.indexOf("--kotlin-source"));
  assert.ok(kotlin.includes('"platforms;android-37.0" "ndk;29.0.14206865"'));
});

test("only ordinary push and PR checks cancel superseded runs", () => {
  for (const name of ["rust-ci", "codeql", "dependency-security", "protobuf-ci", "fuzz"]) {
    const source = readFileSync(new URL(`../.github/workflows/${name}.yml`, import.meta.url), "utf8");
    assert.ok(source.includes("(github.event_name == 'push' && github.ref)"), name);
    assert.ok(source.includes("cancel-in-progress: ${{ github.event_name == 'pull_request' || github.event_name == 'push' }}"), name);
  }
  for (const name of ["crates", "swift-package", "kotlin-android-package", "npm-package"]) {
    const source = readFileSync(new URL(`../.github/workflows/${name}-release.yml`, import.meta.url), "utf8");
    assert.ok(source.includes("cancel-in-progress: false"), name);
  }
});
