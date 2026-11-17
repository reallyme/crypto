// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createReleaseReadinessContext } from "./release-readiness/core.mjs";

const context = createReleaseReadinessContext({ scriptUrl: import.meta.url });
const source = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const steps = (path) => context.extractWorkflowSteps(path);
const claPath = ".github/workflows/cla.yaml";
const osvPath = ".github/workflows/osv-lockfile-scan.yml";

test("crate package builds cannot restore executable or build caches", () => {
  const workflow = source(".github/workflows/crates-package-preflight.yml");
  assert.doesNotMatch(workflow, /uses:\s*(?:Swatinem\/rust-cache|actions\/cache(?:\/restore)?)@/u);
  assert.match(workflow, /cargo install cargo-semver-checks --version 0\.51\.0 --locked/u);
});

test("every pinned tool installer disables fallback downloads", () => {
  let installers = 0;
  for (const name of readdirSync(new URL("../.github/workflows/", import.meta.url))) {
    if (!/\.ya?ml$/u.test(name)) continue;
    const path = `.github/workflows/${name}`;
    const lines = source(path).split(/\r?\n/u);
    for (const step of steps(path)) {
      if (!step.uses?.startsWith("taiki-e/install-action@")) continue;
      installers += 1;
      const inputs = context.readWorkflowStepInputs(path, step, lines);
      assert.equal(inputs.get("fallback"), "none", `${path}: ${step.name}`);
    }
  }
  assert.ok(installers > 0);
});

test("only signature processing has CLA write permissions", () => {
  context.assertWorkflowPermissionsPolicy({
    path: claPath,
    workflow: { contents: "read" },
    jobs: {
      "cla-signatures": { actions: "write", contents: "write", "pull-requests": "write" },
      "cla-merge-queue": { actions: "read", contents: "read", "pull-requests": "read" },
      CLAAssistant: { contents: "none" },
    },
  });
  const workflow = source(claPath);
  assert.doesNotMatch(workflow, /uses:\s*actions\/checkout@/u);
  assert.match(workflow, /needs: \[cla-signatures, cla-merge-queue\]/u);
  assert.match(workflow, /if: >-\n\s+always\(\)/u);
  assert.match(workflow, /github\.event_name != 'merge_group' &&/u);
  assert.match(workflow, /github\.event_name == 'merge_group' &&/u);
});

test("the required CLA check fails for failed, cancelled, or skipped required work", () => {
  const gate = steps(claPath).find((step) => step.name === "Require the applicable CLA result");
  assert.ok(gate?.run);
  const results = ["success", "failure", "cancelled", "skipped"];
  for (const event of ["pull_request_target", "issue_comment", "merge_group", "push"]) {
    for (const signatures of results) {
      for (const queue of results) {
        const result = spawnSync("bash", ["-c", gate.run], {
          encoding: "utf8",
          timeout: 5_000,
          env: { ...process.env, GITHUB_EVENT_NAME: event, SIGNATURE_RESULT: signatures, QUEUE_RESULT: queue },
        });
        assert.equal(result.error, undefined);
        const expected = event === "merge_group"
          ? queue === "success" && signatures === "skipped"
          : ["pull_request_target", "issue_comment"].includes(event) && signatures === "success" && queue === "skipped";
        assert.equal(result.status === 0, expected, `${event}/${signatures}/${queue}`);
      }
    }
  }
});

test("dependency scanners are read-only and preserve separate runtime and tooling policies", () => {
  for (const path of [".github/workflows/dependency-security.yml", osvPath]) {
    context.assertWorkflowPermissionsPolicy({ path, workflow: { contents: "read" }, jobs: {} });
  }
  const caller = source(".github/workflows/dependency-security.yml");
  assert.equal(caller.split(`uses: ./${osvPath}`).length - 1, 2);
  assert.match(caller, /report-name: runtime-OSV-report\n\s+fail-on-vuln: true/u);
  assert.match(caller, /report-name: build-tooling-OSV-report/u);
  assert.match(caller, /fail-on-vuln: false/u);
  const scanSteps = steps(osvPath);
  const prepare = scanSteps.findIndex((step) => step.name === "Prepare scan outputs");
  const scan = scanSteps.findIndex((step) => step.name === "Scan lockfiles");
  const completed = scanSteps.findIndex((step) => step.name === "Require completed scan results");
  const report = scanSteps.findIndex((step) => step.name === "Report vulnerabilities");
  assert.ok(prepare >= 0 && prepare < scan && scan < completed && completed < report);
  assert.equal(scanSteps[completed].condition, null);
  assert.equal(scanSteps[completed].continueOnError, null);
  assert.equal(scanSteps[report].condition, null);
  assert.equal(scanSteps[report].continueOnError, null);
  assert.match(source(osvPath), /--fail-on-vuln=\$\{\{ inputs\.fail-on-vuln \}\}/u);
  for (const name of readdirSync(new URL("../.github/workflows/", import.meta.url))) {
    if (!/\.ya?ml$/u.test(name)) continue;
    const workflow = source(`.github/workflows/${name}`);
    if (name === "codeql.yml") {
      assert.match(workflow, /security-events: write/u);
    } else {
      assert.doesNotMatch(workflow, /security-events:\s*write/u, name);
    }
  }
});

test("checked-in OSV reports cannot mask a scanner failure", (testContext) => {
  const directory = mkdtempSync(join(tmpdir(), "osv-stale-report-"));
  testContext.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const name of ["results.json", "results.sarif"]) {
    writeFileSync(join(directory, name), '{"results":[]}');
  }
  const prepare = steps(osvPath).find((step) => step.name === "Prepare scan outputs");
  assert.ok(prepare?.run);
  assert.equal(prepare.condition, null);
  assert.equal(prepare.continueOnError, null);
  const result = spawnSync("bash", ["-c", prepare.run], { cwd: directory, encoding: "utf8", timeout: 5_000 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(existsSync(join(directory, "results.json")), false);
  assert.equal(existsSync(join(directory, "results.sarif")), false);
});

test("OSV completion guard rejects missing, empty, and malformed results", (testContext) => {
  const directory = mkdtempSync(join(tmpdir(), "osv-completion-"));
  testContext.after(() => rmSync(directory, { recursive: true, force: true }));
  const guard = steps(osvPath).find((step) => step.name === "Require completed scan results");
  assert.ok(guard?.run);
  for (const [contents, expected] of [
    [null, false], ["", false], ["not json", false], ["null", false], ["[]", false],
    ['{"results":[]}', true], ['{"results":[{"packages":[]}]}', true],
  ]) {
    const path = join(directory, "results.json");
    if (contents !== null) writeFileSync(path, contents);
    const result = spawnSync("bash", ["-c", guard.run], { cwd: directory, encoding: "utf8", timeout: 5_000 });
    assert.equal(result.error, undefined);
    assert.equal(result.status === 0, expected, contents ?? "missing");
  }
});
