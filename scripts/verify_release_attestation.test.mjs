#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  ReleaseAttestationError,
  requiredWorkflowsForRelease,
  requireLatestSuccessfulRun,
  requireSuccessfulJobs,
  run,
} from "./verify_release_attestation.mjs";

const releaseSha = "a".repeat(40);
const workflowRun = (overrides = {}) => ({
  attempt: 1,
  conclusion: "success",
  databaseId: 100,
  displayTitle: "Code Checks",
  event: "push",
  headBranch: "main",
  headSha: releaseSha,
  status: "completed",
  ...overrides,
});

test("release evidence includes dependency security for every package lane", () => {
  for (const preflight of [
    "crates-package-preflight.yml",
    "swift-package-preflight.yml",
    "kotlin-android-package-preflight.yml",
    "npm-package-preflight.yml",
  ]) {
    assert.deepEqual(requiredWorkflowsForRelease(preflight), [
      "rust-ci.yml",
      "dependency-security.yml",
      preflight,
    ]);
  }
});

test("package preflight attestation is bound to the requested version", () => {
  assert.doesNotThrow(() => {
    requireLatestSuccessfulRun(
      [workflowRun({ displayTitle: "Swift package preflight 0.3.0", event: "workflow_dispatch" })],
      releaseSha,
      "swift-package-preflight.yml",
      "0.3.0",
    );
  });
  assert.throws(
    () => {
      requireLatestSuccessfulRun(
        [workflowRun({ displayTitle: "Kotlin Android package preflight 0.3.0", event: "workflow_dispatch" })],
        releaseSha,
        "kotlin-android-package-preflight.yml",
        "0.4.0",
      );
    },
    (error) =>
      error instanceof ReleaseAttestationError && error.code === "preflight-version-mismatch",
  );
});

test("latest successful workflow attempt authorizes release", () => {
  const latest = requireLatestSuccessfulRun(
    [workflowRun({ attempt: 1 }), workflowRun({ attempt: 2 })],
    releaseSha,
    "rust-ci.yml",
  );
  assert.equal(latest.databaseId, 100);
  assert.equal(latest.attempt, 2);
});

test("release evidence requires every named code-check job", () => {
  const names = [
    "fmt, lint, test, wasm, package",
    "native sanitizer lanes",
    "FFI release artifact and C sanitizer",
    "FFI pointer and panic boundary Miri tests",
    "swift package + vector conformance",
    "kotlin package + vector conformance",
  ];
  const jobs = names.map((name) => ({ name, status: "completed", conclusion: "success" }));
  assert.doesNotThrow(() => requireSuccessfulJobs(jobs, "rust-ci.yml"));
  assert.throws(
    () => requireSuccessfulJobs(jobs.slice(1), "rust-ci.yml"),
    (error) => error instanceof ReleaseAttestationError && error.code === "missing-rust-ci.yml-job",
  );
  assert.throws(
    () => requireSuccessfulJobs([{ ...jobs[0], conclusion: "skipped" }, ...jobs.slice(1)], "rust-ci.yml"),
    (error) => error instanceof ReleaseAttestationError && error.code === "required-rust-ci.yml-job-not-successful",
  );
});

test("package preflight attestation requires matrix and publication jobs", () => {
  const jobs = [
    "verify source SHA",
    "jvm native preflight linux-x86_64",
    "jvm native preflight linux-aarch64",
    "jvm native preflight macos-x86_64",
    "jvm native preflight macos-aarch64",
    "jvm native preflight windows-x86_64",
    "kotlin maven preflight",
    "android aar preflight",
    "android instrumented preflight api 26",
    "android instrumented preflight api 36",
  ].map((name) => ({ name, status: "completed", conclusion: "success" }));
  assert.doesNotThrow(() => requireSuccessfulJobs(jobs, "kotlin-android-package-preflight.yml"));
  assert.throws(
    () => requireSuccessfulJobs(jobs.slice(0, -1), "kotlin-android-package-preflight.yml"),
    ReleaseAttestationError,
  );
});

test("newer failed or in-progress runs invalidate an older success", () => {
  for (const latest of [
    workflowRun({ conclusion: "failure", databaseId: 101 }),
    workflowRun({ conclusion: null, databaseId: 101, status: "in_progress" }),
  ]) {
    assert.throws(
      () => {
        requireLatestSuccessfulRun(
          [workflowRun({ databaseId: 100 }), latest],
          releaseSha,
          "rust-ci.yml",
        );
      },
      ReleaseAttestationError,
    );
  }
});

test("pull-request success cannot substitute for a main push check", () => {
  assert.throws(() => {
    requireLatestSuccessfulRun(
      [workflowRun({ databaseId: 101, event: "pull_request", headBranch: "feature" })],
      releaseSha,
      "rust-ci.yml",
    );
  }, ReleaseAttestationError);
});

test("dependency security must pass on the release commit", () => {
  const latest = requireLatestSuccessfulRun(
    [workflowRun({ displayTitle: "Dependency Security" })],
    releaseSha,
    "dependency-security.yml",
  );
  assert.equal(latest.headSha, releaseSha);
  assert.throws(() => {
    requireLatestSuccessfulRun(
      [workflowRun({ displayTitle: "Dependency Security", event: "pull_request" })],
      releaseSha,
      "dependency-security.yml",
    );
  }, ReleaseAttestationError);
});

test("malformed or wrong-SHA workflow data fails closed", () => {
  assert.throws(() => {
    requireLatestSuccessfulRun(
      [workflowRun({ headSha: "b".repeat(40) })],
      releaseSha,
      "rust-ci.yml",
    );
  }, ReleaseAttestationError);
  assert.throws(() => {
    requireLatestSuccessfulRun({}, releaseSha, "rust-ci.yml");
  }, ReleaseAttestationError);
});

test("silent successful command does not require captured stdout", () => {
  assert.equal(run(process.execPath, ["-e", ""], { capture: false }), "");
});
