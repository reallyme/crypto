// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const root = new URL("../", import.meta.url);
const sha = "a".repeat(40);
const cratesVersion = /^version = "([^"]+)"$/mu.exec(
  readFileSync(new URL("crates/crypto/Cargo.toml", root), "utf8"),
)[1];

const shellStep = (filename, name) => {
  const source = readFileSync(new URL(`.github/workflows/${filename}.yml`, root), "utf8");
  const lines = source.split("\n");
  const start = lines.indexOf(`      - name: ${name}`);
  assert.notEqual(start, -1, filename);
  const end = lines.findIndex((line, index) => index > start && /^ {0,6}\S/u.test(line));
  const step = lines.slice(start, end === -1 ? lines.length : end);
  const run = step.indexOf("        run: |");
  assert.notEqual(run, -1, filename);
  return { source, script: step.slice(run + 1).map((line) => line.slice(10)).join("\n") };
};

const runShell = (script, env) => spawnSync(
  "bash", ["--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
  { cwd: root, env: { PATH: process.env.PATH, ...env }, encoding: "utf8", timeout: 10_000 },
);

const resolveGit = `
git() {
  case "$*" in
    'fetch --no-tags origin main'|"checkout --detach $GITHUB_SHA") return 0 ;;
    "merge-base --is-ancestor $GITHUB_SHA origin/main") return 0 ;;
    *) return 97 ;;
  esac
}
`;

for (const [ecosystem, preflight, publish] of [
  ["crates", "crates-package-preflight", "crates-release"],
  ["npm", "npm-package-preflight", "npm-package-release"],
  ["swift", "swift-package-preflight", "swift-package-release"],
  ["maven", "kotlin-android-package-preflight", "kotlin-android-package-release"],
]) {
  test(`${ecosystem} preflight reports only validated release inputs`, (t) => {
    const scratch = mkdtempSync(join(tmpdir(), "crypto-release-form-"));
    t.after(() => rmSync(scratch, { recursive: true, force: true }));
    const { source, script } = shellStep(preflight, "Show release form inputs");
    assert.ok(source.includes(`run-name: Preflight ${ecosystem} ` +
      "${{ inputs.version }} ${{ inputs.source_sha }}"));
    assert.ok(source.includes(`PUBLISH_WORKFLOW: ${publish}.yml`));
    assert.ok(source.includes("SOURCE_SHA: ${{ inputs.source_sha }}"));
    const env = {
      GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_REF: "refs/heads/main", GITHUB_SHA: sha,
      SOURCE_SHA: sha, RELEASE_VERSION: cratesVersion, SHA_PATTERN: "^[0-9a-f]{40}$",
      VERSION_PATTERN: "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$",
      GITHUB_STEP_SUMMARY: join(scratch, "summary"), PUBLISH_WORKFLOW: `${publish}.yml`,
    };
    assert.equal(runShell(script, env).status, 0);
    const summary = readFileSync(env.GITHUB_STEP_SUMMARY, "utf8");
    assert.ok(summary.includes(["**Version**", "```text", cratesVersion, "```"].join("\n")));
    assert.ok(summary.includes(["**Source SHA**", "```text", sha, "```"].join("\n")));
    assert.ok(summary.includes(
      `gh workflow run ${publish}.yml --repo reallyme/crypto --ref main -f version=${cratesVersion} -f source_sha=${sha}`,
    ));
    rmSync(env.GITHUB_STEP_SUMMARY);
    for (const invalid of [{ SOURCE_SHA: "b".repeat(40) }, { RELEASE_VERSION: "0.4.1\nother" },
      { GITHUB_REF: "refs/heads/other" }, { GITHUB_EVENT_NAME: "push" }]) {
      const rejected = runShell(script, { ...env, ...invalid });
      assert.equal(rejected.status, 0, rejected.stderr);
      assert.match(rejected.stderr, /Cannot show release inputs/u);
      assert.equal(existsSync(env.GITHUB_STEP_SUMMARY), false);
    }
  });

  test(`${ecosystem} publish selects an exact SHA from main history`, () => {
    const { source, script } = shellStep(publish, "Select source from main history");
    assert.match(source, /\n      version:\n        description: [^\n]+\n        required: true\n        type: string\n        default: [^\n]+\n      source_sha:/u);
    assert.match(source, /\n      source_sha:\n        description: [^\n]+\n        required: true\n        type: string/u);
    assert.ok(source.includes(`        default: ${cratesVersion}\n      source_sha:`));
    assert.ok(source.includes("RELEASE_VERSION: ${{ inputs.version }}"));
    assert.match(source, /id: candidate/u);
    assert.match(source, /digest-mismatch: error/u);
    const env = { GITHUB_REF: "refs/heads/main", GITHUB_SHA: sha, SOURCE_SHA: sha, RELEASE_VERSION: cratesVersion };
    const resolved = runShell(resolveGit + script, env);
    assert.equal(resolved.status, 0, resolved.stderr);
    const swapped = runShell(script, { ...env, RELEASE_VERSION: sha });
    assert.equal(swapped.status, 1);
    assert.match(swapped.stdout, /Enter the package version from preflight/u);
    for (const override of [{ SOURCE_SHA: "b".repeat(40) }, { SOURCE_SHA: "" },
      { GITHUB_REF: "refs/heads/other" }]) {
      assert.notEqual(runShell(resolveGit + script, { ...env, ...override }).status, 0);
    }
  });
}
