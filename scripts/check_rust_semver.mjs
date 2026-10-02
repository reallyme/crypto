#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { resolve } from "node:path";

const BASELINE_PATH = ".semver-baseline";
const MAX_METADATA_BYTES = 32 * 1024 * 1024;
// These crates have known cargo-semver-checks 0.49.0 module-missing false
// positives. Their package contents are still inspected by the preflight.
const TOOL_EXCEPTIONS = ["reallyme-crypto-kmac", "reallyme-crypto-x448"];

const fail = (reason) => {
  console.error(`Rust semver preflight failed: ${reason}`);
  process.exit(1);
};

let baseline;
try {
  baseline = realpathSync(resolve(BASELINE_PATH));
} catch {
  fail("the reviewed semver baseline checkout is missing");
}
const metadata = (manifestPath) => {
  const result = spawnSync("cargo", [
    "metadata", "--format-version", "1", "--no-deps", "--manifest-path", manifestPath,
  ], { encoding: "utf8", maxBuffer: MAX_METADATA_BYTES });
  if (result.error !== undefined || result.status !== 0) {
    fail("workspace metadata could not be read");
  }
  try {
    const value = JSON.parse(result.stdout);
    if (!Array.isArray(value.packages) || !value.packages.every(
      (pkg) => typeof pkg.name === "string" && (pkg.publish === null || Array.isArray(pkg.publish)),
    )) {
      fail("workspace metadata has an invalid package list");
    }
    return value.packages;
  } catch {
    fail("workspace metadata is not valid JSON");
  }
};

const baselineNames = new Set(metadata(`${baseline}/Cargo.toml`).map((pkg) => pkg.name));
const current = metadata("Cargo.toml");
const excluded = current
  .filter((pkg) => pkg.publish?.length === 0 || !baselineNames.has(pkg.name))
  .map((pkg) => pkg.name);
for (const exception of TOOL_EXCEPTIONS) {
  if (!current.some((pkg) => pkg.name === exception) || !baselineNames.has(exception)) {
    fail("a semver tool exception no longer matches both workspaces");
  }
  excluded.push(exception);
}
const uniqueExcluded = [...new Set(excluded)].sort();
console.log(`Rust semver baseline: ${baseline}`);
console.log(`New or private crates excluded: ${uniqueExcluded.join(", ")}`);
const args = ["semver-checks", "--workspace", "--baseline-root", baseline];
for (const name of uniqueExcluded) {
  args.push("--exclude", name);
}
const check = spawnSync("cargo", args, { stdio: "inherit" });
if (check.error !== undefined || !Number.isInteger(check.status)) {
  fail("cargo-semver-checks could not be started");
}
process.exit(check.status);
