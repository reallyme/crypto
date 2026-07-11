// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";

const MODE_INSPECT = "inspect";
const MODE_PUBLISH = "publish";
const args = process.argv.slice(2);
const mode = args[0] ?? MODE_INSPECT;
const allowDirty = args.includes("--allow-dirty");
const unknownArgs = args.slice(1).filter((arg) => arg !== "--allow-dirty");

if ((mode !== MODE_INSPECT && mode !== MODE_PUBLISH) || unknownArgs.length !== 0) {
  console.error(
    `usage: node scripts/publish_crates_in_order.mjs ${MODE_INSPECT}|${MODE_PUBLISH} [--allow-dirty]`,
  );
  process.exit(2);
}

if (allowDirty && mode !== MODE_INSPECT) {
  console.error("--allow-dirty is only supported for local package inspection");
  process.exit(2);
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: options.capture ? "pipe" : "inherit",
  });
  if (result.error) {
    throw result.error;
  }
  return result;
}

const metadataResult = run("cargo", ["metadata", "--format-version", "1", "--no-deps"], {
  capture: true,
});

if (metadataResult.status !== 0) {
  process.stderr.write(metadataResult.stderr);
  process.exit(metadataResult.status ?? 1);
}

const metadata = JSON.parse(metadataResult.stdout);

function isPublishablePackage(pkg) {
  return !(Array.isArray(pkg.publish) && pkg.publish.length === 0);
}

const publishable = new Map();
for (const pkg of metadata.packages) {
  if (isPublishablePackage(pkg)) {
    publishable.set(pkg.name, pkg);
  }
}

const visiting = new Set();
const visited = new Set();
const ordered = [];

function visit(pkg) {
  if (visited.has(pkg.name)) {
    return;
  }
  if (visiting.has(pkg.name)) {
    console.error(`workspace publish dependency cycle at ${pkg.name}`);
    process.exit(1);
  }

  visiting.add(pkg.name);
  for (const dep of pkg.dependencies) {
    const depName = dep.package ?? dep.name;
    if (dep.source === null && publishable.has(depName)) {
      visit(publishable.get(depName));
    }
  }
  visiting.delete(pkg.name);
  visited.add(pkg.name);
  ordered.push(pkg);
}

for (const pkg of publishable.values()) {
  visit(pkg);
}

console.log(`Publish order (${ordered.length} crates):`);
for (const pkg of ordered) {
  console.log(`- ${pkg.name} ${pkg.version}`);
}

function publishPackage(pkg) {
  const args = ["publish", "-p", pkg.name, "--locked"];
  const token = process.env.CARGO_REGISTRY_TOKEN;
  if (token) {
    args.push("--token", token);
  }

  for (let attempt = 1; attempt <= 8; attempt += 1) {
    const result = run("cargo", args, { capture: true });
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);

    if (result.status === 0) {
      return;
    }

    const combined = `${result.stdout}\n${result.stderr}`;
    if (combined.includes("already uploaded") || combined.includes("already exists")) {
      console.log(`${pkg.name} ${pkg.version} is already published; continuing.`);
      return;
    }

    if (!combined.includes("no matching package named") || attempt === 8) {
      process.exit(result.status ?? 1);
    }

    const delayMs = attempt * 15000;
    console.log(
      `crates.io index has not observed a freshly published dependency yet; retrying ${pkg.name} in ${delayMs / 1000}s...`,
    );
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, delayMs);
  }
}

for (const pkg of ordered) {
  if (mode === MODE_INSPECT) {
    const args = ["package", "-p", pkg.name, "--list"];
    if (allowDirty) {
      args.push("--allow-dirty");
    }
    const result = run("cargo", args);
    if (result.status !== 0) {
      process.exit(result.status ?? 1);
    }
    continue;
  }

  publishPackage(pkg);
}
