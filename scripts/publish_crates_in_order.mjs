// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";

import {
  PublishFailureCode,
  PublishRetryError,
  PublishRetryKind,
  publishWithRetries,
} from "./publish_retry_policy.mjs";

const MODE_INSPECT = "inspect";
const MODE_ORDER = "order";
const MODE_PUBLISH = "publish";
const args = process.argv.slice(2);
const mode = args[0] ?? MODE_INSPECT;
const allowDirty = args.includes("--allow-dirty");
const unknownArgs = args.slice(1).filter((arg) => arg !== "--allow-dirty");
const releaseVersion = process.env.RELEASE_VERSION ?? "";

if (
  (mode !== MODE_INSPECT && mode !== MODE_ORDER && mode !== MODE_PUBLISH) ||
  unknownArgs.length !== 0
) {
  console.error(
    `usage: node scripts/publish_crates_in_order.mjs ${MODE_INSPECT}|${MODE_ORDER}|${MODE_PUBLISH} [--allow-dirty]`,
  );
  process.exit(2);
}

if (allowDirty && mode !== MODE_INSPECT && mode !== MODE_ORDER) {
  console.error("--allow-dirty is only supported for local package inspection and order checks");
  process.exit(2);
}

if (mode === MODE_PUBLISH && releaseVersion.length === 0) {
  console.error("RELEASE_VERSION must be set when publishing crates.");
  process.exit(2);
}

if (releaseVersion.length !== 0 && !/^[0-9]+[.][0-9]+[.][0-9]+$/.test(releaseVersion)) {
  console.error("RELEASE_VERSION must be an exact semver release such as 0.3.0.");
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

function sleepMs(delayMs) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, delayMs);
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

function dependencyPackageName(dep) {
  return dep.package ?? dep.name;
}

function isWorkspacePathDependency(dep) {
  return (
    dep.source === null &&
    typeof dep.path === "string" &&
    publishable.has(dependencyPackageName(dep))
  );
}

function isPublishOrderingDependency(dep) {
  return isWorkspacePathDependency(dep) && dep.kind !== "dev";
}

function parseVersion(version) {
  const parts = version.split(".");
  if (parts.length !== 3) {
    return null;
  }

  const parsed = parts.map((part) => Number.parseInt(part, 10));
  if (parsed.some((part) => !Number.isSafeInteger(part) || part < 0)) {
    return null;
  }

  return {
    major: parsed[0],
    minor: parsed[1],
    patch: parsed[2],
  };
}

function isCaretReqSatisfied(req, version) {
  if (!req.startsWith("^")) {
    return req === `=${version}` || req === version;
  }

  const minimum = parseVersion(req.slice(1));
  const actual = parseVersion(version);
  if (minimum === null || actual === null) {
    return false;
  }

  if (actual.major !== minimum.major) {
    return false;
  }

  if (minimum.major === 0 && actual.minor !== minimum.minor) {
    return false;
  }

  if (actual.minor < minimum.minor) {
    return false;
  }

  if (actual.minor === minimum.minor && actual.patch < minimum.patch) {
    return false;
  }

  return true;
}

function checkPathDependencyVersions() {
  const failures = [];
  for (const pkg of publishable.values()) {
    for (const dep of pkg.dependencies) {
      if (!isPublishOrderingDependency(dep)) {
        continue;
      }

      const target = publishable.get(dependencyPackageName(dep));
      if (!isCaretReqSatisfied(dep.req, target.version)) {
        failures.push(
          `${pkg.name} depends on ${dep.name} with ${dep.req}; local version is ${target.version}`,
        );
      }
    }
  }

  if (failures.length !== 0) {
    console.error("publishable workspace path dependency versions are stale:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }
}

function checkReleaseVersion() {
  if (releaseVersion.length === 0) {
    return;
  }

  const failures = [];
  for (const pkg of publishable.values()) {
    if (pkg.version !== releaseVersion) {
      failures.push(`${pkg.name} is ${pkg.version}; expected ${releaseVersion}`);
    }
  }

  if (failures.length !== 0) {
    console.error("publishable crate versions do not match RELEASE_VERSION:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
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
    const depName = dependencyPackageName(dep);
    if (isPublishOrderingDependency(dep) && publishable.has(depName)) {
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

checkPathDependencyVersions();
checkReleaseVersion();

const orderedIndexByName = new Map();
ordered.forEach((pkg, index) => {
  orderedIndexByName.set(pkg.name, index);
});

function requirePublishOrderBefore(dependencyName, dependentName) {
  const dependencyIndex = orderedIndexByName.get(dependencyName);
  const dependentIndex = orderedIndexByName.get(dependentName);
  if (dependencyIndex === undefined) {
    console.error(
      `${dependencyName} must be publishable and included in the crates.io release order`,
    );
    process.exit(1);
  }
  if (dependentIndex === undefined) {
    console.error(
      `${dependentName} must be publishable and included in the crates.io release order`,
    );
    process.exit(1);
  }
  if (dependencyIndex >= dependentIndex) {
    console.error(`${dependencyName} must be published before ${dependentName}`);
    process.exit(1);
  }
}

requirePublishOrderBefore("reallyme-crypto-proto", "reallyme-crypto");

function unresolvedRegistryPackages(output) {
  const missing = [];
  const noMatchPattern = /no matching package named `([^`]+)` found/g;
  for (let match = noMatchPattern.exec(output); match !== null; match = noMatchPattern.exec(output)) {
    missing.push(match[1]);
  }

  const versionSelectPattern = /failed to select a version for the requirement `([^`\s]+) =/g;
  for (
    let match = versionSelectPattern.exec(output);
    match !== null;
    match = versionSelectPattern.exec(output)
  ) {
    missing.push(match[1]);
  }

  return [...new Set(missing)];
}

function isEarlierWorkspaceDependency(pkg, depName) {
  const pkgIndex = orderedIndexByName.get(pkg.name);
  const depIndex = orderedIndexByName.get(depName);
  return depIndex !== undefined && pkgIndex !== undefined && depIndex < pkgIndex;
}

function inspectPackage(pkg) {
  const listArgs = ["package", "-p", pkg.name, "--list"];
  if (allowDirty) {
    listArgs.push("--allow-dirty");
  }
  const listResult = run("cargo", listArgs);
  if (listResult.status !== 0) {
    process.exit(listResult.status ?? 1);
  }

  const dryRunArgs = ["publish", "-p", pkg.name, "--dry-run", "--locked"];
  if (allowDirty) {
    dryRunArgs.push("--allow-dirty");
  }
  const dryRunResult = run("cargo", dryRunArgs, { capture: true });
  process.stdout.write(dryRunResult.stdout);
  process.stderr.write(dryRunResult.stderr);
  if (dryRunResult.status === 0) {
    return;
  }

  const combined = `${dryRunResult.stdout}\n${dryRunResult.stderr}`;
  const missing = unresolvedRegistryPackages(combined);
  if (
    missing.length !== 0 &&
    missing.every((depName) => isEarlierWorkspaceDependency(pkg, depName))
  ) {
    console.log(
      `${pkg.name} dry-run reached unpublished ordered workspace dependencies: ${missing.join(", ")}`,
    );
    return;
  }

  process.exit(dryRunResult.status ?? 1);
}

function publishPackage(pkg) {
  const args = ["publish", "-p", pkg.name, "--locked"];
  try {
    publishWithRetries({
      attemptPublish: () => run("cargo", args, { capture: true }),
      sleep: sleepMs,
      onRetry(kind, delayMs) {
        if (kind === PublishRetryKind.RateLimit) {
          console.log(
            `crates.io rate-limited new crate uploads; retrying ${pkg.name} in ${Math.ceil(delayMs / 1000)}s...`,
          );
          return;
        }
        console.log(
          `crates.io index has not observed a freshly published dependency yet; retrying ${pkg.name} in ${delayMs / 1000}s...`,
        );
      },
    });
  } catch (error) {
    if (error instanceof PublishRetryError) {
      if (error.code === PublishFailureCode.AlreadyPublished) {
        console.log(
          `${pkg.name} ${pkg.version} is already published on crates.io; continuing release resume.`,
        );
        return;
      }
      console.error(`${pkg.name} ${pkg.version} publish failed: ${error.code}.`);
      process.exit(error.status);
    }
    console.error(`${pkg.name} ${pkg.version} publish failed: internal-runner-failure.`);
    process.exit(1);
  }
}

for (const pkg of ordered) {
  if (mode === MODE_ORDER) {
    continue;
  }

  if (mode === MODE_INSPECT) {
    inspectPackage(pkg);
    continue;
  }

  publishPackage(pkg);
}
