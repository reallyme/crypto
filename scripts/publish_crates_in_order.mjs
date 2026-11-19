// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { constants, copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, sep } from "node:path";

import {
  PublishFailureCode,
  PublishRetryError,
  PublishRetryKind,
  publishWithRetries,
} from "./publish_retry_policy.mjs";

const MODE_INSPECT = "inspect";
const MODE_ORDER = "order";
const MODE_PUBLISH = "publish";
const MODE_STAGE = "stage";
const args = process.argv.slice(2);
const mode = args[0] ?? MODE_INSPECT;
const allowDirty = args.includes("--allow-dirty");
const unknownArgs = args.slice(1).filter((arg) => arg !== "--allow-dirty");
const releaseVersion = process.env.RELEASE_VERSION ?? "";
const archiveDirectory = process.env.CRATE_ARCHIVE_DIR ?? "";

if (
  ![MODE_INSPECT, MODE_ORDER, MODE_STAGE, MODE_PUBLISH].includes(mode) ||
  unknownArgs.length !== 0
) {
  console.error(
    `usage: node scripts/publish_crates_in_order.mjs ${MODE_INSPECT}|${MODE_ORDER}|${MODE_STAGE}|${MODE_PUBLISH} [--allow-dirty]`,
  );
  process.exit(2);
}

if (allowDirty && mode !== MODE_INSPECT && mode !== MODE_ORDER) {
  console.error("--allow-dirty is only supported for local package inspection and order checks");
  process.exit(2);
}

if ([MODE_STAGE, MODE_PUBLISH].includes(mode) && (releaseVersion.length === 0 || !isAbsolute(archiveDirectory))) {
  console.error("RELEASE_VERSION and an absolute CRATE_ARCHIVE_DIR are required for crate staging and publication.");
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
    env: options.env ?? process.env,
  });
  if (result.error) {
    throw result.error;
  }
  return result;
}

function sleepMs(delayMs) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, delayMs);
}

const privacyResult = run("python3", ["-B", "scripts/check_repository_privacy.py", "--index"]);
if (privacyResult.status !== 0) process.exit(privacyResult.status ?? 1);

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
requirePublishOrderBefore("reallyme-crypto-proto", "reallyme-crypto-core");
requirePublishOrderBefore("reallyme-crypto-proto", "reallyme-crypto-hpke");

function inspectPackages() {
  // Select the entire release set so Cargo resolves unpublished workspace
  // dependencies together instead of substituting older registry packages.
  const selectors = ordered.flatMap((pkg) => ["-p", pkg.name]);
  for (const operation of [["package", "--list"], ["publish", "--dry-run"]]) {
    const args = [...operation, "--locked", ...selectors];
    if (allowDirty) args.push("--allow-dirty");
    const result = run("cargo", args);
    if (result.status !== 0) process.exit(result.status ?? 1);
  }
}

const archiveName = (pkg) => `${pkg.name}-${pkg.version}.crate`;
const packageOutput = join(metadata.target_directory, "package");
const packagedArchive = (pkg) => join(packageOutput, archiveName(pkg));
const preflightArchive = (pkg) => join(archiveDirectory, archiveName(pkg));
const archiveDigest = (path) => createHash("sha256").update(readFileSync(path)).digest();

function assertArchivePrivacy(pkg, path) {
  const sourceRoot = relative(metadata.workspace_root, dirname(pkg.manifest_path)).split(sep).join("/");
  const checked = run("python3", [
    "-B", "scripts/check_release_privacy.py", "--archive", path,
    "--source-root", sourceRoot || ".", "--strip-components", "1",
  ]);
  if (checked.status !== 0) process.exit(checked.status ?? 1);
}

function stageArchives() {
  // Rust 1.100's workspace publish dry run keeps the exact upload archives
  // in tmp-crate. The single-crate cargo package command uses package/.
  const verifiedOutput = join(packageOutput, "tmp-crate");
  for (const pkg of ordered) assertArchivePrivacy(pkg, join(verifiedOutput, archiveName(pkg)));
  mkdirSync(archiveDirectory);
  for (const pkg of ordered) {
    copyFileSync(join(verifiedOutput, archiveName(pkg)), preflightArchive(pkg), constants.COPYFILE_EXCL);
  }
}

function publishPackage(pkg) {
  // The exact release SHA has already passed the tokenless workspace publish
  // dry run. Do not rerun dependency build scripts or proc macros with a
  // registry credential in this process.
  const args = ["publish", "-p", pkg.name, "--locked", "--no-verify"];
  const packagingEnv = { ...process.env };
  delete packagingEnv.CARGO_REGISTRY_TOKEN;
  try {
    publishWithRetries({
      attemptPublish: () => {
        const repacked = run("cargo", ["package", "-p", pkg.name, "--locked", "--no-verify"],
          { capture: true, env: packagingEnv });
        if (repacked.status !== 0) return repacked;
        assertArchivePrivacy(pkg, packagedArchive(pkg));
        if (!archiveDigest(packagedArchive(pkg)).equals(archiveDigest(preflightArchive(pkg)))) {
          console.error(`${pkg.name} packaged bytes differ from the reviewed preflight archive.`);
          process.exit(1);
        }
        return run("cargo", args, { capture: true });
      },
      sleep: sleepMs,
      onRetry(kind, delayMs) {
        if (kind === PublishRetryKind.RateLimit) {
          console.log(
            `crates.io rate-limited publish requests; retrying ${pkg.name} in ${Math.ceil(delayMs / 1000)}s...`,
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
        // A version match alone cannot prove the published crate has this
        // release commit's packaged files or resolved dependencies.
        console.error(
          `${pkg.name} ${pkg.version} already exists on crates.io; verify its packaged contents and dependency lock before any manual resume.`,
        );
        process.exit(error.status);
      }
      console.error(`${pkg.name} ${pkg.version} publish failed: ${error.code}.`);
      process.exit(error.status);
    }
    console.error(`${pkg.name} ${pkg.version} publish failed: internal-runner-failure.`);
    process.exit(1);
  }
}

if (mode === MODE_STAGE) {
  stageArchives();
  process.exit(0);
}

if (mode === MODE_INSPECT) {
  inspectPackages();
} else if (mode === MODE_PUBLISH) {
  for (const pkg of ordered) publishPackage(pkg);
}
