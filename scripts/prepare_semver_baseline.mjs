#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { lstatSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// The tagged 0.3.9 Swift manifest is the last immutable release source before 0.3.10.
export const RUST_SEMVER_BASELINE_COMMIT = "fbd30bcc205eec791bc8df70bccd75397ee40664";

const BASELINE_CODEC_VERSION = "0.2.3";
const MAX_MANIFEST_BYTES = 65_536;
const MAX_LOCKFILE_BYTES = 524_288;

const BASELINE_DEPENDENCIES = Object.freeze([
  Object.freeze({
    path: "crates/crypto/dispatch/Cargo.toml",
    packageName: "reallyme-codec-multikey",
  }),
  Object.freeze({
    path: "crates/p256/Cargo.toml",
    packageName: "reallyme-codec-pem",
  }),
  Object.freeze({
    path: "crates/jwk/Cargo.toml",
    packageName: "reallyme-codec-base64url",
  }),
  Object.freeze({
    path: "crates/jwk/Cargo.toml",
    packageName: "reallyme-codec-jcs",
  }),
  Object.freeze({
    path: "crates/jwk-multikey/Cargo.toml",
    packageName: "reallyme-codec-multikey",
  }),
  Object.freeze({
    path: "crates/jwk-multikey/Cargo.toml",
    packageName: "reallyme-codec-base64url",
  }),
]);

const BASELINE_CHECKSUMS = Object.freeze({
  "reallyme-codec-base64url": "f6bf7a30f229edf6e3236df0b2b11c522da128cfbdcc3b0dfca4912b7f6463a0",
  "reallyme-codec-jcs": "4e8f5718cd2bdbcdc6b6b9eb91ac77ea35aaec6051c7222367090ad52b1fc551",
  "reallyme-codec-multibase": "e38491c026515d692ac863bd277eba813a399053bc3740550f0cb3e6206bd003",
  "reallyme-codec-multicodec": "9400a5df3a8bc8e66e87be32a2563dd631f923c29418ce582949ac6ba4fcfa8f",
  "reallyme-codec-multikey": "86018a0dd6bad08ad4f48f5a1d62c8db722f2f4407bd0991824fdd8ca1744e0f",
  "reallyme-codec-pem": "7bcaf67e2614ae686fab132732937779dfaaa93bc527c0f1dea0637791432b81",
});

const ERROR_MESSAGES = Object.freeze({
  INVALID_ARGUMENT: "the semver baseline path is invalid",
  INVALID_CHECKOUT: "the semver baseline checkout does not match the reviewed commit",
  INVALID_FILE: "a semver baseline file is missing, unsafe, or outside its size boundary",
  INVALID_DEPENDENCY: "the semver baseline dependency policy does not match the reviewed release",
  INVALID_LOCKFILE: "the semver baseline lockfile provenance does not match the reviewed release",
  WRITE_FAILED: "the semver baseline dependency freeze could not be written",
});

export class SemverBaselineError extends Error {
  constructor(code) {
    const acceptedCode = Object.hasOwn(ERROR_MESSAGES, code) ? code : "INVALID_FILE";
    super(ERROR_MESSAGES[acceptedCode]);
    this.name = "SemverBaselineError";
    this.code = acceptedCode;
  }
}

const fail = (code) => {
  throw new SemverBaselineError(code);
};

const readRegularFile = (path, maximumBytes) => {
  let status;
  try {
    status = lstatSync(path);
  } catch {
    fail("INVALID_FILE");
  }
  if (status.isSymbolicLink() || !status.isFile() || status.size === 0 || status.size > maximumBytes) {
    fail("INVALID_FILE");
  }
  try {
    return readFileSync(path, "utf8");
  } catch {
    fail("INVALID_FILE");
  }
};

const escapeRegExpLiteral = (value) => value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");

const assertLockfileProvenance = (root) => {
  const lockfile = readRegularFile(resolve(root, "Cargo.lock"), MAX_LOCKFILE_BYTES);
  for (const [packageName, checksum] of Object.entries(BASELINE_CHECKSUMS)) {
    const block = new RegExp(
      `name = "${escapeRegExpLiteral(packageName)}"\\n` +
        `version = "${escapeRegExpLiteral(BASELINE_CODEC_VERSION)}"\\n` +
        'source = "registry\\+https://github\\.com/rust-lang/crates\\.io-index"\\n' +
        `checksum = "${checksum}"`,
      "u",
    );
    if (!block.test(lockfile)) {
      fail("INVALID_LOCKFILE");
    }
  }
};

export const prepareSemverBaseline = (root) => {
  assertLockfileProvenance(root);
  const manifests = new Map();
  for (const dependency of BASELINE_DEPENDENCIES) {
    const manifestPath = resolve(root, dependency.path);
    const manifest = manifests.get(manifestPath) ?? readRegularFile(manifestPath, MAX_MANIFEST_BYTES);
    const oldNeedle =
      `package = "${dependency.packageName}", version = "${BASELINE_CODEC_VERSION}"`;
    const frozenNeedle =
      `package = "${dependency.packageName}", version = "=${BASELINE_CODEC_VERSION}"`;
    if (manifest.split(oldNeedle).length !== 2 || manifest.includes(frozenNeedle)) {
      fail("INVALID_DEPENDENCY");
    }
    manifests.set(manifestPath, manifest.replace(oldNeedle, frozenNeedle));
  }
  try {
    for (const [path, contents] of manifests) {
      writeFileSync(path, contents, { encoding: "utf8", flag: "w" });
    }
  } catch {
    fail("WRITE_FAILED");
  }
};

const validateCheckout = (root) => {
  const result = spawnSync("git", ["-C", root, "rev-parse", "HEAD"], {
    encoding: "utf8",
    stdio: "pipe",
  });
  if (
    result.error !== undefined ||
    result.status !== 0 ||
    result.stdout.trim() !== RUST_SEMVER_BASELINE_COMMIT
  ) {
    fail("INVALID_CHECKOUT");
  }
};

const isMain =
  process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    if (process.argv.length !== 3) {
      fail("INVALID_ARGUMENT");
    }
    const baselineRoot = realpathSync(resolve(process.argv[2]));
    validateCheckout(baselineRoot);
    prepareSemverBaseline(baselineRoot);
    console.log(`prepared Rust semver baseline at ${RUST_SEMVER_BASELINE_COMMIT}`);
  } catch (error) {
    if (error instanceof SemverBaselineError) {
      console.error(`semver baseline preparation failed [${error.code}]: ${error.message}`);
    } else {
      console.error("semver baseline preparation failed [INVALID_ARGUMENT]: invalid baseline input");
    }
    process.exitCode = 1;
  }
}
