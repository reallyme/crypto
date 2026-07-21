#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { lstatSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const RUST_SEMVER_BASELINE_COMMIT = "5b8928f10777d0ce44561bb966b9425a281a05d7";

const BASELINE_CODEC_VERSION = "0.1.21";
const MAX_MANIFEST_BYTES = 65_536;
const MAX_LOCKFILE_BYTES = 524_288;

const BASELINE_DEPENDENCIES = Object.freeze([
  Object.freeze({
    path: "crates/crypto/dispatch/Cargo.toml",
    packageName: "reallyme-codec-multikey",
  }),
  Object.freeze({
    path: "crates/crypto/primitives/p256/Cargo.toml",
    packageName: "reallyme-codec-pem",
  }),
  Object.freeze({
    path: "crates/envelopes/jwk/Cargo.toml",
    packageName: "reallyme-codec-base64url",
  }),
  Object.freeze({
    path: "crates/envelopes/jwk/Cargo.toml",
    packageName: "reallyme-codec-jcs",
  }),
  Object.freeze({
    path: "crates/envelopes/jwk-multikey/Cargo.toml",
    packageName: "reallyme-codec-multikey",
  }),
  Object.freeze({
    path: "crates/envelopes/jwk-multikey/Cargo.toml",
    packageName: "reallyme-codec-base64url",
  }),
]);

const BASELINE_CHECKSUMS = Object.freeze({
  "reallyme-codec-base64url": "8168250ef5dc92702ba9b0e807e80997868097c4a9f80ada75c107e1d529ce8f",
  "reallyme-codec-jcs": "ba51c2b3e0d25e34165909e7151f78aaa745480ecc7e44ae8bfbd540b78a1f0f",
  "reallyme-codec-multibase": "b82a83c4711d72ca041ff612ca03651e7b34fa006fa2fc9e597a73dfbf3c0cf4",
  "reallyme-codec-multicodec": "549fdfaa051c62e9a1ec25bd00cf6f062d1a4d36e8c0cc24feb686da34c85b77",
  "reallyme-codec-multikey": "ac918ebc04f36646b302be6c3ee923329e972d159a1ecfeba785289cd78f3c12",
  "reallyme-codec-pem": "81d1d2566a6b6edc797f4c0782ef7baa29daab6c989063f8bbc1df360ece00c6",
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
