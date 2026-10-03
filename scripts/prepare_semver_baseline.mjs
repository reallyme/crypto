#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { lstatSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// The tagged 0.3.10 release is the immutable baseline for the 0.3.11 API check.
export const RUST_SEMVER_BASELINE_COMMIT = "80bc7b710cc5de7b5c847a17ed5d10de3231158f";

const BASELINE_CODEC_VERSION = "0.3.0";
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
  "reallyme-codec-base64url": "25318a052c3216e06840561e830540d72d5c5891202bc28f46ac7a1a4b80608d",
  "reallyme-codec-jcs": "2be4e9db86812ceef2b5666a20e9089a3532e172fd0a14270a3d7b34b072cdfc",
  "reallyme-codec-multibase": "a72c1edcbcd9acfa3776d829507cc2c9793c252c64ef2b6c1746d8affbab819a",
  "reallyme-codec-multicodec": "7b4576f9bbe6011c9efd215e595e882ab5dd2518ceabb51f8ae9530119d4e5b8",
  "reallyme-codec-multikey": "4be655fa8af73a8ed0ad551aa153a8a950c6ffc542bac9f2666315d65afd89f8",
  "reallyme-codec-pem": "584d367a74c2cec746d697d3c43ac33099b06bb4ee141c81a37b332cd2af9c58",
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
