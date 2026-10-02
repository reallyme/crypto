// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { prepareSemverBaseline, SemverBaselineError } from "./prepare_semver_baseline.mjs";

const dependencies = [
  ["crates/crypto/dispatch/Cargo.toml", "reallyme-codec-multikey"],
  ["crates/p256/Cargo.toml", "reallyme-codec-pem"],
  ["crates/jwk/Cargo.toml", "reallyme-codec-base64url"],
  ["crates/jwk/Cargo.toml", "reallyme-codec-jcs"],
  ["crates/jwk-multikey/Cargo.toml", "reallyme-codec-multikey"],
  ["crates/jwk-multikey/Cargo.toml", "reallyme-codec-base64url"],
];

const checksums = {
  "reallyme-codec-base64url": "f6bf7a30f229edf6e3236df0b2b11c522da128cfbdcc3b0dfca4912b7f6463a0",
  "reallyme-codec-jcs": "4e8f5718cd2bdbcdc6b6b9eb91ac77ea35aaec6051c7222367090ad52b1fc551",
  "reallyme-codec-multibase": "e38491c026515d692ac863bd277eba813a399053bc3740550f0cb3e6206bd003",
  "reallyme-codec-multicodec": "9400a5df3a8bc8e66e87be32a2563dd631f923c29418ce582949ac6ba4fcfa8f",
  "reallyme-codec-multikey": "86018a0dd6bad08ad4f48f5a1d62c8db722f2f4407bd0991824fdd8ca1744e0f",
  "reallyme-codec-pem": "7bcaf67e2614ae686fab132732937779dfaaa93bc527c0f1dea0637791432b81",
};

const fixture = () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-semver-baseline-"));
  const byPath = new Map();
  for (const [path, packageName] of dependencies) {
    const entries = byPath.get(path) ?? [];
    entries.push(`dependency = { package = "${packageName}", version = "0.2.3" }`);
    byPath.set(path, entries);
  }
  for (const [path, lines] of byPath) {
    const absolutePath = join(root, path);
    mkdirSync(dirname(absolutePath), { recursive: true });
    writeFileSync(absolutePath, `${lines.join("\n")}\n`, "utf8");
  }
  const lockfile = Object.entries(checksums)
    .map(
      ([packageName, checksum]) =>
        `[[package]]\nname = "${packageName}"\nversion = "0.2.3"\n` +
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n' +
        `checksum = "${checksum}"\n`,
    )
    .join("\n");
  writeFileSync(join(root, "Cargo.lock"), lockfile, "utf8");
  return root;
};

test("freezes reviewed baseline codec dependencies to the lockfile patch version", () => {
  const root = fixture();
  prepareSemverBaseline(root);
  for (const [path, packageName] of dependencies) {
    const manifest = readFileSync(join(root, path), "utf8");
    assert.match(
      manifest,
      new RegExp(`package = "${packageName}", version = "=0\\.2\\.3"`, "u"),
    );
  }
});

test("rejects a changed registry checksum", () => {
  const root = fixture();
  const lockPath = join(root, "Cargo.lock");
  writeFileSync(lockPath, readFileSync(lockPath, "utf8").replace(/checksum = "[^"]+"/u, 'checksum = "changed"'));
  assert.throws(
    () => prepareSemverBaseline(root),
    (error) => error instanceof SemverBaselineError && error.code === "INVALID_LOCKFILE",
  );
});

test("rejects dependency drift and a repeated preparation", () => {
  const root = fixture();
  const manifestPath = join(root, dependencies[0][0]);
  writeFileSync(
    manifestPath,
    readFileSync(manifestPath, "utf8").replace('version = "0.2.3"', 'version = "0.2.4"'),
  );
  assert.throws(
    () => prepareSemverBaseline(root),
    (error) => error instanceof SemverBaselineError && error.code === "INVALID_DEPENDENCY",
  );

  const cleanRoot = fixture();
  prepareSemverBaseline(cleanRoot);
  assert.throws(
    () => prepareSemverBaseline(cleanRoot),
    (error) => error instanceof SemverBaselineError && error.code === "INVALID_DEPENDENCY",
  );
});
