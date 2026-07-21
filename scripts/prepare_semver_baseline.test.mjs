// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { prepareSemverBaseline, SemverBaselineError } from "./prepare_semver_baseline.mjs";

const dependencies = [
  ["crates/crypto/dispatch/Cargo.toml", "reallyme-codec-multikey"],
  ["crates/crypto/primitives/p256/Cargo.toml", "reallyme-codec-pem"],
  ["crates/envelopes/jwk/Cargo.toml", "reallyme-codec-base64url"],
  ["crates/envelopes/jwk/Cargo.toml", "reallyme-codec-jcs"],
  ["crates/envelopes/jwk-multikey/Cargo.toml", "reallyme-codec-multikey"],
  ["crates/envelopes/jwk-multikey/Cargo.toml", "reallyme-codec-base64url"],
];

const checksums = {
  "reallyme-codec-base64url": "8168250ef5dc92702ba9b0e807e80997868097c4a9f80ada75c107e1d529ce8f",
  "reallyme-codec-jcs": "ba51c2b3e0d25e34165909e7151f78aaa745480ecc7e44ae8bfbd540b78a1f0f",
  "reallyme-codec-multibase": "b82a83c4711d72ca041ff612ca03651e7b34fa006fa2fc9e597a73dfbf3c0cf4",
  "reallyme-codec-multicodec": "549fdfaa051c62e9a1ec25bd00cf6f062d1a4d36e8c0cc24feb686da34c85b77",
  "reallyme-codec-multikey": "ac918ebc04f36646b302be6c3ee923329e972d159a1ecfeba785289cd78f3c12",
  "reallyme-codec-pem": "81d1d2566a6b6edc797f4c0782ef7baa29daab6c989063f8bbc1df360ece00c6",
};

const fixture = () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-semver-baseline-"));
  const byPath = new Map();
  for (const [path, packageName] of dependencies) {
    const entries = byPath.get(path) ?? [];
    entries.push(`dependency = { package = "${packageName}", version = "0.1.21" }`);
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
        `[[package]]\nname = "${packageName}"\nversion = "0.1.21"\n` +
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
      new RegExp(`package = "${packageName}", version = "=0\\.1\\.21"`, "u"),
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
    readFileSync(manifestPath, "utf8").replace('version = "0.1.21"', 'version = "0.1.22"'),
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
