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
  "reallyme-codec-base64url": "25318a052c3216e06840561e830540d72d5c5891202bc28f46ac7a1a4b80608d",
  "reallyme-codec-jcs": "2be4e9db86812ceef2b5666a20e9089a3532e172fd0a14270a3d7b34b072cdfc",
  "reallyme-codec-multibase": "a72c1edcbcd9acfa3776d829507cc2c9793c252c64ef2b6c1746d8affbab819a",
  "reallyme-codec-multicodec": "7b4576f9bbe6011c9efd215e595e882ab5dd2518ceabb51f8ae9530119d4e5b8",
  "reallyme-codec-multikey": "4be655fa8af73a8ed0ad551aa153a8a950c6ffc542bac9f2666315d65afd89f8",
  "reallyme-codec-pem": "584d367a74c2cec746d697d3c43ac33099b06bb4ee141c81a37b332cd2af9c58",
};

const fixture = () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-semver-baseline-"));
  const byPath = new Map();
  for (const [path, packageName] of dependencies) {
    const entries = byPath.get(path) ?? [];
    entries.push(`dependency = { package = "${packageName}", version = "0.3.0" }`);
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
        `[[package]]\nname = "${packageName}"\nversion = "0.3.0"\n` +
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
      new RegExp(`package = "${packageName}", version = "=0\\.3\\.0"`, "u"),
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
    readFileSync(manifestPath, "utf8").replace('version = "0.3.0"', 'version = "0.3.1"'),
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
