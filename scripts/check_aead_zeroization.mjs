#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const MAX_TREE_BYTES = 8 * 1024 * 1024;

export function dependencyStatesHaveZeroize(tree, requiredPackages) {
  if (typeof tree !== "string" || tree.trim().length === 0) return false;
  const found = new Set();
  for (const line of tree.trimEnd().split(/\r?\n/u)) {
    const fields = line.split("|");
    if (fields.length !== 2) return false;
    const match = /^(\S+) v\S+(?:\s.*)?$/u.exec(fields[0]);
    if (match === null) return false;
    if (!requiredPackages.includes(match[1])) continue;
    // Every resolved version must wipe its own state. Another version's
    // zeroize feature, or a zeroize dependency alone, cannot protect it.
    if (!fields[1].split(",").includes("zeroize")) return false;
    found.add(match[1]);
  }
  return requiredPackages.every((name) => found.has(name));
}

function checkAeadZeroization() {
  const profiles = [
    ["reallyme-crypto-aes256-gcm-siv", "native", "wasm", ["aes-gcm-siv", "polyval"]],
    ["reallyme-crypto-chacha20-poly1305", "native", "wasm", ["chacha20poly1305", "poly1305"]],
    // Keep HPKE isolated from the primitive crates so workspace feature
    // unification cannot conceal a missing standalone dependency feature.
    ["reallyme-crypto-hpke", "kem-x25519,kdf-hkdf-sha256,aead-chacha20-poly1305", "kem-x25519,kdf-hkdf-sha256,aead-chacha20-poly1305", ["chacha20poly1305", "poly1305"]],
  ];
  for (const [packageName, nativeFeatures, wasmFeatures, dependencies] of profiles) {
    for (const target of [[], ["--target", "wasm32-unknown-unknown"]]) {
      const result = spawnSync("cargo", [
        "tree", "--locked", "--color", "never", "--package", packageName,
        "--no-default-features", "--features", target.length === 0 ? nativeFeatures : wasmFeatures,
        "--edges", "normal", "--prefix", "none", "--no-dedupe",
        "--format", "{p}|{f}", ...target,
      ], { cwd: root, encoding: "utf8", maxBuffer: MAX_TREE_BYTES, timeout: 60_000 });
      if (result.error !== undefined || result.status !== 0 || !dependencyStatesHaveZeroize(result.stdout, dependencies)) {
        process.stderr.write("AEAD zeroization check failed: every one-time keyed state must enable zeroize\n");
        return 1;
      }
    }
  }
  process.stdout.write("AEAD zeroization check passed: isolated primitive and HPKE native/WASM graphs\n");
  return 0;
}

if (process.argv[1] !== undefined && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = checkAeadZeroization();
}
