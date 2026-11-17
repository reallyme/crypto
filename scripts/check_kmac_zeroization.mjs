#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const MAX_TREE_BYTES = 8 * 1024 * 1024;

export function kmacBackendHasZeroize(tree) {
  if (typeof tree !== "string" || tree.trim().length === 0) return false;
  const stack = [];
  const backends = [];
  for (const line of tree.trimEnd().split(/\r?\n/u)) {
    const match = /^(\d+)(.+)$/u.exec(line);
    if (match === null) return false;
    const depth = Number(match[1]);
    if (!Number.isSafeInteger(depth) || depth > stack.length) return false;
    let owner = depth === 0 ? null : stack[depth - 1];
    const fields = match[2].split("|");
    if (fields.length > 2) return false;
    if (fields.length === 2 && /^sha3-kmac v\S+(?:\s.*)?$/u.test(fields[0])) {
      owner = { hasSponge: false };
      backends.push(owner);
    } else if (fields.length === 2 && owner !== null && /^sha3 v\S+(?:\s.*)?$/u.test(fields[0])) {
      // Inspect the features on the actual dependency beneath sha3-kmac.
      // A zeroize feature node or another direct SHA-3 version is insufficient.
      if (!fields[1].split(",").includes("zeroize")) return false;
      owner.hasSponge = true;
    }
    stack.length = depth;
    stack.push(owner);
  }
  return backends.length !== 0 && backends.every((backend) => backend.hasSponge);
}

function checkKmacZeroization() {
  for (const options of [
    ["--no-default-features"],
    ["--no-default-features", "--features", "native"],
    ["--no-default-features", "--features", "wasm", "--target", "wasm32-unknown-unknown"],
  ]) {
    const result = spawnSync("cargo", [
      "tree", "--locked", "--color", "never", "--package", "reallyme-crypto-kmac",
      "--edges", "features,no-dev,no-build", "--prefix", "depth", "--no-dedupe",
      "--format", "{p}|{f}", ...options,
    ], { cwd: root, encoding: "utf8", maxBuffer: MAX_TREE_BYTES, timeout: 60_000 });
    if (result.error !== undefined || result.status !== 0 || !kmacBackendHasZeroize(result.stdout)) {
      process.stderr.write("KMAC zeroization check failed: every sha3-kmac sponge must enable zeroize\n");
      return 1;
    }
  }
  process.stdout.write("KMAC zeroization check passed: minimal, native, and wasm dependency graphs\n");
  return 0;
}

if (process.argv[1] !== undefined && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = checkKmacZeroization();
}
