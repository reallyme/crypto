#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const requiredFiles = [
  "package/dist/index.js",
  "package/dist/index.d.ts",
  "package/dist/proto.js",
  "package/dist/proto.d.ts",
  "package/dist/wasm/reallyme_crypto_wasm.js",
  "package/dist/wasm/reallyme_crypto_wasm_bg.wasm",
  "package/dist/wasmModuleTypes.d.ts",
  "package/LICENSE",
  "package/README.md",
  "package/package.json",
];

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

// Pack inspection must not depend on the ownership or integrity of a developer's
// global npm cache. A private cache also prevents concurrent repository checks
// from sharing npm's mutable temporary entries.
const npmCacheDirectory = mkdtempSync(
  join(tmpdir(), "reallyme-crypto-npm-pack-"),
);
let result;
try {
  result = spawnSync("npm", ["pack", "--dry-run", "--json"], {
    cwd: packageDirectory,
    encoding: "utf8",
    env: {
      ...process.env,
      npm_config_cache: npmCacheDirectory,
    },
  });
} finally {
  rmSync(npmCacheDirectory, { force: true, recursive: true });
}

if (result.status !== 0) {
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  process.exit(result.status ?? 1);
}

let packEntries;
for (let index = result.stdout.indexOf("["); index !== -1; index = result.stdout.indexOf("[", index + 1)) {
  try {
    packEntries = JSON.parse(result.stdout.slice(index));
    break;
  } catch {
    // npm lifecycle scripts may print before the JSON array; keep scanning.
  }
}

if (packEntries === undefined) {
  fail("npm pack --dry-run --json returned invalid JSON.");
}

if (!Array.isArray(packEntries) || packEntries.length !== 1) {
  fail("npm pack --dry-run --json returned an unexpected package list.");
}

const files = packEntries[0]?.files;
if (!Array.isArray(files)) {
  fail("npm pack --dry-run --json did not report packaged files.");
}

const names = new Set();
for (const file of files) {
  if (typeof file?.path === "string") {
    names.add(`package/${file.path}`);
  }
}

const missing = requiredFiles.filter((file) => !names.has(file));
if (missing.length !== 0) {
  fail(`npm package is missing required release artifacts:\n- ${missing.join("\n- ")}`);
}

process.stdout.write(
  `npm pack dry run includes ${files.length} files, including reallyme_crypto_wasm_bg.wasm.\n`,
);
