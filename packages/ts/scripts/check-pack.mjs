#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageJsonPath = resolve(packageDirectory, "package.json");
const readUtf8 = (path) => readFileSync(path, "utf8");
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

function assertContains(label, text, needle) {
  if (!text.includes(needle)) {
    fail(`${label} is missing required release-surface evidence: ${needle}`);
  }
}

function assertNotContains(label, text, needle) {
  if (text.includes(needle)) {
    fail(`${label} retains removed release-surface evidence: ${needle}`);
  }
}

const packageJson = JSON.parse(readUtf8(packageJsonPath));
const packageExports = packageJson.exports;
if (
  typeof packageExports !== "object" ||
  packageExports === null ||
  packageExports["./wasm/reallyme_crypto_wasm.js"]?.default !==
    "./dist/wasm/reallyme_crypto_wasm.js" ||
  packageExports["./wasm/reallyme_crypto_wasm.js"]?.types !==
    "./dist/wasmModuleTypes.d.ts" ||
  packageExports["./wasm/reallyme_crypto_wasm_bg.wasm"]?.default !==
    "./dist/wasm/reallyme_crypto_wasm_bg.wasm"
) {
  fail("package.json exports do not match the documented raw WASM provider artifact contract.");
}

const readme = readUtf8(resolve(packageDirectory, "README.md"));
assertContains("README.md", readme, "## Raw WASM Module Contract");
assertContains("README.md", readme, "Direct raw WASM calls are unsupported for application logic.");
assertContains("README.md", readme, "no ambient global crypto-provider functions");

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

const wasmTypeDeclarations = readUtf8(
  resolve(packageDirectory, "dist", "wasmModuleTypes.d.ts"),
);
for (const declaration of [
  "export declare function processOperationResponse",
  "export declare function argon2idDeriveKey",
  "export declare function kmac256Derive",
  "export declare function hpkeOpenBase",
  "export declare function rsaVerifyPss",
  "export declare function mlKem512DeriveKeypair",
  "export declare function xWing768DeriveKeypair",
]) {
  assertContains("dist/wasmModuleTypes.d.ts", wasmTypeDeclarations, declaration);
}
assertNotContains(
  "dist/wasmModuleTypes.d.ts",
  wasmTypeDeclarations,
  "export declare function processProto",
);
assertNotContains("dist/wasmModuleTypes.d.ts", wasmTypeDeclarations, "Derand");

const generatedWasmGlue = readUtf8(
  resolve(packageDirectory, "dist", "wasm", "reallyme_crypto_wasm.js"),
);
const wasmBinary = readFileSync(
  resolve(packageDirectory, "dist", "wasm", "reallyme_crypto_wasm_bg.wasm"),
);
let wasmModule;
try {
  wasmModule = new WebAssembly.Module(wasmBinary);
} catch {
  fail("dist/wasm/reallyme_crypto_wasm_bg.wasm is not a valid WebAssembly module.");
}

const allowedWasmImportNames = [
  /^__wbg_new_[0-9a-f]+$/,
  /^__wbg_length_[0-9a-f]+$/,
  /^__wbg_prototypesetcall_[0-9a-f]+$/,
  /^__wbg_new_from_slice_[0-9a-f]+$/,
  /^__wbg_set_[0-9a-f]+$/,
  /^__wbg_getRandomValues_[0-9a-f]+$/,
  /^__wbg___wbindgen_throw_[0-9a-f]+$/,
  /^__wbindgen_init_externref_table$/,
  /^__wbindgen_cast_[0-9a-f]+$/,
];
for (const wasmImport of WebAssembly.Module.imports(wasmModule)) {
  const allowed =
    wasmImport.module === "./reallyme_crypto_wasm_bg.js" &&
    wasmImport.kind === "function" &&
    allowedWasmImportNames.some((pattern) => pattern.test(wasmImport.name));
  if (!allowed) {
    // Keep this as a hard failure: a semantic import here could otherwise make
    // generated WASM glue reference an ambient crypto-provider global.
    fail(
      `generated WASM glue references ambient crypto-provider global or unreviewed import ${wasmImport.module}:${wasmImport.name}`,
    );
  }
}

const declaredWasmFunctions = new Set(
  [...wasmTypeDeclarations.matchAll(/export declare function ([A-Za-z0-9_]+)\(/g)]
    .map((match) => match[1])
    .filter((name) => name !== "initSync"),
);
const binaryWasmFunctions = new Set(
  WebAssembly.Module.exports(wasmModule)
    .filter((item) => item.kind === "function" && !item.name.startsWith("__"))
    .map((item) => item.name),
);
const deterministicEncryptionExports = [...binaryWasmFunctions].filter((name) =>
  /derand/i.test(name),
);
if (deterministicEncryptionExports.length !== 0) {
  fail(
    `published WASM exposes conformance-only deterministic encryption functions: ${deterministicEncryptionExports.sort().join(", ")}`,
  );
}
assertNotContains(
  "dist/wasm/reallyme_crypto_wasm.js",
  generatedWasmGlue,
  "Derand",
);
const missingDeclarations = [...binaryWasmFunctions].filter(
  (name) => !declaredWasmFunctions.has(name),
);
const staleDeclarations = [...declaredWasmFunctions].filter(
  (name) => !binaryWasmFunctions.has(name),
);
if (missingDeclarations.length !== 0 || staleDeclarations.length !== 0) {
  fail(
    `raw WASM declarations do not match the binary export surface:\n` +
      `missing declarations: ${missingDeclarations.sort().join(", ") || "none"}\n` +
      `stale declarations: ${staleDeclarations.sort().join(", ") || "none"}`,
  );
}
for (const generatedExport of binaryWasmFunctions) {
  assertContains(
    "dist/wasm/reallyme_crypto_wasm.js",
    generatedWasmGlue,
    `export function ${generatedExport}`,
  );
}

process.stdout.write(
  `npm pack dry run includes ${files.length} files, including reallyme_crypto_wasm_bg.wasm.\n`,
);
