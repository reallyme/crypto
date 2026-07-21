#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("./verify_native_artifact_handoff.mjs", import.meta.url));
const nativeResourceRoot = "me/really/crypto/native";
const platforms = Object.freeze([
  Object.freeze({
    id: "linux-x86_64",
    path: `${nativeResourceRoot}/linux-x86_64/libcrypto_ffi.so`,
    env: "NATIVE_SHA256_LINUX_X86_64",
  }),
  Object.freeze({
    id: "linux-aarch64",
    path: `${nativeResourceRoot}/linux-aarch64/libcrypto_ffi.so`,
    env: "NATIVE_SHA256_LINUX_AARCH64",
  }),
  Object.freeze({
    id: "macos-x86_64",
    path: `${nativeResourceRoot}/macos-x86_64/libcrypto_ffi.dylib`,
    env: "NATIVE_SHA256_MACOS_X86_64",
  }),
  Object.freeze({
    id: "macos-aarch64",
    path: `${nativeResourceRoot}/macos-aarch64/libcrypto_ffi.dylib`,
    env: "NATIVE_SHA256_MACOS_AARCH64",
  }),
  Object.freeze({
    id: "windows-x86_64",
    path: `${nativeResourceRoot}/windows-x86_64/crypto_ffi.dll`,
    env: "NATIVE_SHA256_WINDOWS_X86_64",
  }),
]);

const createNativeTree = (root) => {
  const environment = Object.create(null);
  for (const platform of platforms) {
    const path = join(root, platform.path);
    const bytes = Buffer.from(`native fixture for ${platform.id}`, "utf8");
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, bytes);
    environment[platform.env] = createHash("sha256").update(bytes).digest("hex");
  }
  return environment;
};

const runVerifier = (arguments_, environment = Object.create(null)) =>
  spawnSync(process.execPath, [script, ...arguments_], {
    encoding: "utf8",
    env: { ...process.env, ...environment },
  });

test("records a platform-specific producer digest as a job output", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-native-record-"));
  const outputRoot = mkdtempSync(join(tmpdir(), "reallyme-native-output-"));
  try {
    const platform = platforms[0];
    const path = join(root, platform.path);
    const output = join(outputRoot, "github-output");
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, "native producer fixture", "utf8");
    writeFileSync(output, "", "utf8");

    const result = runVerifier(["record", root, platform.id], { GITHUB_OUTPUT: output });
    assert.equal(result.status, 0, result.stderr);
    assert.match(readFileSync(output, "utf8"), /^linux_x86_64_sha256=[0-9a-f]{64}\n$/u);
  } finally {
    rmSync(root, { force: true, recursive: true });
    rmSync(outputRoot, { force: true, recursive: true });
  }
});

test("accepts a complete download bound to all producer job outputs", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-native-verify-"));
  try {
    const environment = createNativeTree(root);
    const result = runVerifier(["verify", root], environment);
    assert.equal(result.status, 0, result.stderr);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("rejects a substituted native library even when the other libraries match", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-native-tamper-"));
  try {
    const environment = createNativeTree(root);
    writeFileSync(join(root, platforms[3].path), "substituted native bytes", "utf8");
    const result = runVerifier(["verify", root], environment);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /does not match its producer job output/u);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("rejects a missing producer job output", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-native-missing-output-"));
  try {
    const environment = createNativeTree(root);
    delete environment.NATIVE_SHA256_WINDOWS_X86_64;
    const result = runVerifier(["verify", root], environment);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /job output digest for windows-x86_64 is missing or malformed/u);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("rejects unbound extra native libraries", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-native-extra-"));
  try {
    const environment = createNativeTree(root);
    writeFileSync(
      join(root, nativeResourceRoot, "linux-x86_64/unreviewed.so"),
      "unexpected native bytes",
      "utf8",
    );
    const result = runVerifier(["verify", root], environment);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /exact expected file set/u);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("rejects a non-native class file anywhere in the artifact tree", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-native-extra-class-"));
  try {
    const environment = createNativeTree(root);
    const injectedClass = join(root, "me/really/crypto/Evil.class");
    mkdirSync(dirname(injectedClass), { recursive: true });
    writeFileSync(injectedClass, "unbound JVM bytecode fixture", "utf8");
    const result = runVerifier(["verify", root], environment);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /exact expected file set/u);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("rejects symbolic links in a downloaded native resource tree", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-native-symlink-"));
  try {
    const environment = createNativeTree(root);
    symlinkSync(join(root, platforms[0].path), join(root, "linked-library.so"));
    const result = runVerifier(["verify", root], environment);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /symbolic link/u);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("rejects recursively nested artifact content beyond the fixed resource layout", () => {
  const root = mkdtempSync(join(tmpdir(), "reallyme-native-depth-"));
  try {
    const environment = createNativeTree(root);
    const nested = join(root, "one", "two", "three", "four", "five", "six");
    mkdirSync(nested, { recursive: true });
    writeFileSync(join(nested, "nested.so"), "nested native bytes", "utf8");
    const result = runVerifier(["verify", root], environment);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /exceeds the supported depth/u);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});
