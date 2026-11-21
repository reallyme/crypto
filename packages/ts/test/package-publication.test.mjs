// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { PackageError, stagePackage } from "../scripts/pack.mjs";

function fixture(run) {
  const root = mkdtempSync(join(tmpdir(), "crypto-package-test-"));
  try {
    const source = join(root, "source");
    mkdirSync(join(source, "dist", "wasm"), { recursive: true });
    const manifest = { name: "@reallyme/crypto", version: "1.0.0", main: "./dist/index.js", types: "./dist/index.d.ts",
      exports: { ".": { types: "./dist/index.d.ts", default: "./dist/index.js" },
        "./wasm/reallyme_crypto_wasm.js": { default: "./dist/wasm/reallyme_crypto_wasm.js" } },
      dependencies: { "@reallyme/codec": "0.4.5" }, scripts: { prepack: "must never execute" } };
    writeFileSync(join(source, "package.json"), JSON.stringify(manifest));
    for (const name of ["LICENSE", "README.md"]) writeFileSync(join(source, name), name);
    writeFileSync(join(source, "dist", "index.js"), "export const value = 1;\n");
    writeFileSync(join(source, "dist", "index.d.ts"), "export declare const value = 1;\n");
    writeFileSync(join(source, "dist", "wasm", "reallyme_crypto_wasm.js"), "export default {};\n");
    run({ source, destination: join(root, "package"), manifest });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("publication retains public imports, dependency pins and compiled bytes outside ignored paths", () => {
  fixture(({ source, destination, manifest }) => {
    stagePackage(source, destination);
    const staged = JSON.parse(readFileSync(join(destination, "package.json"), "utf8"));
    assert.deepEqual(Object.keys(staged.exports), Object.keys(manifest.exports));
    assert.equal(staged.main, "./src/index.js");
    assert.equal(staged.types, "./src/index.d.ts");
    assert.equal(staged.exports["./wasm/reallyme_crypto_wasm.js"].default, "./src/wasm/reallyme_crypto_wasm.js");
    assert.deepEqual(staged.dependencies, manifest.dependencies);
    assert.equal(staged.scripts, undefined);
    assert.deepEqual(readFileSync(join(source, "dist", "index.js")), readFileSync(join(destination, "src", "index.js")));
    assert.deepEqual(JSON.parse(readFileSync(join(source, "package.json"), "utf8")), manifest);
  });
});

test("publication rejects linked build inputs and malformed export targets", () => {
  fixture(({ source, destination }) => {
    symlinkSync(join(source, "LICENSE"), join(source, "dist", "linked"));
    assert.throws(() => stagePackage(source, destination),
      (error) => error instanceof PackageError && error.code === "NON_REGULAR_BUILD_INPUT");
  });
  fixture(({ source, destination, manifest }) => {
    manifest.exports["."] = { default: 42 };
    writeFileSync(join(source, "package.json"), JSON.stringify(manifest));
    assert.throws(() => stagePackage(source, destination),
      (error) => error instanceof PackageError && error.code === "INVALID_EXPORT_TARGET");
  });
});

test("npm refuses direct source-tree packaging before producing an archive", () => {
  fixture(({ source, manifest }) => {
    const actualManifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    manifest.scripts.prepack = actualManifest.scripts.prepack;
    mkdirSync(join(source, "scripts"));
    writeFileSync(join(source, "scripts", "pack.mjs"), readFileSync(new URL("../scripts/pack.mjs", import.meta.url)));
    writeFileSync(join(source, "package.json"), JSON.stringify(manifest));
    const result = spawnSync("npm", ["pack", "--dry-run", "--cache", join(source, "cache")], {
      cwd: source, encoding: "utf8",
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stdout + result.stderr, /PUBLICATION_REQUIRES_STAGED_PACKAGE/u);
  });
});
