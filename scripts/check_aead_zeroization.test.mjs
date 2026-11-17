// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { test } from "node:test";
import { dependencyStatesHaveZeroize } from "./check_aead_zeroization.mjs";

const correct = "aes-gcm-siv v0.12.1|aes,alloc,zeroize\npolyval v0.7.3|zeroize\nzeroize v1.9.1|alloc\n";
const required = ["aes-gcm-siv", "polyval"];

test("AEAD state checks inspect resolved crate features", () => {
  assert.equal(dependencyStatesHaveZeroize(correct, required), true);
});

for (const [name, tree] of [
  ["an AEAD without zeroize", correct.replace("aes,alloc,zeroize", "aes,alloc")],
  ["a MAC without zeroize", correct.replace("polyval v0.7.3|zeroize", "polyval v0.7.3|")],
  ["a different version carrying zeroize", correct.replace("polyval v0.7.3|zeroize", "polyval v0.7.3|\npolyval v0.6.2|zeroize")],
  ["a missing MAC", "aes-gcm-siv v0.12.1|zeroize\n"],
  ["a zeroize dependency without keyed-state features", "zeroize v1.9.1|alloc\n"],
  ["empty output", ""],
  ["malformed output", "polyval v0.7.3|zeroize|unexpected\n"],
]) {
  test(`AEAD state checks reject ${name}`, () => {
    assert.equal(dependencyStatesHaveZeroize(tree, required), false);
  });
}

test("AEAD guard checks native and WASM features without workspace feature masking", (t) => {
  const root = mkdtempSync(join(tmpdir(), "aead-zeroization-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, "scripts"));
  mkdirSync(join(root, "bin"));
  const script = join(root, "scripts", "check_aead_zeroization.mjs");
  copyFileSync(new URL("./check_aead_zeroization.mjs", import.meta.url), script);
  const log = join(root, "calls.jsonl");
  const cargo = join(root, "bin", "cargo");
  writeFileSync(cargo, `#!/usr/bin/env node
const { appendFileSync } = require("node:fs");
appendFileSync(process.env.AEAD_TREE_CALLS, JSON.stringify(process.argv.slice(2)) + "\\n");
process.stdout.write("aes-gcm-siv v0.12.1|zeroize\\npolyval v0.7.3|zeroize\\nchacha20poly1305 v0.11.0|zeroize\\npoly1305 v0.9.1|zeroize\\n");
`);
  chmodSync(cargo, 0o755);
  const result = spawnSync(process.execPath, [script], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, PATH: `${join(root, "bin")}${delimiter}${process.env.PATH}`, AEAD_TREE_CALLS: log },
  });
  assert.equal(result.status, 0, result.stderr);
  const calls = readFileSync(log, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  assert.equal(calls.length, 6);
  for (const [index, args] of calls.entries()) {
    assert.ok(args.includes("--locked"));
    assert.ok(args.includes("--no-default-features"));
    assert.equal(args.includes("--workspace"), false);
    const features = args[args.indexOf("--features") + 1];
    if (index < 4) assert.equal(features, index % 2 === 0 ? "native" : "wasm");
    else assert.equal(features, "kem-x25519,kdf-hkdf-sha256,aead-chacha20-poly1305");
    assert.equal(args.includes("--target"), index % 2 === 1);
  }
});
