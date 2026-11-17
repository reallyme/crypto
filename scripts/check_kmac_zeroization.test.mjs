// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { kmacBackendHasZeroize } from "./check_kmac_zeroization.mjs";

const correct = `0reallyme-crypto-kmac v0.4.3 (/source tree)|
1sha3-kmac v0.3.0|
2sha3 v0.10.9|zeroize
3zeroize v1.9.1|alloc
1sha3 feature "zeroize"
2sha3 v0.10.9|zeroize
`;

test("KMAC graph check follows the backend through feature nodes", () => {
  assert.equal(kmacBackendHasZeroize(correct), true);
  assert.equal(kmacBackendHasZeroize(correct.replace(
    "2sha3 v0.10.9|zeroize", '2sha3 feature "default"\n3sha3 v0.10.9|default,zeroize',
  )), true);
  // The rule follows future backend versions rather than blessing the old alias.
  assert.equal(kmacBackendHasZeroize(correct.replaceAll("v0.10.9", "v0.12.0")), true);
});

for (const [name, tree] of [
  ["zeroize enabled only on a different major version", correct.replace(
    "2sha3 v0.10.9|zeroize", "2sha3 v0.10.9|default",
  ).replace('1sha3 feature "zeroize"\n2sha3 v0.10.9|zeroize', '1sha3 feature "zeroize"\n2sha3 v0.12.0|zeroize')],
  ["a feature label without the backend feature", correct.replace(
    "2sha3 v0.10.9|zeroize", '2sha3 feature "zeroize"\n3sha3 v0.10.9|',
  )],
  ["one unprotected backend among several", `${correct}1sha3-kmac v0.4.0|\n2sha3 v0.12.0|default\n`],
  ["a missing backend", "0sha3 v0.10.9|zeroize\n"],
  ["a backend without its sponge", "0sha3-kmac v0.3.0|\n1zeroize v1.9.1|alloc\n"],
  ["an empty tree", ""],
  ["invalid depth", "0sha3-kmac v0.3.0|\n3sha3 v0.10.9|zeroize\n"],
]) {
  test(`KMAC graph check rejects ${name}`, () => {
    assert.equal(kmacBackendHasZeroize(tree), false);
  });
}

function runFixture(t, tree, exitCode = 0) {
  const root = mkdtempSync(join(tmpdir(), "kmac feature graph # "));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  mkdirSync(join(root, "scripts"));
  mkdirSync(join(root, "bin"));
  copyFileSync(fileURLToPath(new URL("./check_kmac_zeroization.mjs", import.meta.url)), join(root, "scripts/check_kmac_zeroization.mjs"));
  const trace = join(root, "calls.jsonl");
  writeFileSync(join(root, "bin/cargo"), `#!/usr/bin/env node
const { appendFileSync } = require("node:fs");
appendFileSync(${JSON.stringify(trace)}, JSON.stringify(process.argv.slice(2)) + "\\n");
process.stdout.write(${JSON.stringify(tree)});
process.exitCode = ${exitCode};
`, { mode: 0o700 });
  const result = spawnSync(process.execPath, [join(root, "scripts/check_kmac_zeroization.mjs")], {
    encoding: "utf8", timeout: 30_000,
    env: { ...process.env, PATH: `${join(root, "bin")}:${process.env.PATH ?? ""}` },
  });
  assert.equal(result.error, undefined);
  assert.ok(existsSync(trace), result.stderr || "cargo was not invoked");
  const calls = readFileSync(trace, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  return { result, calls };
}

test("KMAC CI command checks minimal, native, and wasm graphs without dev or build feature masking", (t) => {
  const { result, calls } = runFixture(t, correct);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(calls.length, 3);
  for (const args of calls) {
    assert.equal(args[0], "tree");
    for (const argument of ["--locked", "--no-default-features", "features,no-dev,no-build", "--no-dedupe", "{p}|{f}"]) {
      assert.ok(args.includes(argument), argument);
    }
  }
  assert.ok(calls[1].includes("native"));
  assert.ok(calls[2].includes("wasm"));
  assert.ok(calls[2].includes("wasm32-unknown-unknown"));
});

test("KMAC CI command fails on an unprotected backend", (t) => {
  const { result, calls } = runFixture(t, correct.replace("2sha3 v0.10.9|zeroize", "2sha3 v0.10.9|"));
  assert.equal(result.status, 1);
  assert.equal(calls.length, 1);
});

test("KMAC CI command fails when cargo cannot produce a tree", (t) => {
  const { result } = runFixture(t, correct, 1);
  assert.equal(result.status, 1);
});
