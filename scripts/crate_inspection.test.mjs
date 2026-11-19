// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

const names = ["reallyme-crypto-proto", "reallyme-crypto-core", "reallyme-crypto-hpke", "reallyme-crypto"];
const packages = names.map((name, index) => ({
  name,
  version: "1.0.0",
  publish: null,
  dependencies: index === 0 ? [] : [{ name: names[0], source: null, path: "/workspace/proto", req: "=1.0.0", kind: null }],
}));

function inspect(failingOperation = null) {
  // Exercise the actual CLI without a registry or publish credentials. Cargo
  // must receive the complete set even when dependencies are unpublished.
  const preload = `
    import childProcess from "node:child_process";
    import { syncBuiltinESMExports } from "node:module";
    const calls = [];
    process.on("exit", () => process.stdout.write("\\nCALLS=" + JSON.stringify(calls)));
    childProcess.spawnSync = (command, args) => {
      if (command === "python3") return { status: 0 };
      if (command !== "cargo") throw new TypeError("Unexpected command");
      if (args[0] === "metadata") return { status: 0, stdout: ${JSON.stringify(JSON.stringify({ packages, target_directory: "/workspace/target" }))} };
      calls.push(args);
      return { status: args[0] === ${JSON.stringify(failingOperation)} ? 17 : 0 };
    };
    syncBuiltinESMExports();
  `;
  const result = spawnSync(process.execPath, ["--import", `data:text/javascript,${encodeURIComponent(preload)}`,
    "scripts/publish_crates_in_order.mjs", "inspect", "--allow-dirty"], { encoding: "utf8" });
  assert.equal(result.error, undefined);
  const calls = JSON.parse(result.stdout.split("\nCALLS=")[1]);
  return { status: result.status, calls, stderr: result.stderr };
}

test("crate inspection resolves the complete release set together", () => {
  const result = inspect();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.calls.length, 2);
  for (const args of result.calls) {
    assert.ok(args.includes("--locked"));
    assert.ok(args.includes("--allow-dirty"));
    assert.deepEqual(args.filter((_, index) => args[index - 1] === "-p"), names);
  }
  assert.deepEqual(result.calls[0].slice(0, 2), ["package", "--list"]);
  assert.deepEqual(result.calls[1].slice(0, 2), ["publish", "--dry-run"]);
});

test("crate inspection fails closed on either packaging or dry-run errors", () => {
  for (const operation of ["package", "publish"]) {
    const result = inspect(operation);
    assert.equal(result.status, 17, result.stderr);
    assert.equal(result.calls.length, operation === "package" ? 1 : 2);
  }
});
