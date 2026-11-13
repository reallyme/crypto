// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const ownedPath = "crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.rs";
const strictBranch = `                        _ => {
                            return Err(serde::de::Error::custom("unknown field"));
                        }`;

for (const namespace of ["serde", "::serde"]) {
  test(`protobuf hardening rejects unknown oneof fields from ${namespace} generator output`, () => {
    const root = mkdtempSync(join(tmpdir(), "crypto-proto-hardening-"));
    try {
      for (const path of ["gen", "crates/proto/src/generated", "crates/proto/proto", "scripts/redact_crypto_proto_debug.mjs"]) {
        mkdirSync(dirname(join(root, path)), { recursive: true });
        cpSync(new URL(`../${path}`, import.meta.url), join(root, path), { recursive: true });
      }
      const original = readFileSync(join(root, ownedPath), "utf8");
      assert.equal(original.split(strictBranch).length - 1, 6);
      // Undo just the oneof rejection to model both supported raw-generator
      // spellings. All existing secret-field hardening must survive the pass.
      const rawBranch = strictBranch.replace(
        'return Err(serde::de::Error::custom("unknown field"));',
        `map.next_value::<${namespace}::de::IgnoredAny>()?;`,
      );
      writeFileSync(join(root, ownedPath), original.replaceAll(strictBranch, rawBranch));
      const script = join(root, "scripts/redact_crypto_proto_debug.mjs");
      const result = spawnSync(process.execPath, [script], { encoding: "utf8" });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(readFileSync(join(root, ownedPath), "utf8"), original);
      const stablePaths = [ownedPath,
        "crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.__view.rs",
        "gen/swift/reallyme/crypto/v1/crypto.pb.swift"];
      const past = new Date("2000-01-01T00:00:00Z");
      for (const path of stablePaths) utimesSync(join(root, path), past, past);
      const timestamps = stablePaths.map((path) => statSync(join(root, path)).mtimeMs);
      const repeated = spawnSync(process.execPath, [script, "--check-idempotent"], { encoding: "utf8" });
      assert.equal(repeated.status, 0, repeated.stderr);
      assert.deepEqual(stablePaths.map((path) => statSync(join(root, path)).mtimeMs), timestamps,
        "idempotent verification must preserve incremental-build timestamps");

      // A partially changed template must fail closed instead of silently
      // leaving an unknown-field acceptance route in the generated decoder.
      writeFileSync(join(root, ownedPath), original.replace(strictBranch, rawBranch));
      const partial = spawnSync(process.execPath, [script], { encoding: "utf8" });
      assert.notEqual(partial.status, 0);
      assert.match(partial.stderr, /expected 6 oneof unknown-field branches, found 1/u);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}

test("CI policy and generation modes do not launch repository tests", () => {
  // Trace the actual checker through the test-routing boundary. Child commands
  // are intercepted; only the tracked-file inventory may execute. Stop before
  // any package metadata, SDK, generation or other toolchain commands run.
  const preload = `
    import childProcess from "node:child_process";
    import { syncBuiltinESMExports } from "node:module";
    const original = childProcess.spawnSync;
    const calls = [];
    childProcess.spawnSync = (command, args, options) => {
      if (command === "git" && args.length === 2 && args[0] === "ls-files" && args[1] === "-z") {
        return original(command, args, options);
      }
      calls.push(args);
      if (args[0] === "scripts/publish_crates_in_order.mjs") {
        process.stdout.write(JSON.stringify(calls));
        process.exit(73);
      }
      return { status: 0, stdout: "", stderr: "" };
    };
    syncBuiltinESMExports();
  `;
  const checker = fileURLToPath(new URL("./check_release_readiness.mjs", import.meta.url));
  const root = fileURLToPath(new URL("../", import.meta.url));
  for (const mode of [undefined, "--release-packages", "--ci-policy", "--generated-freshness",
    "--typescript-source", "--swift-source", "--kotlin-source"]) {
    const result = spawnSync(process.execPath, ["--import",
      `data:text/javascript,${encodeURIComponent(preload)}`, checker, ...(mode === undefined ? [] : [mode])],
    { cwd: root, encoding: "utf8", timeout: 10_000 });
    assert.equal(result.error, undefined, mode);
    assert.equal(result.status, 73, result.stderr);
    const calls = JSON.parse(result.stdout);
    assert.equal(calls.filter((args) => args[0] === "--test").length,
      mode === undefined || mode === "--release-packages" ? 1 : 0, mode);
  }
});
