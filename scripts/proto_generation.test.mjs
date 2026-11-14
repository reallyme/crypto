// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { checkGeneratedOwners } from "./native_buffa_readiness.mjs";

test("a secret owned view cannot escape through the native trait", () => {
  const root = "../crates/proto/tests/fixtures/guarded/generated/";
  const eager = readFileSync(new URL(root + "guarded_fixture.__view.rs", import.meta.url), "utf8");
  const lazy = readFileSync(new URL(root + "guarded_fixture.__lazy_view.rs", import.meta.url), "utf8");
  // The selector names Child. Its containing message must lose the raw handle too.
  for (const name of ["Child", "Fixture"]) {
    assert.match(eager, new RegExp(`pub struct ${name}View`, "u"));
    assert.match(lazy, new RegExp(`pub struct ${name}LazyView`, "u"));
    assert.doesNotMatch(eager, new RegExp(`\\b${name}OwnedView\\b`, "u"));
    assert.doesNotMatch(eager, new RegExp(`HasMessageView\\s+for\\s+super::super::${name}\\b`, "u"));
  }
});

test("native guards cover optional and nonoptional byte slots", () => {
  const schema = readFileSync(new URL("../crates/proto/proto/reallyme/crypto/v1/crypto.proto", import.meta.url), "utf8");
  const generated = readFileSync(new URL("../crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.rs", import.meta.url), "utf8");
  assert.equal(checkGeneratedOwners(schema, generated), null);
  assert.equal(checkGeneratedOwners(schema, generated.replace("pub secret_key: crate::PrivateBytes,", "pub secret_key: Vec<u8>,")), "CryptoKeyPair.secret_key");
});

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
