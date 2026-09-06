// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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
      const repeated = spawnSync(process.execPath, [script, "--check-idempotent"], { encoding: "utf8" });
      assert.equal(repeated.status, 0, repeated.stderr);

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
