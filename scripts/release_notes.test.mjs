// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { extractReleaseNotes, ReleaseNotesError } from "./release_notes.mjs";

test("selects only the requested release section", () => {
  const notes = extractReleaseNotes("# Notes\n\n## 0.3.11\n\n- New hash\n\n## 0.3.9\n\n- Prior release\n", "0.3.11");
  assert.equal(notes, "## 0.3.11\n\n- New hash");
});

test("rejects malformed, missing, duplicate, and empty sections", () => {
  const cases = [
    ["## 0.3.11\n\n- New hash\n", "v0.3.11", "InvalidVersion"],
    ["## 0.3.9\n\n- Prior release\n", "0.3.11", "MissingOrDuplicateVersion"],
    ["## 0.3.11\n\n- First\n\n## 0.3.11\n\n- Second\n", "0.3.11", "MissingOrDuplicateVersion"],
    ["## 0.3.11\n\n## 0.3.9\n\n- Prior release\n", "0.3.11", "EmptyReleaseNotes"],
  ];
  for (const [source, version, code] of cases) {
    assert.throws(() => extractReleaseNotes(source, version), (error) => {
      assert.ok(error instanceof ReleaseNotesError);
      assert.equal(error.code, code);
      return true;
    });
  }
});

test("0.4.0 notes describe the Rust error migration and wire compatibility", () => {
  const path = fileURLToPath(new URL("../RELEASE_NOTES.md", import.meta.url));
  const notes = extractReleaseNotes(readFileSync(path, "utf8"), "0.4.0");
  assert.match(notes, /canonical\s+`CryptoErrorReason` values/u);
  assert.match(notes, /Preserves the published protobuf field numbers/u);
  assert.match(notes, /ReallyMe Buffa `0[.]1[.]1`/u);
  assert.match(notes, /Rust and TypeScript\/WASM Codec dependencies to `0[.]4[.]0`/u);
});

test("0.3.17 notes describe the additive API and dependency release", () => {
  const path = fileURLToPath(new URL("../RELEASE_NOTES.md", import.meta.url));
  const notes = extractReleaseNotes(readFileSync(path, "utf8"), "0.3.17");
  assert.match(notes, /HPKE sender and receiver contexts `Send`/u);
  assert.match(notes, /P256Sha256Digest/u);
  assert.match(notes, /Codec to `0[.]3[.]2`/u);
  assert.match(notes, /Android Gradle\s+Plugin `9[.]5[.]1`/u);
  assert.match(notes, /release-readiness `v0[.]6[.]9`/u);
  assert.match(notes, /Preserves existing wire formats/u);
});
