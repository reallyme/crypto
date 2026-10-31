// SPDX-FileCopyrightText: 2026 ReallyMe LLC
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

test("current 0.3.16 notes describe the dependency maintenance release", () => {
  const path = fileURLToPath(new URL("../RELEASE_NOTES.md", import.meta.url));
  const notes = extractReleaseNotes(readFileSync(path, "utf8"), "0.3.16");
  assert.match(notes, /constant-time hardening/u);
  assert.match(notes, /hpke` from `0[.]14[.]1` to `0[.]15[.]1/u);
  assert.match(notes, /log` `0[.]4[.]35/u);
  assert.match(notes, /wasm-bindgen` `0[.]2[.]130/u);
  assert.match(notes, /wasm-pack` `0[.]15[.]1/u);
  assert.match(notes, /Android Gradle Plugin `9[.]5[.]0`/u);
  assert.match(notes, /Preserves the `0[.]3[.]15` public API/u);
});
