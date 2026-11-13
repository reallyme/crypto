// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const runFixture = (context, mode, host = "Linux") => {
  const root = mkdtempSync(join(tmpdir(), "crypto ABI gate "));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const bin = join(root, "bin");
  mkdirSync(bin);
  mkdirSync(join(root, "scripts"));
  copyFileSync(new URL("./test_ffi_abi_release_artifact.sh", import.meta.url), join(root, "scripts/check.sh"));
  const executable = (name, body) => writeFileSync(join(bin, name), `#!/usr/bin/env bash\nset -eu\n${body}\n`, { mode: 0o755 });
  executable("uname", 'printf "%s\\n" "$ABI_TEST_HOST"');
  executable("rustc", 'printf "host: %s\\n" "$ABI_TEST_TARGET"');
  executable("cargo", `
printf '%s\\0' "$@" >> "$ABI_TEST_ROOT/cargo-args"
if [[ "$1" == check ]]; then
  if [[ "$ABI_TEST_MODE" == abort-success ]]; then exit 0; fi
  if [[ "$ABI_TEST_MODE" == unrelated-error ]]; then echo 'unrelated build failure' >&2; exit 101; fi
  echo 'crypto-ffi release artifacts require an unwind-capable panic strategy' >&2
  exit 101
fi
mkdir -p "$ABI_TEST_ROOT/target/$ABI_TEST_TARGET/release-ffi"
touch "$ABI_TEST_ROOT/target/$ABI_TEST_TARGET/release-ffi/libcrypto_ffi.so" "$ABI_TEST_ROOT/target/$ABI_TEST_TARGET/release-ffi/libcrypto_ffi.dylib"
`);
  executable("nm", `
printf '%s\\0' "$@" > "$ABI_TEST_ROOT/nm-args"
if [[ "$ABI_TEST_MODE" != missing-export ]]; then
  if [[ "$ABI_TEST_HOST" == Darwin ]]; then echo '_rm_crypto_ed25519_verify'; else echo 'rm_crypto_ed25519_verify'; fi
fi
if [[ "$ABI_TEST_MODE" == conformance-export ]]; then echo 'rm_crypto_ml_kem_768_encapsulate_derand'; fi
`);
  executable("clang", `
touch "$ABI_TEST_ROOT/clang-called"
while [[ "$1" != -o ]]; do shift; done
shift
printf '#!/usr/bin/env bash\\nexit %s\\n' "$ABI_TEST_HARNESS_EXIT" > "$1"
chmod +x "$1"
`);
  const result = spawnSync("bash", [join(root, "scripts/check.sh")], {
    cwd: tmpdir(), encoding: "utf8", timeout: 10_000,
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, ABI_TEST_ROOT: root,
      ABI_TEST_MODE: mode, ABI_TEST_HOST: host, ABI_TEST_HARNESS_EXIT: mode === "harness-error" ? "73" : "0",
      ABI_TEST_TARGET: host === "Darwin" ? "aarch64-apple-darwin" : "x86_64-unknown-linux-gnu",
      CARGO_TARGET_DIR: join(root, "ambient-target"), CARGO_BUILD_TARGET: "wasm32-unknown-unknown" },
  });
  return { result, root };
};

test("one production artifact supplies symbols and the sanitizer on Linux and macOS", (context) => {
  for (const host of ["Linux", "Darwin"]) {
    const { result, root } = runFixture(context, "valid", host);
    assert.equal(result.status, 0, result.stderr);
    const cargo = readFileSync(join(root, "cargo-args"), "utf8").split("\0");
    assert.equal(cargo.filter((arg) => arg === "build").length, 1);
    assert.equal(cargo.filter((arg) => arg === "check").length, 1);
    assert.equal(cargo.filter((arg) => arg === "--target").length, 2);
    assert.equal(cargo.filter((arg) => arg === "--target-dir").length, 2);
    for (const [index, arg] of cargo.entries()) {
      if (arg === "--target-dir") assert.equal(cargo[index + 1], join(root, "target"));
      if (arg === "--target") assert.equal(cargo[index + 1], host === "Darwin" ? "aarch64-apple-darwin" : "x86_64-unknown-linux-gnu");
    }
    const nm = readFileSync(join(root, "nm-args"), "utf8");
    assert.ok(nm.includes(join(root, "target", host === "Darwin" ? "aarch64-apple-darwin" : "x86_64-unknown-linux-gnu", "release-ffi/libcrypto_ffi")));
    assert.ok(nm.includes(host === "Darwin" ? "-gU" : "--defined-only"));
    assert.match(result.stdout, /passed C sanitizer checks/u);
  }
});

test("abort rejection requires the intended compilation diagnostic", (context) => {
  for (const mode of ["abort-success", "unrelated-error"]) {
    const { result } = runFixture(context, mode);
    assert.equal(result.status, 1, result.stderr);
    assert.doesNotMatch(result.stdout, /passed C sanitizer checks/u);
  }
});

test("missing production exports and leaked conformance exports fail the gate", (context) => {
  for (const mode of ["missing-export", "conformance-export"]) {
    const { result } = runFixture(context, mode);
    assert.equal(result.status, 1, result.stderr);
    assert.doesNotMatch(result.stdout, /passed C sanitizer checks/u);
  }
});

test("a failed C sanitizer executable cannot produce a green gate", (context) => {
  const { result } = runFixture(context, "harness-error");
  assert.equal(result.status, 73, result.stderr);
  assert.doesNotMatch(result.stdout, /passed C sanitizer checks/u);
});
