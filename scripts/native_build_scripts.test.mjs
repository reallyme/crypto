// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

for (const script of ["build_android_native_resources.sh", "build_kotlin_native_resource.sh", "build_swift_xcframework.sh"]) {
  test(`${script} builds the staged repository and target directory`, { skip: process.platform === "win32" }, () => {
    const fixture = mkdtempSync(join(tmpdir(), "crypto-native-build-"));
    try {
      const repository = join(fixture, "repository with spaces");
      const bin = join(fixture, "bin");
      const caller = join(fixture, "other-checkout");
      for (const path of [join(repository, "scripts"), join(repository, "crates/ffi/abi"), bin, caller,
        join(fixture, "ndk/toolchains/llvm/prebuilt/darwin-x86_64/bin")]) {
        mkdirSync(path, { recursive: true });
      }
      copyFileSync(new URL(script, import.meta.url), join(repository, "scripts", script));
      writeFileSync(join(repository, "crates/ffi/abi/reallyme_crypto_ffi.h"), "test header\n");
      // Stop at Cargo, before any native compiler or package operation. This
      // exercises real shell argument handling without needing Apple/NDK tools.
      writeFileSync(join(bin, "cargo"), '#!/usr/bin/env bash\nprintf "%s\\0" "$@" > "$BUILD_ARGUMENTS"\nexit 73\n', { mode: 0o755 });
      writeFileSync(join(bin, "uname"), '#!/usr/bin/env bash\nprintf "Darwin\\n"\n', { mode: 0o755 });
      for (const command of ["rustup", "xcodebuild", "lipo", "swift"]) {
        writeFileSync(join(bin, command), "#!/usr/bin/env bash\nexit 0\n", { mode: 0o755 });
      }
      const result = spawnSync("bash", [join(repository, "scripts", script)], {
        cwd: caller,
        encoding: "utf8",
        env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, ANDROID_NDK_HOME: join(fixture, "ndk"),
          CARGO_TARGET_DIR: join(fixture, "ambient-target"), BUILD_ARGUMENTS: join(fixture, "arguments") },
      });
      assert.equal(result.status, 73, result.stderr);
      const args = readFileSync(join(fixture, "arguments"), "utf8").split("\0");
      assert.equal(args[args.indexOf("--manifest-path") + 1], join(repository, "Cargo.toml"));
      assert.equal(args[args.indexOf("--target-dir") + 1], join(repository, "target"));
      assert.equal(args[args.indexOf("--profile") + 1], "release-ffi");
      assert.ok(args.includes("--locked"));
    } finally {
      rmSync(fixture, { recursive: true, force: true });
    }
  });
}
