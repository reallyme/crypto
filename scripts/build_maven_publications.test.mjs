// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { buildLocalMavenPublications, verifyLocalNativeResources } from "./build_maven_publications.mjs";
import { MavenPublicationError, publicationLayout } from "./stage_maven_publications.mjs";

const SHA = "a".repeat(40);

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "crypto-local-maven-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const resources = join(root, "resources");
  const native = join(resources, "me/really/crypto/native");
  const entries = [];
  for (const [platform, filename] of [["linux-x86_64", "libcrypto_ffi.so"], ["linux-aarch64", "libcrypto_ffi.so"],
    ["macos-x86_64", "libcrypto_ffi.dylib"], ["macos-aarch64", "libcrypto_ffi.dylib"], ["windows-x86_64", "crypto_ffi.dll"]]) {
    mkdirSync(join(native, platform), { recursive: true });
    const bytes = Buffer.from(platform);
    writeFileSync(join(native, platform, filename), bytes);
    entries.push({ path: `${platform}/${filename}`, size: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex") });
  }
  const manifest = { schemaVersion: 1, package: "reallyme-crypto-native", commitSha: SHA, entries };
  writeFileSync(join(native, "native-manifest.json"), JSON.stringify(manifest));
  for (const [lane, kind] of [["kotlin", "jvm"], ["kotlin-android", "android"]]) {
    mkdirSync(join(root, "packages", lane), { recursive: true });
    writeFileSync(join(root, "packages", lane, "build.gradle.kts"), 'version = "0.4.6"\n');
    const publication = publicationLayout("0.4.6", SHA).find(({ name }) => name.startsWith(`maven-${kind}-`));
    for (const file of publication.files) {
      const target = join(root, "packages", lane, "build/repos/releases", file.source);
      mkdirSync(join(target, ".."), { recursive: true });
      writeFileSync(target, "local publication");
    }
  }
  const destination = join(root, "destination");
  const scratch = join(root, "scratch");
  mkdirSync(destination);
  mkdirSync(scratch);
  return { root, resources, native, manifest, destination, scratch };
}

test("local Maven staging builds publications without querying ecosystem preflights", async (t) => {
  const f = fixture(t);
  const calls = [];
  await buildLocalMavenPublications(f.root, "0.4.6", SHA, f.destination, f.scratch, {
    environment: { KOTLIN_NATIVE_RESOURCES_DIR: f.resources, MAVEN_SIGNING_PASSWORD: "fixture-only" },
    run: (command, args) => {
      calls.push({ command, args });
      assert.notEqual(command, "gh");
      return command === "git" && args[0] === "rev-parse" ? SHA + "\n" : "";
    },
  });
  assert.ok(calls.some(({ command, args }) => command.endsWith("/kotlin/gradlew") && args.includes("publishMavenPublicationToLocalReleaseRepository")));
  assert.ok(calls.some(({ command, args }) => command.endsWith("/kotlin-android/gradlew") && args.includes("publishAndroidReleasePublicationToLocalReleaseRepository")));
  assert.ok(calls.some(({ command, args }) => command === "bash" && args[0].endsWith("kotlin-android/scripts/build-jni-libs.sh")));
  for (const publication of publicationLayout("0.4.6", SHA)) {
    for (const file of publication.files) assert.equal(readFileSync(join(f.destination, file.target), "utf8"), "local publication");
  }
});

test("native resource manifests reject wrong revisions, modified bytes and unexpected files", async (t) => {
  const f = fixture(t);
  await verifyLocalNativeResources(f.resources, SHA);
  await assert.rejects(verifyLocalNativeResources(f.resources, "b".repeat(40)), MavenPublicationError);
  const library = join(f.native, "linux-x86_64/libcrypto_ffi.so");
  const original = readFileSync(library);
  writeFileSync(library, "modified");
  await assert.rejects(verifyLocalNativeResources(f.resources, SHA), MavenPublicationError);
  writeFileSync(library, original);
  writeFileSync(join(f.native, "private"), "local");
  await assert.rejects(verifyLocalNativeResources(f.resources, SHA), MavenPublicationError);
});

function nativeBuildRunner(f, scenario) {
  const names = f.manifest.entries.map((entry) => entry.path.split("/")[0]);
  const payloads = names.map((name) => Buffer.from(name));
  return (command, args, message, options = {}) => {
    if (command === "git") return args[0] === "rev-parse" ? SHA : "";
    if (command === "gh") {
      assert.deepEqual(args.slice(0, 3), ["api", "--hostname", "github.com"]);
      const endpoint = args[3];
      assert.ok(!endpoint.includes("package-preflight"));
      if (endpoint.includes("/workflows/")) {
        return JSON.stringify({ workflow_runs: [{ id: 81, head_sha: scenario === "wrong-source" ? "b".repeat(40) : SHA,
          status: "completed", conclusion: "success", path: ".github/workflows/jvm-native-resources.yml",
          repository: { full_name: "reallyme/crypto" } }] });
      }
      if (endpoint.endsWith("/artifacts?per_page=100")) {
        return JSON.stringify({ artifacts: names.map((name, index) => ({ id: index + 1, name: `kotlin-native-${name}`,
          size_in_bytes: payloads[index].length, expired: scenario === "expired",
          digest: "sha256:" + createHash("sha256").update(payloads[index]).digest("hex") })) });
      }
      const match = /\/artifacts\/([1-5])\/zip$/u.exec(endpoint);
      assert.ok(match);
      const bytes = scenario === "bad-digest" ? Buffer.from("modified") : payloads[Number(match[1]) - 1];
      writeFileSync(options.stdio[1], bytes);
      return "";
    }
    if (command === "jar") {
      const platform = args[1].split("/").at(-1).replace(/\.zip$/u, "");
      const entry = f.manifest.entries.find((item) => item.path.startsWith(platform + "/"));
      const path = "me/really/crypto/native/" + entry.path;
      if (args[0] === "tf") return path + "\n";
      assert.equal(args[0], "xf");
      assert.equal(args[2], path);
      const target = join(options.cwd, path);
      mkdirSync(join(target, ".."), { recursive: true });
      writeFileSync(target, Buffer.from(platform));
      return "";
    }
    if (command === process.execPath && args[0].endsWith("write_native_manifest.mjs")) {
      mkdirSync(join(args[2], ".."), { recursive: true });
      writeFileSync(args[2], JSON.stringify(f.manifest));
    }
    return "";
  };
}

test("local staging can obtain only matching native-build artifacts without a package preflight", async (t) => {
  const f = fixture(t);
  await buildLocalMavenPublications(f.root, "0.4.6", SHA, f.destination, f.scratch, {
    environment: {}, run: nativeBuildRunner(f, "valid"),
  });
  assert.equal(readFileSync(join(f.destination, "me/really/crypto/0.4.6/crypto-0.4.6.jar"), "utf8"), "local publication");
});

for (const scenario of ["wrong-source", "expired", "bad-digest"]) {
  test(`local staging rejects ${scenario} native-build artifacts`, async (t) => {
    const f = fixture(t);
    await assert.rejects(buildLocalMavenPublications(f.root, "0.4.6", SHA, f.destination, f.scratch, {
      environment: {}, run: nativeBuildRunner(f, scenario),
    }), MavenPublicationError);
  });
}

test("native resource directories and libraries cannot be symlinks", async (t) => {
  const f = fixture(t);
  const alias = join(f.root, "alias");
  symlinkSync(f.resources, alias);
  await assert.rejects(verifyLocalNativeResources(alias, SHA), MavenPublicationError);
  const library = join(f.native, "linux-x86_64/libcrypto_ffi.so");
  rmSync(library);
  symlinkSync(join(f.native, "linux-aarch64/libcrypto_ffi.so"), library);
  await assert.rejects(verifyLocalNativeResources(f.resources, SHA), MavenPublicationError);
});

test("local builds stop before publication when the checkout or package versions disagree", async (t) => {
  const f = fixture(t);
  let calls = 0;
  await assert.rejects(buildLocalMavenPublications(f.root, "0.4.6", SHA, f.destination, f.scratch, {
    environment: { KOTLIN_NATIVE_RESOURCES_DIR: f.resources },
    run: () => { calls += 1; return "b".repeat(40); },
  }), MavenPublicationError);
  assert.equal(calls, 1);
  writeFileSync(join(f.root, "packages/kotlin/build.gradle.kts"), 'version = "0.4.4"\n');
  calls = 0;
  await assert.rejects(buildLocalMavenPublications(f.root, "0.4.6", SHA, f.destination, f.scratch, {
    run: () => { calls += 1; return ""; },
  }), MavenPublicationError);
  assert.equal(calls, 0);
});
