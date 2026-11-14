#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export class SdkProtoGenerationError extends Error {
  constructor(code) { super("SDK protobuf generation failed"); this.name = "SdkProtoGenerationError"; this.code = code; }
}
const fail = (code) => { throw new SdkProtoGenerationError(code); };
const writeChanged = (path, before, after) => { if (before !== after) writeFileSync(path, after); };

/** Platform generators have independent diagnostic contracts; never edit Rust here. */
export function redactSdkProtoDebug(root, policy) {
  for (const file of new Set(policy.messages.map((message) => message.file))) {
    const path = join(root, "gen/swift", file.replace(/\.proto$/u, ".pb.swift"));
    const before = readFileSync(path, "utf8");
    let source = before;
    for (const message of policy.messages.filter((entry) => entry.file === file && policy.sdkNames.has(entry.name))) {
      const name = `ReallyMeProto${message.name}`;
      const declaration = source.includes(`public nonisolated struct ${name}: @unchecked Sendable {`)
        ? `public nonisolated struct ${name}: @unchecked Sendable {`
        : `public nonisolated struct ${name}: Sendable {`;
      const marker = `public var debugDescription: String { "${name}(<redacted>)" }`;
      if (!source.includes(marker)) {
        if (!source.includes(declaration)) fail("swift-declaration");
        source = source.replace(declaration, `${declaration}\n  // Security post-processing: protobuf bytes can contain secrets or PII.\n  ${marker}`);
      }
    }
    writeChanged(path, before, source);
  }
  for (const name of policy.sdkNames) {
    const path = join(root, `gen/java/me/really/crypto/v1/${name}.java`);
    const before = readFileSync(path, "utf8");
    if (before.includes(`${name}{<redacted>}`)) continue;
    const declaration = new RegExp(`public\\s+final\\s+class\\s+${name}\\s+extends`, "u").exec(before);
    if (declaration === null) fail("java-declaration");
    const open = before.indexOf("{", declaration.index);
    if (open < 0) fail("java-declaration");
    const redaction = `\n  // Security post-processing: protobuf bytes can contain secrets or PII.\n  @java.lang.Override\n  public java.lang.String toString() {\n    return "${name}{<redacted>}";\n  }\n`;
    writeChanged(path, before, before.slice(0, open + 1) + redaction + before.slice(open + 1));
  }
}

/** Keep platform output deterministic without invalidating identical files. */
export function normalizeSdkProtos(root) {
  for (const [folder, extensions] of [
    ["gen/java/me/really/crypto/v1", [".java"]], ["gen/kotlin/me/really/crypto/v1", [".kt"]],
    ["gen/swift/reallyme/crypto/v1", [".swift"]], ["gen/es/reallyme/crypto/v1", [".js", ".ts"]],
    ["packages/ts/src/proto/generated/reallyme/crypto/v1", [".ts"]],
  ]) {
    for (const file of readdirSync(join(root, folder), { withFileTypes: true })) {
      if (!file.isFile() || !extensions.some((extension) => file.name.endsWith(extension))) continue;
      const path = join(root, folder, file.name);
      const before = readFileSync(path, "utf8");
      writeChanged(path, before, before.replace(/[ \t]+$/gmu, "").replace(/\n+$/u, "\n"));
    }
  }
}
