#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url);

const rustGeneratedFiles = [
  "crates/proto/crypto/src/generated/buffa/reallyme.crypto.v1.crypto.rs",
  "crates/proto/crypto/src/generated/buffa/reallyme.crypto.v1.crypto.__view.rs",
];

const protoPath = join(
  root.pathname,
  "crates/proto/crypto/proto/reallyme/crypto/v1/crypto.proto",
);
const protoSource = readFileSync(protoPath, "utf8");
const byteFieldNames = new Set();
const byteBearingMessageNames = [];
const messagePattern = /message\s+(\w+)\s*\{([\s\S]*?)\n\}/gu;
for (const match of protoSource.matchAll(messagePattern)) {
  const [, messageName, body] = match;
  const fields = [...body.matchAll(/\bbytes\s+(\w+)\s*=/gu)];
  if (fields.length === 0) {
    continue;
  }
  byteBearingMessageNames.push(messageName);
  for (const field of fields) {
    byteFieldNames.add(field[1]);
  }
}

for (const relativePath of rustGeneratedFiles) {
  const filePath = join(root.pathname, relativePath);
  let source = readFileSync(filePath, "utf8");

  for (const fieldName of byteFieldNames) {
    source = source.replaceAll(
      `.field("${fieldName}", &self.${fieldName})`,
      `.field("${fieldName}", &"<redacted>")`,
    );
  }

  writeFileSync(filePath, source);
}

const swiftPath = join(
  root.pathname,
  "gen/swift/reallyme/crypto/v1/crypto.pb.swift",
);
let swiftSource = readFileSync(swiftPath, "utf8");
for (const messageName of byteBearingMessageNames) {
  const swiftName = `ReallyMeProto${messageName}`;
  const declaration = `public nonisolated struct ${swiftName}: Sendable {`;
  const replacement = `${declaration}
  // Security post-processing: protobuf bytes can contain secrets or PII.
  public var debugDescription: String { "${swiftName}(<redacted>)" }

  public func hash(into hasher: inout Hasher) {
    hasher.combine("${swiftName}(<redacted>)")
  }`;
  if (!swiftSource.includes(`${swiftName}(<redacted>)`)) {
    swiftSource = swiftSource.replace(declaration, replacement);
  }
}
writeFileSync(swiftPath, swiftSource);

for (const messageName of byteBearingMessageNames) {
  const javaPath = join(
    root.pathname,
    `gen/java/me/really/crypto/v1/${messageName}.java`,
  );
  let javaSource = readFileSync(javaPath, "utf8");
  if (javaSource.includes(`${messageName}{<redacted>}`)) {
    continue;
  }
  const declaration = new RegExp(`public\\s+final class ${messageName} extends`, "u");
  const declarationMatch = declaration.exec(javaSource);
  const declarationStart = declarationMatch?.index ?? -1;
  const bodyStart = javaSource.indexOf("{", declarationStart);
  if (declarationStart < 0 || bodyStart < 0) {
    throw new Error(`unable to locate generated Java message ${messageName}`);
  }
  const redaction = `
  // Security post-processing: protobuf bytes can contain secrets or PII.
  @java.lang.Override
  public java.lang.String toString() {
    return "${messageName}{<redacted>}";
  }

  @java.lang.Override
  public int hashCode() {
    return 0x524d;
  }
`;
  javaSource = `${javaSource.slice(0, bodyStart + 1)}${redaction}${javaSource.slice(bodyStart + 1)}`;
  writeFileSync(javaPath, javaSource);
}
