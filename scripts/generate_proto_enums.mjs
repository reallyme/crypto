#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const MAX_DESCRIPTOR_BYTES = 4_194_304;
const PACKAGE = "reallyme.crypto.v1";
const OUTPUT = "crates/proto/src/generated/enum_contracts.rs";

export class ProtoEnumGenerationError extends Error {
  constructor(code) {
    super("protobuf enum contract generation failed");
    this.name = "ProtoEnumGenerationError";
    this.code = code;
  }
}
const fail = (code) => { throw new ProtoEnumGenerationError(code); };
const identifier = (value) => {
  if (typeof value !== "string" || value.length > 160 || !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(value)) fail("identifier");
  return value;
};
const pascal = (value) => value.toLowerCase().split("_").map((word) => word.charAt(0).toUpperCase() + word.slice(1)).join("");
const shouty = (value) => value.replace(/([A-Z]+)([A-Z][a-z])/gu, "$1_$2").replace(/([a-z0-9])([A-Z])/gu, "$1_$2").toUpperCase();

/** A single descriptor defines both concrete enum authority and native mappings. */
export function parseProtoEnums(document) {
  if (document === null || typeof document !== "object" || !Array.isArray(document.file) || document.file.length > 128) fail("descriptor");
  const result = [];
  const names = new Set();
  for (const file of document.file) {
    if (file.package !== PACKAGE) continue;
    for (const enumeration of file.enumType ?? []) {
      const name = identifier(enumeration.name);
      if (names.has(name) || enumeration.options?.allowAlias === true || !Array.isArray(enumeration.value) || enumeration.value.length === 0 || enumeration.value.length > 4096) fail("enum");
      names.add(name);
      const numbers = new Set();
      const variants = new Set();
      const aliases = new Set();
      const prefix = shouty(name) + "_";
      const values = enumeration.value.map((value) => {
        const variant = identifier(value.name);
        const number = value.number ?? 0;
        if (!Number.isSafeInteger(number) || number < -2_147_483_648 || number > 2_147_483_647 || numbers.has(number) || variants.has(variant)) fail("value");
        const alias = pascal(variant.startsWith(prefix) ? variant.slice(prefix.length) : variant);
        if (aliases.has(alias) || alias === "Self") fail("alias");
        numbers.add(number); variants.add(variant); aliases.add(alias);
        return { name: variant, number, alias };
      });
      if (values[0].number !== 0) fail("default");
      result.push({ name, values });
    }
  }
  if (result.length === 0 || result.length > 128) fail("enum-count");
  return result;
}

export function renderProtoEnums(enumerations) {
  const lines = ["// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited", "//", "// SPDX-License-Identifier: MIT OR Apache-2.0", "", "// Generated from canonical schema descriptors by scripts/generate_proto_enums.mjs.", "", "pub use crate::error_types::CryptoErrorReason;", ""];
  for (const { name, values } of enumerations) {
    if (name !== "CryptoErrorReason") {
      lines.push(`/// Schema-owned identity \`${PACKAGE}.${name}\`.`, "#[allow(non_camel_case_types)]", "#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]", "#[repr(i32)]", `pub enum ${name} {`);
      for (const [index, value] of values.entries()) lines.push(`    /// \`${value.name}\`.`, ...(index === 0 ? ["    #[default]"] : []), `    ${value.name} = ${value.number},`);
      lines.push("}", `impl ${name} {`);
      for (const value of values) lines.push(`    /// Idiomatic alias for [\`Self::${value.name}\`].`, "    #[allow(non_upper_case_globals)]", `    pub const ${value.alias}: Self = Self::${value.name};`);
      lines.push("}");
    }
    lines.push(`impl ::buffa::Enumeration for ${name} {`, "    fn from_i32(value: i32) -> Option<Self> {", "        match value {", ...values.map((value) => `            ${value.number} => Some(Self::${value.name}),`), "            _ => None,", "        }", "    }", "    fn to_i32(&self) -> i32 { *self as i32 }", "    fn proto_name(&self) -> &'static str {", "        match self {", ...values.map((value) => `            Self::${value.name} => "${value.name}",`), "        }", "    }", "    fn from_proto_name(name: &str) -> Option<Self> {", "        match name {", ...values.map((value) => `            "${value.name}" => Some(Self::${value.name}),`), "            _ => None,", "        }", "    }", "    fn values() -> &'static [Self] {", "        &[", ...values.map((value) => `            Self::${value.name},`), "        ]", "    }", "}", `impl ::zeroize::Zeroize for ${name} {`, "    fn zeroize(&mut self) { ::buffa::sensitive::reset_copy(self); }", "}", `impl ::serde::Serialize for ${name} {`, "    fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {", "        serializer.serialize_str(::buffa::Enumeration::proto_name(self))", "    }", "}", `impl<'de> ::serde::Deserialize<'de> for ${name} {`, "    fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {", "        crate::enum_json::deserialize(deserializer)", "    }", "}", `impl ::buffa::json_helpers::ProtoElemJson for ${name} {`, "    fn serialize_proto_json<S: ::serde::Serializer>(value: &Self, serializer: S) -> Result<S::Ok, S::Error> {", "        ::serde::Serialize::serialize(value, serializer)", "    }", "    fn deserialize_proto_json<'de, D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {", "        ::serde::Deserialize::deserialize(deserializer)", "    }", "}", "");
  }
  return lines.join("\n");
}

export function generateProtoEnums(root, document, check = false) {
  const source = renderProtoEnums(parseProtoEnums(document));
  const formatted = spawnSync("rustfmt", ["--edition", "2021", "--emit", "stdout"], { input: source, encoding: "utf8", timeout: 30_000, maxBuffer: MAX_DESCRIPTOR_BYTES });
  if (formatted.status !== 0 || formatted.error !== undefined) fail("format");
  const path = resolve(root, OUTPUT);
  let before;
  try { before = readFileSync(path, "utf8"); } catch (error) { if (error.code !== "ENOENT") fail("read"); }
  if (check) { if (before !== formatted.stdout) fail("stale"); }
  else if (before !== formatted.stdout) writeFileSync(path, formatted.stdout);
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length > 3 || (process.argv.length === 3 && process.argv[2] !== "--check")) fail("arguments");
    const root = fileURLToPath(new URL("../", import.meta.url));
    const descriptor = spawnSync("buf", ["build", "--exclude-source-info", "--as-file-descriptor-set", "-o", "-#format=json"], { cwd: root, encoding: "utf8", maxBuffer: MAX_DESCRIPTOR_BYTES, timeout: 30_000 });
    if (descriptor.status !== 0 || descriptor.error !== undefined) fail("descriptor-command");
    generateProtoEnums(root, JSON.parse(descriptor.stdout), process.argv[2] === "--check");
  } catch (error) {
    process.stderr.write(`protobuf enum generation failed: ${error instanceof ProtoEnumGenerationError ? error.code : "internal"}\n`);
    process.exitCode = 1;
  }
}
