#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawnSync } from "node:child_process";
import { constants, closeSync, fstatSync, openSync, readSync, realpathSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGE = "reallyme.crypto.v1";
const SCHEMA = "reallyme/crypto/v1/crypto.proto";
const PREFIX = "CRYPTO_ERROR_REASON_";
const REASON_TYPE = `.${PACKAGE}.CryptoErrorReason`;
const MAX_DESCRIPTOR_BYTES = 4_194_304;
const MAX_GENERATED_BYTES = 4_194_304;
const MAX_DESCRIPTORS = 128;
const MAX_DECLARATIONS = 4_096;
const MAX_REASONS = 1_024;
const MAX_IDENTIFIER_LENGTH = 160;
const COMMAND_TIMEOUT_MS = 30_000;
const OUTPUT = "crates/proto/src/generated/error_contract.rs";
const BUFFA_OUTPUT = "crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.rs";
const REEXPORT = "pub use crate::error_types::CryptoErrorReason;";

/** Fixed diagnostics never contain descriptor values or subprocess output. */
export class ErrorContractGenerationError extends Error {
  constructor(code) {
    super("error contract generation failed");
    this.name = "ErrorContractGenerationError";
    this.code = code;
  }
}
const fail = (code) => { throw new ErrorContractGenerationError(code); };
const record = (value) => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail("descriptor-shape");
  return value;
};
const list = (value, maximum, allowEmpty = false) => {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0) || value.length > maximum) fail("descriptor-shape");
  return value;
};
const identifier = (value, pattern) => {
  if (typeof value !== "string" || value.length > MAX_IDENTIFIER_LENGTH || !pattern.test(value)) {
    fail("descriptor-identifier");
  }
  return value;
};
const integer = (value, minimum, maximum) => {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail("descriptor-number");
  return value;
};
const named = (values, name) => {
  const found = list(values, MAX_DECLARATIONS).map(record).filter((value) => value.name === name);
  if (found.length !== 1) fail("descriptor-declaration");
  return found[0];
};
const pascal = (value) => value.toLowerCase().split("_").map((word) =>
  word.charAt(0).toUpperCase() + word.slice(1)).join("");

/** Read only the descriptor schema needed by the error contract. */
export function parseErrorDescriptor(input) {
  if (typeof input !== "string" || Buffer.byteLength(input, "utf8") > MAX_DESCRIPTOR_BYTES) {
    fail("descriptor-size");
  }
  let document;
  try { document = JSON.parse(input); } catch { fail("descriptor-json"); }
  const files = list(record(document).file, MAX_DESCRIPTORS).map(record);
  const matches = files.filter((file) => file.name === SCHEMA);
  if (matches.length !== 1) fail("descriptor-file");
  const file = matches[0];
  if (file.package !== PACKAGE || file.syntax !== "proto3") fail("descriptor-file");
  const enumeration = named(file.enumType, "CryptoErrorReason");
  if (record(enumeration.options ?? {}).allowAlias === true) fail("descriptor-alias");
  const reservedNames = new Set(list(enumeration.reservedName ?? [], MAX_DECLARATIONS, true).map((name) =>
    identifier(name, /^[A-Za-z_][A-Za-z0-9_]*$/u)));
  const reservedRanges = list(enumeration.reservedRange ?? [], MAX_DECLARATIONS, true).map((raw) => {
    const range = record(raw);
    const start = integer(range.start, -2_147_483_648, 2_147_483_647);
    const end = integer(range.end, -2_147_483_648, 2_147_483_647);
    if (start > end) fail("descriptor-reserved");
    return { start, end };
  });
  const envelope = named(file.messageType, "CryptoError");
  const oneofs = list(envelope.oneofDecl, MAX_DECLARATIONS).map(record);
  if (oneofs.length !== 1 || oneofs[0].name !== "error") fail("descriptor-branch");
  const branchNames = new Set();
  const branchNumbers = new Set();
  const branches = list(envelope.field, MAX_DECLARATIONS).map((raw) => {
    const field = record(raw);
    const name = identifier(field.name, /^[a-z]+(?:_[a-z]+)*$/u);
    const number = integer(field.number, 1, 536_870_911);
    if (branchNames.has(name) || branchNumbers.has(number) || (number >= 19_000 && number <= 19_999)) {
      fail("descriptor-branch");
    }
    branchNames.add(name);
    branchNumbers.add(number);
    const rust = pascal(name);
    if (rust === "Self") fail("descriptor-identifier");
    if (field.oneofIndex !== 0 || field.label !== "LABEL_OPTIONAL" ||
        field.type !== "TYPE_MESSAGE" || field.proto3Optional === true ||
        field.typeName !== `.${PACKAGE}.Crypto${rust}Error`) fail("descriptor-branch");
    const message = named(file.messageType, `Crypto${rust}Error`);
    const fields = list(message.field, MAX_DECLARATIONS).map(record);
    const reason = fields[0];
    if (fields.length !== 1 || reason.name !== "reason" || reason.number !== 1 ||
        reason.type !== "TYPE_ENUM" || reason.typeName !== REASON_TYPE ||
        reason.label !== "LABEL_OPTIONAL" || Object.hasOwn(reason, "oneofIndex") ||
        reason.proto3Optional === true || Object.hasOwn(message, "oneofDecl")) fail("descriptor-branch");
    return { name, rust, number, prefix: `${name.toUpperCase()}_` };
  }).sort((left, right) => left.number - right.number);
  const names = new Set();
  const numbers = new Set();
  const aliases = new Set();
  const reasons = list(enumeration.value, MAX_REASONS).map((raw) => {
    const value = record(raw);
    const name = identifier(value.name, /^CRYPTO_ERROR_REASON_[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/u);
    const number = integer(value.number, 0, 2_147_483_647);
    const suffix = name.slice(PREFIX.length);
    const alias = pascal(suffix);
    if (reservedNames.has(name) || reservedRanges.some((range) => number >= range.start && number <= range.end)) {
      fail("descriptor-reserved");
    }
    if (names.has(name) || numbers.has(number) || aliases.has(alias)) fail("descriptor-alias");
    names.add(name); numbers.add(number); aliases.add(alias);
    if (number === 0) {
      if (suffix !== "UNSPECIFIED") fail("descriptor-zero");
      return { name, number, suffix, alias, branch: undefined };
    }
    const owners = branches.filter((branch) => suffix.startsWith(branch.prefix) &&
      suffix.length > branch.prefix.length);
    if (suffix === "UNSPECIFIED" || owners.length !== 1) fail("descriptor-owner");
    return { name, number, suffix, alias, branch: owners[0] };
  }).sort((left, right) => left.number - right.number);
  if (reasons[0].number !== 0) fail("descriptor-zero");
  if (!reasons.some((reason) => reason.suffix === "PRIMITIVE_INVALID_PARAMETER" &&
      reason.branch?.name === "primitive")) fail("descriptor-constructor-reason");
  if (branches.some((branch) => !reasons.some((reason) => reason.branch === branch))) fail("descriptor-owner");
  return { reasons, branches };
}

// The schema enum is the only classification vocabulary. A second native
// thiserror enum would restate every reason; the validated struct instead owns
// exactly one canonical nonzero reason and has no additional variants to map.
/** Generate one shared closed enum and a checked native error owner. */
export function renderErrorContract(contract) {
  const { reasons, branches } = contract;
  const lines = [
    "// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited", "//",
    "// SPDX-License-Identifier: MIT OR Apache-2.0", "",
    "// Generated from the schema descriptor. Regenerate with scripts/generate_error_contract.mjs.", "",
    "/// Error-envelope branch derived from the schema oneof.",
    "#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]", "#[repr(u32)]", "pub enum CryptoErrorBranch {",
    ...branches.flatMap((branch) => [`    /// The ${branch.name} error-envelope field.`,
      `    ${branch.rust} = ${branch.number},`]), "}", "",
    "/// Canonical schema reason; zero remains available for protobuf defaults.",
    "#[allow(non_camel_case_types)]", "#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]",
    "#[repr(i32)]", "pub enum CryptoErrorReason {",
    ...reasons.flatMap((reason) => [`    /// \`${reason.name}\`.`,
      ...(reason.number === 0 ? ["    #[default]"] : []), `    ${reason.name} = ${reason.number},`]),
    "}", "", "impl CryptoErrorReason {", "    /// All schema values in numeric order.",
    "    pub const VALUES: &[Self] = &[", ...reasons.map((reason) => `        Self::${reason.name},`),
    "    ];", "", "    /// Stable protobuf numeric identity.", "    #[must_use]",
    "    pub const fn code(self) -> i32 { self as i32 }", "",
    "    /// Stable schema name, independent of backend diagnostic text.", "    #[must_use]",
    "    pub const fn name(self) -> &'static str {", "        match self {",
    ...reasons.map((reason) => `            Self::${reason.name} => "${reason.name}",`),
    "        }", "    }", "", "    /// Recognize a schema number, including the protobuf zero sentinel.",
    "    #[must_use]", "    pub const fn from_code(code: i32) -> Option<Self> {", "        match code {",
    ...reasons.map((reason) => `            ${reason.number} => Some(Self::${reason.name}),`),
    "            _ => None,", "        }", "    }", "",
    "    /// The owning wire branch; an unspecified reason has no owner.", "    #[must_use]",
    "    pub const fn branch(self) -> Option<CryptoErrorBranch> {", "        match self {",
    ...reasons.map((reason) => `            Self::${reason.name} => ${reason.branch === undefined ? "None" :
      `Some(CryptoErrorBranch::${reason.branch.rust})`},`), "        }", "    }", "",
    ...reasons.flatMap((reason) => [`    /// Idiomatic alias for [\`Self::${reason.name}\`].`,
      "    #[allow(non_upper_case_globals)]", `    pub const ${reason.alias}: Self = Self::${reason.name};`]),
    "}", "",
    "impl core::fmt::Display for CryptoErrorReason {",
    "    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {",
    "        formatter.write_str(self.name())", "    }", "}", "",
    "/// Nonzero known reason with fixed diagnostics and no input-bearing fields.",
    "///", "/// ```compile_fail", "/// use reallyme_crypto_proto::error_types::CryptoError;",
    "/// let _: CryptoError = Default::default();", "/// ```", "///", "/// ```compile_fail",
    "/// use reallyme_crypto_proto::error_types::{CryptoError, CryptoErrorReason};",
    "/// let _ = CryptoError { reason: CryptoErrorReason::Unspecified };", "/// ```",
    "#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, thiserror::Error)]", "#[error(\"{reason}\")]",
    "pub struct CryptoError {", "    reason: CryptoErrorReason,", "}", "", "impl CryptoError {",
    ...reasons.filter((reason) => reason.number !== 0).flatMap((reason) => [
      `    /// The schema failure \`${reason.name}\`.`, `    pub const ${reason.suffix}: Self = Self {`,
      `        reason: CryptoErrorReason::${reason.name},`, "    };", "",
    ]), "    /// All native failure constants in schema numeric order.",
    "    pub const VALUES: &[Self] = &[",
    ...reasons.filter((reason) => reason.number !== 0).map((reason) => `        Self::${reason.suffix},`),
    "    ];", "", "    /// Validate a reason before constructing a native failure.",
    "    pub const fn try_new(reason: CryptoErrorReason) -> Result<Self, Self> {",
    "        match reason {", "            CryptoErrorReason::CRYPTO_ERROR_REASON_UNSPECIFIED =>",
    "                Err(Self::PRIMITIVE_INVALID_PARAMETER),", "            _ => Ok(Self { reason }),",
    "        }", "    }", "", "    /// The known, nonzero schema reason.", "    #[must_use]",
    "    pub const fn reason(self) -> CryptoErrorReason { self.reason }", "",
    "    /// Stable protobuf numeric identity.", "    #[must_use]",
    "    pub const fn code(self) -> i32 { self.reason.code() }", "}", "",
    "impl TryFrom<CryptoErrorReason> for CryptoError {", "    type Error = Self;",
    "    fn try_from(reason: CryptoErrorReason) -> Result<Self, Self::Error> { Self::try_new(reason) }", "}", "",
    "impl TryFrom<i32> for CryptoError {", "    type Error = Self;",
    "    fn try_from(code: i32) -> Result<Self, Self::Error> {", "        match CryptoErrorReason::from_code(code) {",
    "            Some(reason) => Self::try_new(reason),", "            None => Err(Self::PRIMITIVE_INVALID_PARAMETER),",
    "        }", "    }", "}", "",
  ];
  return lines.join("\n");
}

// Only simple generated enum/alias/default blocks are removed. Unexpected
// generator output fails closed instead of stripping unrelated Rust items.
const blockEnd = (source, start) => {
  let depth = 0;
  let comment = false;
  for (let index = source.indexOf("{", start); index >= 0 && index < source.length; index += 1) {
    const character = source[index];
    if (comment) {
      if (character === "\n") comment = false;
      continue;
    }
    if (character === "/" && source[index + 1] === "/") { comment = true; continue; }
    // These declaration blocks contain only enum values, aliases and Default.
    // Reject unfamiliar syntax instead of interpreting strings or block comments.
    if (character === '"' || (character === "/" && source[index + 1] === "*")) fail("binding-shape");
    if (character === "{") depth += 1;
    if (character === "}" && --depth === 0) return index + 1;
  }
  fail("binding-shape");
};
const uniqueIndex = (source, marker) => {
  const index = source.indexOf(marker);
  if (index < 0 || source.indexOf(marker, index + marker.length) >= 0) fail("binding-shape");
  return index;
};

/** Retain generated wire traits on the same crate-owned enum. */
export function shareReasonEnum(source, contract) {
  if (typeof source !== "string" || Buffer.byteLength(source) > MAX_GENERATED_BYTES) fail("binding-size");
  for (const implementation of ["impl ::serde::Serialize for CryptoErrorReason",
    "impl<'de> ::serde::Deserialize<'de> for CryptoErrorReason", "impl ::buffa::Enumeration for CryptoErrorReason"]) {
    uniqueIndex(source, implementation);
  }
  const implementation = uniqueIndex(source, "impl ::buffa::Enumeration for CryptoErrorReason");
  const fromStart = source.indexOf("fn from_i32(value: i32)", implementation);
  if (fromStart < 0) fail("binding-shape");
  const fromEnd = blockEnd(source, fromStart);
  const conversions = [...source.slice(fromStart, fromEnd).matchAll(/([0-9]+)i32\s*=>\s*(?:\{\s*)?::core::option::Option::Some\(\s*Self::(CRYPTO_ERROR_REASON_[A-Z0-9_]+)\s*,?\s*\)/gu)]
    .sort((left, right) => Number(left[1]) - Number(right[1]));
  if (conversions.length !== contract.reasons.length || conversions.some((match, index) =>
    Number(match[1]) !== contract.reasons[index].number || match[2] !== contract.reasons[index].name)) {
    fail("binding-descriptor-mismatch");
  }
  if (source.includes(REEXPORT)) {
    uniqueIndex(source, REEXPORT);
    if (source.includes("pub enum CryptoErrorReason") || source.includes("impl CryptoErrorReason") ||
        source.includes("impl ::core::default::Default for CryptoErrorReason")) fail("binding-shape");
    return source;
  }
  const enumIndex = uniqueIndex(source, "pub enum CryptoErrorReason {");
  const attributeStart = source.lastIndexOf("#[allow(non_camel_case_types)]", enumIndex);
  const attributes = source.slice(attributeStart, enumIndex);
  if (!/^#\[allow\(non_camel_case_types\)\]\s*#\[derive\([^\n]+\)\]\s*#\[repr\(i32\)\]\s*$/u.test(attributes)) {
    fail("binding-shape");
  }
  const enumEnd = blockEnd(source, enumIndex);
  const actual = [...source.slice(enumIndex, enumEnd).matchAll(/^\s*(CRYPTO_ERROR_REASON_[A-Z0-9_]+)\s*=\s*([0-9]+)(?:i32)?,/gmu)]
    .sort((left, right) => Number(left[2]) - Number(right[2]));
  if (actual.length !== contract.reasons.length || actual.some((match, index) =>
    match[1] !== contract.reasons[index].name || Number(match[2]) !== contract.reasons[index].number)) {
    fail("binding-descriptor-mismatch");
  }
  const aliasIndex = uniqueIndex(source, "impl CryptoErrorReason {");
  const aliasEnd = blockEnd(source, aliasIndex);
  const defaultIndex = uniqueIndex(source, "impl ::core::default::Default for CryptoErrorReason {");
  const defaultEnd = blockEnd(source, defaultIndex);
  if (aliasIndex < enumEnd || defaultIndex < aliasEnd ||
      source.slice(enumEnd, aliasIndex).trim() !== "" ||
      source.slice(aliasEnd, defaultIndex).trim() !== "") fail("binding-shape");
  const aliases = source.slice(aliasIndex, aliasEnd);
  const observedAliases = [...aliases.matchAll(/pub const ([A-Za-z][A-Za-z0-9]*): Self = Self::(CRYPTO_ERROR_REASON_[A-Z0-9_]+);/gu)];
  const expectedAliases = new Map(contract.reasons.map((reason) => [reason.alias, reason.name]));
  if (observedAliases.length !== contract.reasons.length || new Set(observedAliases.map((match) => match[1])).size !== observedAliases.length ||
      observedAliases.some((match) => expectedAliases.get(match[1]) !== match[2]) ||
    /\bfn\b/u.test(aliases)) fail("binding-shape");
  if (!/^impl ::core::default::Default for CryptoErrorReason \{\s*fn default\(\) -> Self \{\s*Self::CRYPTO_ERROR_REASON_UNSPECIFIED\s*\}\s*\}$/u
    .test(source.slice(defaultIndex, defaultEnd))) fail("binding-shape");
  return source.slice(0, attributeStart) + REEXPORT + source.slice(defaultEnd);
}

function readBounded(path, maximum, allowMissing = false) {
  let descriptor;
  try {
    if (!Number.isInteger(constants.O_NOFOLLOW)) fail("input-file");
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const status = fstatSync(descriptor);
    if (!status.isFile() || status.size === 0 || status.size > maximum) fail("input-file");
    const bytes = Buffer.alloc(status.size + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(descriptor, bytes, length, bytes.length - length, null);
      if (count === 0) break;
      length += count;
      if (length > status.size || length > maximum) fail("input-file");
    }
    if (length !== status.size) fail("input-file");
    return bytes.subarray(0, length).toString("utf8");
  } catch (error) {
    if (error instanceof ErrorContractGenerationError) throw error;
    if (allowMissing && error !== null && typeof error === "object" && error.code === "ENOENT") return undefined;
    fail("input-file");
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}

/** Preserve incremental-build timestamps when maintenance output is unchanged. */
export function writeErrorContractOutput(path, source) {
  if (typeof source !== "string" || source.length === 0 || Buffer.byteLength(source) > MAX_GENERATED_BYTES) {
    fail("binding-size");
  }
  if (readBounded(path, MAX_GENERATED_BYTES, true) === source) return;
  const flags = constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW;
  try { writeFileSync(path, source, { flag: flags }); } catch { fail("output-file"); }
}

function command(commandName, args, options = {}) {
  const result = spawnSync(commandName, args, { ...options, encoding: "utf8",
    maxBuffer: MAX_DESCRIPTOR_BYTES, timeout: COMMAND_TIMEOUT_MS });
  if (result.error !== undefined || result.status !== 0 || result.signal !== null ||
      typeof result.stdout !== "string") fail("generation-command");
  return result.stdout;
}

function main() {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args.length === 1 && args[0] !== "--check")) fail("arguments");
  const root = fileURLToPath(new URL("../", import.meta.url));
  const descriptor = command("buf", ["build", "--as-file-descriptor-set", "-o", "-#format=json"], { cwd: root });
  const contract = parseErrorDescriptor(descriptor);
  const original = readBounded(resolve(root, BUFFA_OUTPUT), MAX_GENERATED_BYTES);
  const rust = command("rustfmt", ["--edition", "2021", "--emit", "stdout"], { cwd: root, input: renderErrorContract(contract) });
  const shared = shareReasonEnum(original, contract);
  if (args[0] === "--check") {
    if (readBounded(resolve(root, OUTPUT), MAX_GENERATED_BYTES) !== rust || shared !== original) fail("stale-output");
    return;
  }
  // Compute and validate both outputs before making either maintenance edit.
  if (shared !== original) writeErrorContractOutput(resolve(root, BUFFA_OUTPUT), shared);
  writeErrorContractOutput(resolve(root, OUTPUT), rust);
}

const sourcePath = fileURLToPath(import.meta.url);
const entryPath = process.argv[1] === undefined ? undefined : resolve(process.argv[1]);
let isEntry = entryPath === sourcePath;
if (!isEntry && entryPath !== undefined) {
  // A symlink invocation still selects the real repository root. Imports from
  // another entry point must remain free of generation or process-exit effects.
  try { isEntry = realpathSync(entryPath) === sourcePath; } catch { isEntry = false; }
}
if (isEntry) {
  try { main(); } catch (error) {
    process.stderr.write(error instanceof ErrorContractGenerationError ?
      `error contract generation failed: ${error.code}\n` : "error contract generation failed: internal\n");
    process.exitCode = 1;
  }
}
