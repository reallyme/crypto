// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { ContractConstantsGenerationError, parseContractConstantsDescriptor,
  renderContractConstants, validateErrorReasonRanges } from "./generate_contract_constants.mjs";

const PACKAGE = "reallyme.crypto.contract.v1";
const OPTION = `[${PACKAGE}.constant_registry]`;
const typeNames = ["UNSPECIFIED", "U8", "U16", "U32", "U64", "USIZE", "I32", "BYTES"];
const unitNames = ["UNSPECIFIED", "BYTES", "BITS", "KIBIBYTES", "ITERATIONS", "PASSES", "LANES",
  "EVALUATIONS", "IDENTIFIER", "DIMENSIONLESS", "COUNT", "LEVELS"];
const field = (name, number, type, extra = {}) => ({ name, number, type, label: "LABEL_OPTIONAL", ...extra });
const type = (name) => `.${PACKAGE}.${name}`;
const sample = (nativeName = "BUFFER_BYTES", nativeType = "USIZE", unit = "BYTES", value = "32") => ({
  nativeName, nativeType: `NATIVE_TYPE_${nativeType}`, unit: `UNIT_${unit}`,
  [nativeType === "I32" ? "signedValue" : nativeType === "BYTES" ? "bytesValue" : "unsignedValue"]: value,
});
const fixture = () => ({ file: [{
  name: "reallyme/crypto/contract/v1/constants.proto", package: PACKAGE,
  enumType: [{ name: "NativeType", value: typeNames.map((name, number) => ({ name: `NATIVE_TYPE_${name}`, number })) },
    { name: "Unit", value: unitNames.map((name, number) => ({ name: `UNIT_${name}`, number })) }],
  messageType: [{ name: "Constant", oneofDecl: [{ name: "value" }], field: [
    field("native_name", 1, "TYPE_STRING"), field("native_type", 2, "TYPE_ENUM", { typeName: type("NativeType") }),
    field("unit", 3, "TYPE_ENUM", { typeName: type("Unit") }), field("unsigned_value", 4, "TYPE_UINT64", { oneofIndex: 0 }),
    field("signed_value", 5, "TYPE_SINT64", { oneofIndex: 0 }), field("bytes_value", 6, "TYPE_BYTES", { oneofIndex: 0 }),
    field("constant_reference", 7, "TYPE_MESSAGE", { typeName: type("ConstantReference"), oneofIndex: 0 }),
    field("enum_reference", 8, "TYPE_MESSAGE", { typeName: type("EnumValueReference"), oneofIndex: 0 }),
  ] }, { name: "ConstantRange", field: [field("minimum_name", 1, "TYPE_STRING"), field("maximum_name", 2, "TYPE_STRING")] },
  { name: "ConstantReference", field: [field("native_module", 1, "TYPE_STRING"), field("native_name", 2, "TYPE_STRING")] },
  { name: "EnumValueReference", field: [field("enum_type", 1, "TYPE_STRING"), field("value_name", 2, "TYPE_STRING")] },
  { name: "ConstantModule", field: [field("native_module", 1, "TYPE_STRING"),
    field("constants", 2, "TYPE_MESSAGE", { typeName: type("Constant"), label: "LABEL_REPEATED" }),
    field("ranges", 3, "TYPE_MESSAGE", { typeName: type("ConstantRange"), label: "LABEL_REPEATED" })] },
  { name: "ConstantRegistry", field: [field("modules", 1, "TYPE_MESSAGE", { typeName: type("ConstantModule"), label: "LABEL_REPEATED" })] }],
  extension: [{ name: "constant_registry", number: 51000, extendee: ".google.protobuf.FileOptions",
    type: "TYPE_MESSAGE", typeName: type("ConstantRegistry"), label: "LABEL_OPTIONAL" }],
}, { name: "reallyme/crypto/contract/v1/example_constants.proto", package: PACKAGE,
  options: { [OPTION]: { modules: [{ nativeModule: "example", constants: [sample()] }] } },
}] });
const registry = (document) => document.file[1].options[OPTION];
const module = (document) => registry(document).modules[0];
const rejects = (mutate, code) => {
  const document = fixture();
  mutate(document);
  assert.throws(() => parseContractConstantsDescriptor(document), (error) =>
    error instanceof ContractConstantsGenerationError && error.code === code);
};

test("descriptor emits exact native types and schema values without codec dependencies", () => {
  const document = fixture();
  module(document).constants = [sample("BYTE", "U8", "BYTES", "255"),
    sample("WORD", "U16", "BITS", "65535"), sample("COUNT", "U32", "COUNT", "4294967295"),
    sample("WORK", "U64", "EVALUATIONS", "18446744073709551615"),
    sample("BUFFER", "USIZE", "BYTES", "4294967295"), sample("STATUS", "I32", "IDENTIFIER", "-2147483648"),
    sample("PREFIX", "BYTES", "BYTES", "AAH/")];
  const output = renderContractConstants(parseContractConstantsDescriptor(document));
  for (const declaration of ["BYTE: u8 = 255", "WORD: u16 = 65535", "COUNT: u32 = 4294967295",
    "WORK: u64 = 18446744073709551615", "BUFFER: usize = 4294967295", "STATUS: i32 = -2147483648",
    "PREFIX: &[u8] = &[0x00, 0x01, 0xff]"]) assert.ok(output.includes(declaration));
  assert.doesNotMatch(output, /buffa|serde|thiserror|crypto_core|CryptoError|FileDescriptor/u);
});

test("explicit zero and empty public byte constants retain their oneof presence", () => {
  const document = fixture();
  module(document).constants = [sample("ZERO", "USIZE", "COUNT", "0"), sample("EMPTY", "BYTES", "BYTES", "")];
  const output = renderContractConstants(parseContractConstantsDescriptor(document));
  assert.match(output, /ZERO: usize = 0/u);
  assert.match(output, /EMPTY: &\[u8\] = &\[\]/u);
  rejects((value) => { delete module(value).constants[0].unsignedValue; }, "constants-value");
});

test("descriptors reject missing, unknown and ambiguous metadata", () => {
  for (const key of ["nativeName", "nativeType", "unit"]) {
    rejects((value) => { delete module(value).constants[0][key]; }, "constants-fields");
  }
  rejects((value) => { module(value).constants[0].replacementValue = "1"; }, "constants-fields");
  rejects((value) => { module(value).constants[0].signedValue = "1"; }, "constants-value");
  rejects((value) => { module(value).constants[0].nativeType = "NATIVE_TYPE_UNSPECIFIED"; }, "constants-type");
  rejects((value) => { module(value).constants[0].unit = "UNIT_UNSPECIFIED"; }, "constants-type");
  rejects((value) => { module(value).constants[0].unit = "UNIT_UNKNOWN"; }, "constants-type");
  rejects((value) => { module(value).extra = {}; }, "constants-fields");
  rejects((value) => { registry(value).extra = {}; }, "constants-fields");
  rejects((value) => { value.file[1].options = {}; }, "constants-missing");
  rejects((value) => { value.file[1].options[`[${PACKAGE}.constant_typo]`] = {}; }, "constants-option");
  rejects((value) => { value.file[1].messageType = [{ options: { [OPTION]: registry(value) } }]; }, "constants-owner");
});

test("all scalar bounds and decimal encodings fail closed", () => {
  for (const [nativeType, unit, value] of [["U8", "BYTES", "256"], ["U16", "BITS", "65536"],
    ["U32", "COUNT", "4294967296"], ["U64", "EVALUATIONS", "18446744073709551616"],
    ["USIZE", "BYTES", "4294967296"], ["USIZE", "BYTES", "-1"],
    ["I32", "IDENTIFIER", "2147483648"], ["I32", "IDENTIFIER", "-2147483649"]]) {
    rejects((document) => { module(document).constants = [sample("VALUE", nativeType, unit, value)]; }, "constants-overflow");
  }
  for (const value of [32, "01", "+1", "1.0", "1e3", "-0", "", "9".repeat(22)]) {
    rejects((document) => { module(document).constants[0].unsignedValue = value; }, "constants-decimal");
  }
  rejects((document) => { module(document).constants = [sample("VALUE", "I32", "BYTES", "1")]; }, "constants-unit");
  rejects((document) => { module(document).constants[0] = { ...sample("VALUE", "U8"), signedValue: "1" };
    delete module(document).constants[0].unsignedValue; }, "constants-value");
});

test("byte metadata is bounded, canonical and measured in bytes", () => {
  for (const value of ["@@@", "AQ=", "AB==", Buffer.alloc(4097).toString("base64")]) {
    rejects((document) => { module(document).constants = [sample("VALUE", "BYTES", "BYTES", value)]; }, "constants-bytes");
  }
  rejects((document) => { module(document).constants = [sample("VALUE", "BYTES", "BITS", "AA==")]; }, "constants-bytes");
});

test("native names, duplicate records and module merging are unambiguous", () => {
  for (const value of ["self", "async", "gen", "Example", "__proto__", "bad/path"]) {
    rejects((document) => { module(document).nativeModule = value; }, "constants-identifier");
  }
  for (const value of ["value", "VALUE*/", "1VALUE", "__VALUE", "V".repeat(129)]) {
    rejects((document) => { module(document).constants[0].nativeName = value; }, "constants-identifier");
  }
  rejects((document) => { module(document).constants.push(module(document).constants[0]); }, "constants-duplicate");
  rejects((document) => { registry(document).modules.push(module(document)); }, "constants-duplicate");
  const document = fixture();
  const other = structuredClone(document.file[1]);
  other.name = "reallyme/crypto/contract/v1/other_constants.proto";
  other.options[OPTION].modules[0].constants[0].nativeName = "OTHER_BYTES";
  document.file.push(other);
  assert.equal(parseContractConstantsDescriptor(document).modules[0].constants.length, 2);
  other.options[OPTION].modules[0].constants[0].nativeName = "BUFFER_BYTES";
  assert.throws(() => parseContractConstantsDescriptor(document), (error) =>
    error instanceof ContractConstantsGenerationError && error.code === "constants-duplicate");
});

test("named bounds cannot reference missing, reversed or incompatible constants", () => {
  const withRange = (document) => {
    module(document).constants = [sample("MIN", "USIZE", "BYTES", "1"), sample("MAX", "USIZE", "BYTES", "32")];
    module(document).ranges = [{ minimumName: "MIN", maximumName: "MAX" }];
  };
  const document = fixture(); withRange(document);
  assert.equal(parseContractConstantsDescriptor(document).modules[0].ranges.length, 1);
  rejects((value) => { withRange(value); module(value).constants[0].unsignedValue = "33"; }, "constants-range");
  rejects((value) => { withRange(value); module(value).ranges[0].minimumName = "ABSENT"; }, "constants-range");
  rejects((value) => { withRange(value); module(value).constants[0].unit = "UNIT_BITS"; }, "constants-range");
  rejects((value) => { withRange(value); module(value).constants[0].nativeType = "NATIVE_TYPE_U32"; }, "constants-range");
  rejects((value) => { withRange(value); module(value).ranges[0].minimum = "1"; }, "constants-fields");
});

test("schema representation and descriptor work remain bounded", () => {
  rejects((document) => { document.file[0].enumType[0].value.push({ name: "NATIVE_TYPE_FLOAT", number: 8 }); }, "constants-enum");
  rejects((document) => { document.file[0].messageType[0].field[3].oneofIndex = 1; }, "constants-field");
  rejects((document) => { document.file[0].extension[0].extendee = ".google.protobuf.MessageOptions"; }, "constants-extension");
  rejects((document) => { document.file[0].messageType[0].field[0].defaultValue = "OVERRIDE"; }, "constants-field");
  rejects((document) => { module(document).constants = Array(4097).fill(sample()); }, "constants-complexity");
  rejects((document) => {
    let node = document.file[1];
    for (let depth = 0; depth < 65; depth += 1) { node.next = {}; node = node.next; }
  }, "constants-complexity");
});

test("known error reasons must belong to the schema-owned family bounds", () => {
  const branches = [{ name: "primitive" }, { name: "provider" }, { name: "backend" }];
  const errors = { branches, reasons: branches.map((branch, index) => ({ branch, number: (index + 1) * 100 })) };
  const constants = { modules: [{ name: "proto_wire", constants: branches.flatMap((branch, index) => [
    { name: `${branch.name.toUpperCase()}_REASON_CODE_MIN`, type: "i32", unit: "UNIT_IDENTIFIER", value: String((index + 1) * 100) },
    { name: `${branch.name.toUpperCase()}_REASON_CODE_MAX`, type: "i32", unit: "UNIT_IDENTIFIER", value: String((index + 1) * 100 + 99) },
  ]) }] };
  validateErrorReasonRanges(errors, constants);
  errors.reasons[1].number = 100;
  assert.throws(() => validateErrorReasonRanges(errors, constants), (error) =>
    error instanceof ContractConstantsGenerationError && error.code === "constants-reason-range");
});

test("maintenance shares one descriptor invocation and validates before output writes", () => {
  const source = readFileSync(new URL("./generate_error_contract.mjs", import.meta.url), "utf8");
  assert.equal([...source.matchAll(/command\("buf",/gu)].length, 1);
  assert.match(source, /parseContractConstantsDescriptor\(document\)/u);
  assert.match(source, /validateErrorReasonRanges\(contract, constantsContract\)/u);
  assert.ok(source.indexOf("validateErrorReasonRanges(contract, constantsContract)") <
    source.indexOf("writeErrorContractOutput(resolve(root, OUTPUT), rust)"));
});

test("scalar aliases resolve across modules and retain reference-only Rust output", () => {
  const document = fixture();
  module(document).constants.push({ nativeName: "ALIAS", nativeType: "NATIVE_TYPE_USIZE", unit: "UNIT_BYTES",
    constantReference: { nativeModule: "example", nativeName: "BUFFER_BYTES" } });
  const contract = parseContractConstantsDescriptor(document);
  assert.equal(contract.modules[0].constants.find((value) => value.name === "ALIAS").value, "32");
  assert.match(renderContractConstants(contract), /ALIAS: usize = super::example::BUFFER_BYTES/u);
  rejects((value) => { module(value).constants[0] = { nativeName: "ALIAS", nativeType: "NATIVE_TYPE_USIZE", unit: "UNIT_BYTES",
    constantReference: { nativeModule: "example", nativeName: "ALIAS" } }; }, "constants-reference-cycle");
  rejects((value) => { module(value).constants.push({ nativeName: "ALIAS", nativeType: "NATIVE_TYPE_U32", unit: "UNIT_BYTES",
    constantReference: { nativeModule: "example", nativeName: "BUFFER_BYTES" } }); }, "constants-reference-type");
  rejects((value) => { module(value).constants.push({ nativeName: "ALIAS", nativeType: "NATIVE_TYPE_USIZE", unit: "UNIT_BITS",
    constantReference: { nativeModule: "example", nativeName: "BUFFER_BYTES" } }); }, "constants-reference-type");
  rejects((value) => { module(value).constants.push({ nativeName: "ALIAS", nativeType: "NATIVE_TYPE_USIZE", unit: "UNIT_BYTES",
    constantReference: { nativeModule: "example", nativeName: "ABSENT" } }); }, "constants-reference");
});

test("identity constants resolve only positive known schema enum values", () => {
  const makeReference = (document, valueName = "SCHEMA_ID_EXAMPLE") => {
    document.file[1].enumType = [{ name: "SchemaId", value: [
      { name: "SCHEMA_ID_UNSPECIFIED", number: 0 }, { name: "SCHEMA_ID_EXAMPLE", number: 16 },
    ] }];
    module(document).constants = [{ nativeName: "IDENTITY", nativeType: "NATIVE_TYPE_U16", unit: "UNIT_IDENTIFIER",
      enumReference: { enumType: `.${PACKAGE}.SchemaId`, valueName } }];
  };
  const document = fixture(); makeReference(document);
  assert.match(renderContractConstants(parseContractConstantsDescriptor(document)), /IDENTITY: u16 = 16/u);
  document.file[1].enumType[0].value[1].number = 17;
  assert.match(renderContractConstants(parseContractConstantsDescriptor(document)), /IDENTITY: u16 = 17/u);
  rejects((value) => { makeReference(value, "SCHEMA_ID_UNSPECIFIED"); }, "constants-enum-reference");
  rejects((value) => { makeReference(value, "SCHEMA_ID_MISSING"); }, "constants-enum-reference");
  rejects((value) => { makeReference(value); module(value).constants[0].unit = "UNIT_BYTES"; }, "constants-unit");
  rejects((value) => { makeReference(value); value.file[1].enumType[0].value[1].number = 65536; }, "constants-overflow");
  rejects((value) => { makeReference(value); value.file[1].enumType[0].options = { allowAlias: true }; }, "constants-enum-reference");
});
