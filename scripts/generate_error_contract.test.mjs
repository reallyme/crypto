// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ErrorContractGenerationError, parseErrorDescriptor, renderErrorContract, writeErrorContractOutput } from "./generate_error_contract.mjs";

const fixture = () => ({ file: [{
  name: "reallyme/crypto/v1/crypto.proto", package: "reallyme.crypto.v1", syntax: "proto3",
  enumType: [{ name: "CryptoErrorReason", value: [
    { name: "CRYPTO_ERROR_REASON_UNSPECIFIED", number: 0 },
    { name: "CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER", number: 100 },
    { name: "CRYPTO_ERROR_REASON_PROVIDER_RANDOMNESS_UNAVAILABLE", number: 203 },
    { name: "CRYPTO_ERROR_REASON_BACKEND_INTERNAL", number: 301 },
  ] }],
  messageType: [{ name: "CryptoError", oneofDecl: [{ name: "error" }],
    field: ["primitive", "provider", "backend"].map((name, index) => ({
      name, number: index + 1, label: "LABEL_OPTIONAL", type: "TYPE_MESSAGE", oneofIndex: 0,
      typeName: `.reallyme.crypto.v1.Crypto${name[0].toUpperCase()}${name.slice(1)}Error`,
    })),
  }, ...["Primitive", "Provider", "Backend"].map((name) => ({
    name: `Crypto${name}Error`, field: [{ name: "reason", number: 1, label: "LABEL_OPTIONAL",
      type: "TYPE_ENUM", typeName: ".reallyme.crypto.v1.CryptoErrorReason" }],
  }))],
}] });
const parse = (document) => parseErrorDescriptor(JSON.stringify(document));
const rejects = (mutate, code) => {
  const document = fixture(); mutate(document);
  assert.throws(() => parse(document), (error) =>
    error instanceof ErrorContractGenerationError && error.code === code);
};

test("descriptor generates one reason enum and a validated native error", () => {
  const contract = parse(fixture());
  assert.deepEqual(contract.reasons.map((reason) => reason.number), [0, 100, 203, 301]);
  assert.deepEqual(contract.branches.map((branch) => branch.name), ["primitive", "provider", "backend"]);
  const output = renderErrorContract(contract);
  assert.match(output, /pub enum CryptoErrorReason/u);
  assert.match(output, /pub struct CryptoError \{\n    reason: CryptoErrorReason,/u);
  assert.match(output, /pub const PRIMITIVE_INVALID_PARAMETER: Self/u);
  assert.match(output, /Err\(Self::PRIMITIVE_INVALID_PARAMETER\)/u);
  assert.doesNotMatch(output, /pub enum CryptoError\s*\{/u);
  const nativeDerive = output.match(/#\[derive\(([^\]]*)\)\]\n#\[error\("\{reason\}"\)\]\npub struct CryptoError/u);
  assert.ok(nativeDerive, "native error declaration must keep checked struct ownership");
  assert.doesNotMatch(nativeDerive[1], /Default|Deserialize/u);
  const native = output.slice(output.indexOf("pub struct CryptoError {"));
  const constants = [...native.matchAll(/pub const ([A-Z0-9_]+): Self = Self \{\s*reason: CryptoErrorReason::(CRYPTO_ERROR_REASON_[A-Z0-9_]+),\s*\};/gu)];
  assert.equal(constants.length, contract.reasons.filter((reason) => reason.number !== 0).length);
  for (const reason of contract.reasons.filter((value) => value.number !== 0)) {
    assert.equal(constants.filter((entry) => entry[1] === reason.suffix && entry[2] === reason.name).length, 1);
  }
  const nativeValues = native.match(/pub const VALUES: &\[Self\] = &\[([\s\S]*?)\];/u);
  assert.ok(nativeValues, "all native failure constants must be enumerable");
  const listed = [...nativeValues[1].matchAll(/Self::([A-Z0-9_]+),/gu)].map((entry) => entry[1]);
  assert.deepEqual(listed, constants.map((entry) => entry[1]));
  assert.equal(new Set(listed).size, listed.length);
  assert.doesNotMatch(output, /impl Default for CryptoError\s*\{/u);
  assert.doesNotMatch(output, /serde|buffa|crypto_core|crypto_hpke/u);
});

test("descriptor rejects ambiguous declarations, aliases and malformed numeric identity", () => {
  rejects((d) => d.file.push(d.file[0]), "descriptor-file");
  rejects((d) => d.file[0].enumType.push(d.file[0].enumType[0]), "descriptor-declaration");
  rejects((d) => d.file[0].enumType[0].value.push(d.file[0].enumType[0].value[1]), "descriptor-alias");
  rejects((d) => { d.file[0].enumType[0].value[1].number = -1; }, "descriptor-number");
  rejects((d) => { d.file[0].enumType[0].value[1].number = "100"; }, "descriptor-number");
  rejects((d) => { d.file[0].enumType[0].value[0].name = "CRYPTO_ERROR_REASON_PRIMITIVE_ZERO"; }, "descriptor-zero");
  rejects((d) => { d.file[0].enumType[0].value[0].number = 9; }, "descriptor-owner");
  rejects((d) => { d.file[0].enumType[0].options = { allowAlias: true }; }, "descriptor-alias");
  rejects((d) => { d.file[0].enumType[0].reservedName = ["CRYPTO_ERROR_REASON_PRIMITIVE_INVALID_PARAMETER"]; }, "descriptor-reserved");
  rejects((d) => { d.file[0].enumType[0].reservedRange = [{ start: 100, end: 100 }]; }, "descriptor-reserved");
});

test("descriptor rejects incorrect reason prefixes and oneof ownership", () => {
  rejects((d) => { d.file[0].enumType[0].value[1].name = "CRYPTO_ERROR_REASON_FOREIGN_INVALID_PARAMETER"; }, "descriptor-owner");
  rejects((d) => { d.file[0].enumType[0].value[1].name = "CRYPTO_ERROR_REASON_PRIMITIVE_UNAVAILABLE"; }, "descriptor-constructor-reason");
  rejects((d) => { d.file[0].messageType[0].field[0].oneofIndex = 1; }, "descriptor-branch");
  rejects((d) => { d.file[0].messageType[0].field[0].label = "LABEL_REPEATED"; }, "descriptor-branch");
  rejects((d) => { d.file[0].messageType[0].field[0].typeName = ".foreign.CryptoPrimitiveError"; }, "descriptor-branch");
  rejects((d) => { d.file[0].messageType[1].field[0].typeName = ".foreign.CryptoErrorReason"; }, "descriptor-branch");
  rejects((d) => { d.file[0].messageType[1].field.push(d.file[0].messageType[1].field[0]); }, "descriptor-branch");
});

test("input work is bounded before inspecting descriptor structures", () => {
  assert.throws(() => parseErrorDescriptor("x".repeat(4_194_305)),
    (error) => error instanceof ErrorContractGenerationError && error.code === "descriptor-size");
  assert.throws(() => parseErrorDescriptor("{"),
    (error) => error instanceof ErrorContractGenerationError && error.code === "descriptor-json");
  rejects((d) => { d.file[0].enumType[0].value = Array(1_025).fill({}); }, "descriptor-shape");
});

test("generation preserves timestamps and does not follow output symlinks", (context) => {
  const root = mkdtempSync(join(tmpdir(), "crypto-error-generation-"));
  context.after(() => rmSync(root, { recursive: true, force: true }));
  const output = join(root, "contract.rs");
  const source = renderErrorContract(parse(fixture()));
  writeErrorContractOutput(output, source);
  const past = new Date("2000-01-01T00:00:00Z");
  utimesSync(output, past, past);
  const before = statSync(output).mtimeMs;
  writeErrorContractOutput(output, source);
  assert.equal(statSync(output).mtimeMs, before);
  assert.equal(readFileSync(output, "utf8"), source);
  const target = join(root, "other.rs");
  writeFileSync(target, "untouched\n");
  const substituted = join(root, "substituted.rs");
  symlinkSync(target, substituted);
  assert.throws(() => writeErrorContractOutput(substituted, source),
    (error) => error instanceof ErrorContractGenerationError && error.code === "input-file");
  assert.equal(readFileSync(target, "utf8"), "untouched\n");
});
