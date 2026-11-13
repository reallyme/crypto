// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { classifyProtoScalars, projectLegacyScalarChecks, ProtobufScalarPolicyError } from "./proto_scalar_policy.mjs";

test("new byte, optional, repeated and oneof fields always require clearing owners", () => {
  const result = classifyProtoScalars('message Request { optional bytes kid = 1; repeated bytes keys = 2; oneof input { bytes message = 3; } }');
  assert.deepEqual(result.map((value) => [value.field, value.sensitivity]),
    [["kid", "sensitive"], ["keys", "sensitive"], ["message", "sensitive"]]);
});

test("quoted text and comments do not create fields or hide real message braces", () => {
  const result = classifyProtoScalars('/* message Fake { bytes secret = 1; } */\nmessage Request { option text = "} bytes ignored = 1;"; // bytes fake = 2;\n bytes real = 1; }');
  assert.deepEqual(result, [{ message: "Request", field: "real", kind: "bytes", optional: false, sensitivity: "sensitive" }]);
});

test("only fixed provider-name strings have a public diagnostic classification", () => {
  assert.deepEqual(classifyProtoScalars('message CryptoProviderCapability { repeated string provider_names = 1; string caller_text = 2; }')
    .map((value) => value.sensitivity), ["public", "sensitive"]);
});

test("unsupported and ambiguous schema shapes fail with fixed typed diagnostics", () => {
  for (const [source, code] of [
    ['message A { message B { bytes value = 1; } }', "nested-message"],
    ['message A { map<string, bytes> entries = 1; }', "scalar-map"],
    ['message A { bytes value = 1;', "unterminated-message"],
    ['message A { bytes value = 1; } /*', "unterminated-literal"],
    ['message A { bytes value = 1; } message A { bytes other = 1; }', "duplicate-message"],
    ['message A { bytes value = 1; bytes value = 2; }', "duplicate-field"],
    ['message A {}', "empty-policy"],
    [' '.repeat(1_048_577), "schema-size"],
  ]) {
    assert.throws(() => classifyProtoScalars(source), (error) =>
      error instanceof ProtobufScalarPolicyError && error.code === code && error.message === "protobuf scalar policy is invalid");
  }
});


test("optional compatibility projection requires real clearing owners before legacy shape checks", () => {
  const source = readFileSync(new URL("../crates/proto/proto/reallyme/crypto/v1/crypto.proto", import.meta.url), "utf8");
  const generated = readFileSync(new URL("../crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.rs", import.meta.url), "utf8");
  const actual = classifyProtoScalars(source);
  const projection = projectLegacyScalarChecks(source, generated);
  assert.equal(projection.length, actual.length);
  for (let index = 0; index < actual.length; index += 1) {
    assert.equal(projection[index].sensitivity,
      actual[index].optional ? "public" : actual[index].sensitivity);
    if (actual[index].optional) assert.equal(actual[index].sensitivity, "sensitive");
  }
  const drop = "impl ::core::ops::Drop for CryptoJwkOptions";
  assert.ok(generated.includes(drop));
  assert.throws(() => projectLegacyScalarChecks(source,
    generated.replace(drop, "impl ::core::ops::Drop for UnrelatedOwner")),
  (error) => error instanceof ProtobufScalarPolicyError && error.code === "optional-owner");
});


test("optional projection independently requires Drop, clear and setter cleanup", () => {
  const source = readFileSync(new URL("../crates/proto/proto/reallyme/crypto/v1/crypto.proto", import.meta.url), "utf8");
  const generated = readFileSync(new URL("../crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.rs", import.meta.url), "utf8");
  const wipe = "::zeroize::Zeroize::zeroize(&mut self.kid);";
  for (const marker of [
    "impl ::core::ops::Drop for CryptoJwkOptions",
    "pub fn with_kid(",
    "fn clear(&mut self) {",
  ]) {
    const owner = generated.indexOf("pub struct CryptoJwkOptions {");
    const start = generated.indexOf(marker, owner);
    assert.ok(start >= owner);
    const index = generated.indexOf(wipe, start);
    assert.ok(index > start);
    const mutated = generated.slice(0, index) + generated.slice(index + wipe.length);
    assert.throws(() => projectLegacyScalarChecks(source, mutated), (error) =>
      error instanceof ProtobufScalarPolicyError && error.code === "optional-owner");
  }
});

test("optional projection rejects unguarded or reordered transfer and merge paths", () => {
  const source = readFileSync(new URL("../crates/proto/proto/reallyme/crypto/v1/crypto.proto", import.meta.url), "utf8");
  const generated = readFileSync(new URL("../crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.rs", import.meta.url), "utf8");
  const owner = generated.indexOf("pub struct CryptoJwkOptions {");
  const setter = generated.indexOf("pub fn with_kid(", owner);
  const wipe = "::zeroize::Zeroize::zeroize(&mut self.kid);";
  const transfer = "self.kid = Some(::core::mem::take(&mut *value));";
  const replacement = wipe + "\n        " + transfer;
  const sourceVariants = [
    [setter, "::zeroize::Zeroizing::new(value.into())", "::zeroize::Zeroizing::new(Vec::new())"],
    [setter, replacement, transfer + "\n        " + wipe],
    [owner, "self.kid.get_or_insert_with(::buffa::alloc::vec::Vec::new)", "self.kid.get_or_insert_with(Vec::new)"],
    [owner, 'deserialize_with = "deserialize_optional_zeroizing_bytes"', 'with = "::buffa::json_helpers::opt_bytes"'],
    [owner, "let mut wire = Wire::deserialize(deserializer)?;", "let mut wire = Wire::default();"],
  ];
  for (const [start, before, after] of sourceVariants) {
    assert.ok(start >= owner);
    const index = generated.indexOf(before, start);
    assert.ok(index > start);
    const mutated = generated.slice(0, index) + after + generated.slice(index + before.length);
    assert.throws(() => projectLegacyScalarChecks(source, mutated), (error) =>
      error instanceof ProtobufScalarPolicyError && error.code === "optional-owner");
  }
});
