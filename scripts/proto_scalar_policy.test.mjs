// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { classifyProtoScalars, ProtobufScalarPolicyError } from "./proto_scalar_policy.mjs";

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
