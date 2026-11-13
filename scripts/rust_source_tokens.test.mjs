// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import { ContractConstantsGenerationError } from "./generate_contract_constants.mjs";
import { rustSourceTokens } from "./rust_source_tokens.mjs";

const rejects = (source) => assert.throws(() => rustSourceTokens(source), (error) =>
  error instanceof ContractConstantsGenerationError && error.code === "hpke-source-lexical");

test("comments and every supported string form cannot manufacture code tokens", () => {
  const source = [
    "/* pub const COMMENT: u16 = 1; /* nested { [ */ */",
    '// pub const LINE_COMMENT: u16 = 2;',
    'const A: &str = "pub const STRING: u16 = 3; \\" quoted";',
    'const B: &str = r###"pub enum Raw { } \"## still raw"###;',
    'const C: &[u8] = b"pub const BYTES: u16 = 4;";',
    'const D: &[u8] = br##"pub const RAW_BYTES: u16 = 5;"##;',
    'pub const REAL: u16 = 6;',
  ].join("\n");
  const lexed = rustSourceTokens(source);
  assert.equal(lexed.tokens.filter((token) => token.kind === "identifier" && token.text === "pub").length, 1);
  assert.deepEqual(lexed.tokens.filter((token) => token.kind.endsWith("string")).map((token) => token.kind),
    ["string", "raw-string", "byte-string", "raw-byte-string"]);
  for (const token of lexed.tokens) assert.equal(source.slice(token.start, token.end), token.text);
});

test("character bytes and Unicode scalars remain distinct from borrowed lifetimes", () => {
  const source = "fn borrow<'a>(input: &'a [u8]) -> &'a [u8] { let brace = '{'; let letter = 'a'; let byte = b'K'; let unicode = '\\u{1f980}'; let quote = '\\''; input }";
  const lexed = rustSourceTokens(source);
  assert.equal(lexed.tokens.filter((token) => token.kind === "lifetime").length, 3);
  assert.deepEqual(lexed.tokens.filter((token) => token.kind.includes("character")).map((token) => token.text),
    ["'{'", "'a'", "b'K'", "'\\u{1f980}'", "'\\''"]);
  assert.equal(lexed.tokens.filter((token) => token.text === "{" && token.kind === "punctuation").length, 1);
  const literal = rustSourceTokens("'🦀' 'static '_ b'\\xff'");
  assert.deepEqual(literal.tokens.map((token) => token.kind), ["character", "lifetime", "lifetime", "byte-character"]);
});

test("balanced actual scopes are recorded independently of quoted delimiters", () => {
  const lexed = rustSourceTokens('mod nested { const TEXT: &str = "}]"; } pub enum Real { Value, }');
  const nestedConst = lexed.tokens.find((token) => token.text === "const");
  const realEnum = lexed.tokens.find((token) => token.text === "enum");
  assert.equal(nestedConst.depth, 1);
  assert.equal(realEnum.depth, 0);
  for (const token of lexed.tokens.filter((value) => value.pair !== undefined)) {
    assert.equal(lexed.tokens[token.pair].pair, lexed.tokens.indexOf(token));
  }
});

test("unterminated, ambiguous and unsupported lexical forms fail closed", () => {
  for (const source of ["/* missing", 'r##"missing"#', 'br#"missing', '"missing', "b'x", "'xy'",
    "'\\q'", '"\\q"', "b'🦀'", 'b"é"', 'br"é"', "'\\u{d800}'", "'\\u{110000}'", "b'\\u{41}'",
    "(]", "{", "}", 'c"unsupported"', 'cr#"unsupported"#', "'r#raw", "r#", "\u0000"]) rejects(source);
});

test("source, nesting, raw hashes and token work remain bounded", () => {
  rejects(" ".repeat(4_194_305));
  rejects("/*".repeat(65) + "*/".repeat(65));
  rejects("(".repeat(65) + ")".repeat(65));
  rejects(`r${"#".repeat(256)}"raw"${"#".repeat(256)}`);
  rejects("x ".repeat(250_001));
});
