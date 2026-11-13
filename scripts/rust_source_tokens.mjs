// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// This lexer recognizes bounded Rust tokens without evaluating Rust or macros.
// Literal contents and comments never become declaration tokens. Original
// UTF-16 source spans remain available for exact reviewed literal comparisons.
import { ContractConstantsGenerationError } from "./generate_contract_constants.mjs";

const MAX_SOURCE_BYTES = 4_194_304;
const MAX_TOKENS = 250_000;
const MAX_NESTING = 64;
const MAX_RAW_HASHES = 255;
const OPEN = new Map([["(", ")"], ["[", "]"], ["{", "}"]]);
const CLOSE = new Set(OPEN.values());
const IDENTIFIER_START = /[\p{ID_Start}_]/u;
const IDENTIFIER_CONTINUE = /[\p{ID_Continue}_]/u;
const WHITESPACE = /[\t\n\v\f\r \u0085\u200e\u200f\u2028\u2029]/u;
const SIMPLE_ESCAPES = new Set(["n", "r", "t", "0", "\\", "\"", "'"]);
const PUNCTUATION = new Set("#;:,.=+-*/%&|^!<>?@$~".split(""));
const JOINT = new Set(["::", "->", "=>", "..", "==", "!=", "<=", ">=", "&&", "||",
  "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^="]);
const fail = () => { throw new ContractConstantsGenerationError("hpke-source-lexical"); };

const scalar = (source, offset) => {
  const value = source.codePointAt(offset);
  if (value === undefined || (value >= 0xd800 && value <= 0xdfff) || value === 0) fail();
  return String.fromCodePoint(value);
};
const identifierEnd = (source, start) => {
  let end = start;
  while (end < source.length) {
    const value = scalar(source, end);
    if (!IDENTIFIER_CONTINUE.test(value)) break;
    end += value.length;
  }
  return end;
};

// Return the first position after exactly one supported Rust escape. A string
// continuation can consume whitespace; character literals cannot contain one.
function escapeEnd(source, start, bytes, continuation) {
  const value = source[start + 1];
  if (value === undefined) fail();
  if (SIMPLE_ESCAPES.has(value)) return start + 2;
  if (value === "x") {
    const digits = source.slice(start + 2, start + 4);
    if (!/^[0-9a-fA-F]{2}$/u.test(digits) || (!bytes && Number.parseInt(digits, 16) > 127)) fail();
    return start + 4;
  }
  if (value === "u" && !bytes && source[start + 2] === "{") {
    const closing = source.indexOf("}", start + 3);
    if (closing < 0 || closing - start > 16) fail();
    const digits = source.slice(start + 3, closing);
    const compact = digits.replaceAll("_", "");
    if (!/^[0-9a-fA-F_]+$/u.test(digits) || compact.length === 0 || compact.length > 6) fail();
    const point = Number.parseInt(compact, 16);
    if (point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) fail();
    return closing + 1;
  }
  if (continuation && (value === "\n" || (value === "\r" && source[start + 2] === "\n"))) {
    let end = start + (value === "\r" ? 3 : 2);
    while (end < source.length && WHITESPACE.test(source[end])) end += 1;
    return end;
  }
  fail();
}

function quotedEnd(source, quote, bytes) {
  let end = quote + 1;
  while (end < source.length) {
    if (source[end] === "\"") return end + 1;
    if (source[end] === "\\") { end = escapeEnd(source, end, bytes, true); continue; }
    const value = scalar(source, end);
    if ((bytes && value.codePointAt(0) > 127) || (value === "\r" && source[end + 1] !== "\n")) fail();
    end += value.length;
  }
  fail();
}

function characterEnd(source, quote, bytes) {
  const content = quote + 1;
  if (content >= source.length) fail();
  let end;
  if (source[content] === "\\") end = escapeEnd(source, content, bytes, false);
  else {
    const value = scalar(source, content);
    if (value === "'" || value === "\n" || value === "\r" || (bytes && value.codePointAt(0) > 127)) fail();
    end = content + value.length;
  }
  if (source[end] !== "'") fail();
  return end + 1;
}

function rawEnd(source, start, prefix) {
  let quote = start + prefix;
  while (source[quote] === "#") {
    quote += 1;
    if (quote - start - prefix > MAX_RAW_HASHES) fail();
  }
  if (source[quote] !== "\"") return undefined;
  const hashes = quote - start - prefix;
  const closing = source.indexOf(`\"${"#".repeat(hashes)}`, quote + 1);
  if (closing < 0) fail();
  let position = quote + 1;
  while (position < closing) {
    const value = scalar(source, position);
    if ((prefix === 2 && value.codePointAt(0) > 127) || (value === "\r" && source[position + 1] !== "\n")) fail();
    position += value.length;
  }
  return closing + 1 + hashes;
}

/** Tokenize actual code only, retaining spans and balanced delimiter partners. */
export function rustSourceTokens(source) {
  if (typeof source !== "string" || Buffer.byteLength(source) > MAX_SOURCE_BYTES) fail();
  const tokens = [];
  const stack = [];
  const emit = (kind, start, end) => {
    if (tokens.length >= MAX_TOKENS) fail();
    const text = source.slice(start, end);
    const token = { kind, text, start, end, depth: stack.length, pair: undefined };
    const index = tokens.length;
    if (kind === "punctuation" && OPEN.has(text)) {
      if (stack.length >= MAX_NESTING) fail();
      stack.push({ closing: OPEN.get(text), index });
    } else if (kind === "punctuation" && CLOSE.has(text)) {
      const opening = stack.pop();
      if (opening === undefined || opening.closing !== text) fail();
      token.pair = opening.index;
      tokens[opening.index].pair = index;
    }
    tokens.push(token);
  };
  let offset = source.startsWith("\ufeff") ? 1 : 0;
  while (offset < source.length) {
    if (WHITESPACE.test(source[offset])) { offset += 1; continue; }
    const start = offset;
    if (source.startsWith("//", offset)) {
      const newline = source.indexOf("\n", offset + 2);
      offset = newline < 0 ? source.length : newline;
      continue;
    }
    if (source.startsWith("/*", offset)) {
      offset += 2;
      let depth = 1;
      while (offset < source.length && depth > 0) {
        if (source.startsWith("/*", offset)) {
          depth += 1; if (depth > MAX_NESTING) fail(); offset += 2;
        } else if (source.startsWith("*/", offset)) { depth -= 1; offset += 2; }
        else offset += 1;
      }
      if (depth !== 0) fail();
      continue;
    }
    const rawPrefix = source.startsWith("br", offset) ? 2 : source[offset] === "r" ? 1 : 0;
    if (rawPrefix !== 0) {
      const end = rawEnd(source, offset, rawPrefix);
      if (end !== undefined) { emit(rawPrefix === 2 ? "raw-byte-string" : "raw-string", start, end); offset = end; continue; }
    }
    if (source[offset] === "c" && (source.startsWith("c\"", offset) ||
        /^cr#*"/u.test(source.slice(offset, offset + MAX_RAW_HASHES + 4)))) fail();
    const bytes = source.startsWith("b\"", offset) || source.startsWith("b'", offset);
    const quote = bytes ? offset + 1 : offset;
    if (source[quote] === "\"") {
      offset = quotedEnd(source, quote, bytes); emit(bytes ? "byte-string" : "string", start, offset); continue;
    }
    if (source[quote] === "'") {
      const next = quote + 1;
      if (!bytes && next < source.length && IDENTIFIER_START.test(scalar(source, next))) {
        const end = identifierEnd(source, next);
        if (source[end] !== "'") {
          if (source[end] === "#") fail(); // Raw lifetime syntax is outside this closed grammar.
          offset = end; emit("lifetime", start, offset); continue;
        }
      }
      offset = characterEnd(source, quote, bytes); emit(bytes ? "byte-character" : "character", start, offset); continue;
    }
    const value = scalar(source, offset);
    if (IDENTIFIER_START.test(value)) {
      const raw = source.startsWith("r#", offset);
      const identifierStart = raw ? offset + 2 : offset;
      if (identifierStart >= source.length || !IDENTIFIER_START.test(scalar(source, identifierStart))) fail();
      offset = identifierEnd(source, identifierStart); emit("identifier", start, offset); continue;
    }
    if (/[0-9]/u.test(value)) {
      offset += 1;
      while (offset < source.length && /[A-Za-z0-9_]/u.test(source[offset])) offset += 1;
      emit("number", start, offset); continue;
    }
    if (OPEN.has(value) || CLOSE.has(value) || PUNCTUATION.has(value)) {
      const joint = source.slice(offset, offset + 2);
      offset += JOINT.has(joint) ? 2 : 1;
      emit("punctuation", start, offset); continue;
    }
    fail();
  }
  if (stack.length !== 0) fail();
  return { source, tokens };
}
