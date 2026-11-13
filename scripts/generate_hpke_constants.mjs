// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { ContractConstantsGenerationError, resolveEnumReference } from "./generate_contract_constants.mjs";
import { rustSourceTokens } from "./rust_source_tokens.mjs";

const PACKAGE = "reallyme.crypto.contract.v1";
const SCHEMA = "reallyme/crypto/contract/v1/hpke.proto";
const OPTION = `[${PACKAGE}.hpke_registry]`;
const MAX_ITEMS = 4_096;
const MAX_SUITES = 256;
const MAX_DEPTH = 64;
const MAX_SOURCE_BYTES = 4_194_304;
const FAMILIES = new Map([
  ["kem", { enumType: ".reallyme.crypto.v1.HpkeKemId", nativeType: "HpkeKemId", registry: "HPKE_REGISTERED_KEMS" }],
  ["kdf", { enumType: ".reallyme.crypto.v1.HpkeKdfId", nativeType: "HpkeKdfId", registry: "HPKE_REGISTERED_KDFS" }],
  ["aead", { enumType: ".reallyme.crypto.v1.HpkeAeadId", nativeType: "HpkeAeadId", registry: "HPKE_REGISTERED_AEADS" }],
]);
const fail = (code) => { throw new ContractConstantsGenerationError(code); };
const record = (value) => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail("hpke-shape");
  return value;
};
const list = (value, maximum = MAX_ITEMS) => {
  if (!Array.isArray(value) || value.length === 0 || value.length > maximum) fail("hpke-shape");
  return value.map(record);
};
const keys = (value, allowed, required = allowed) => {
  record(value);
  if (Object.keys(value).some((key) => !allowed.includes(key)) || required.some((key) => !Object.hasOwn(value, key))) fail("hpke-fields");
};
const identifier = (value, variant = false) => {
  const pattern = variant ? /^[A-Z][A-Za-z0-9]*$/u : /^[A-Z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)*$/u;
  if (typeof value !== "string" || value.length > 128 || !pattern.test(value) || value === "Self") fail("hpke-identifier");
  return value;
};
const scalarName = (value) => {
  identifier(value);
  if (!/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/u.test(value)) fail("hpke-identifier");
  return value;
};
const named = (values, name) => {
  const matches = list(values).filter((value) => value.name === name);
  if (matches.length !== 1) fail("hpke-declaration");
  return matches[0];
};
const compare = (left, right) => left < right ? -1 : left > right ? 1 : 0;

function validateDefinitions(file) {
  if (file.package !== PACKAGE || (file.syntax !== undefined && file.syntax !== "proto2") ||
      list(file.messageType).length !== 6 || (Object.hasOwn(file, "enumType") &&
        (!Array.isArray(file.enumType) || file.enumType.length !== 0))) fail("hpke-schema");
  const message = (name) => `.${PACKAGE}.${name}`;
  const field = (name, number, type, extra = {}) => ({ name, number, type, ...extra });
  const shapes = new Map([
    ["HpkeNativeEnumValue", [field("schema_value", 1, "TYPE_STRING"), field("native_variant", 2, "TYPE_STRING"), field("native_constant", 3, "TYPE_STRING")]],
    ["HpkeNativeEnum", [field("enum_type", 1, "TYPE_STRING"), field("values", 2, "TYPE_MESSAGE", { typeName: message("HpkeNativeEnumValue"), repeated: true })]],
    ["HpkeSuiteComponents", [field("kem", 1, "TYPE_MESSAGE", { typeName: message("EnumValueReference") }), field("kdf", 2, "TYPE_MESSAGE", { typeName: message("EnumValueReference") }), field("aead", 3, "TYPE_MESSAGE", { typeName: message("EnumValueReference") })]],
    ["HpkeNamedSuite", [field("native_name", 1, "TYPE_STRING"), field("components", 2, "TYPE_MESSAGE", { typeName: message("HpkeSuiteComponents"), oneof: true }), field("alias_name", 3, "TYPE_STRING", { oneof: true })]],
    ["HpkeOrderedRegistry", [field("native_name", 1, "TYPE_STRING"), field("enum_type", 2, "TYPE_STRING"), field("members", 3, "TYPE_STRING", { repeated: true })]],
    ["HpkeConstantRegistry", [field("native_enums", 1, "TYPE_MESSAGE", { typeName: message("HpkeNativeEnum"), repeated: true }), field("suites", 2, "TYPE_MESSAGE", { typeName: message("HpkeNamedSuite"), repeated: true }), field("registries", 3, "TYPE_MESSAGE", { typeName: message("HpkeOrderedRegistry"), repeated: true })]],
  ]);
  for (const [name, expected] of shapes) {
    const definition = named(file.messageType, name);
    if (Object.hasOwn(definition, "nestedType") || Object.hasOwn(definition, "enumType") ||
        Object.hasOwn(definition, "extension")) fail("hpke-declaration");
    const fields = list(definition.field);
    if (fields.length !== expected.length) fail("hpke-field");
    const seen = new Set();
    for (const value of fields) {
      const shape = expected.find((entry) => entry.name === value.name);
      if (shape === undefined || seen.has(value.name) || value.number !== shape.number || value.type !== shape.type ||
          value.typeName !== shape.typeName || value.label !== (shape.repeated ? "LABEL_REPEATED" : "LABEL_OPTIONAL") ||
          Object.hasOwn(value, "defaultValue") || value.proto3Optional === true ||
          (shape.oneof ? value.oneofIndex !== 0 : Object.hasOwn(value, "oneofIndex"))) fail("hpke-field");
      seen.add(value.name);
    }
    if (name === "HpkeNamedSuite") {
      const oneofs = list(definition.oneofDecl, 1);
      if (oneofs.length !== 1 || oneofs[0].name !== "definition") fail("hpke-oneof");
    } else if (Object.hasOwn(definition, "oneofDecl")) fail("hpke-oneof");
  }
  const extensions = list(file.extension, 1);
  const extension = extensions[0];
  if (extensions.length !== 1 || extension.name !== "hpke_registry" || extension.extendee !== ".google.protobuf.FileOptions" ||
      extension.type !== "TYPE_MESSAGE" || extension.typeName !== message("HpkeConstantRegistry") || extension.label !== "LABEL_OPTIONAL" ||
      !Number.isSafeInteger(extension.number) || extension.number < 1000 || extension.number > 536_870_911 ||
      (extension.number >= 19_000 && extension.number <= 19_999)) fail("hpke-extension");
}

/** Read only registered facts; provider/backend availability stays runtime policy. */
export function parseHpkeConstantsDescriptor(document, constants) {
  const files = list(record(document).file, 128);
  const definitions = files.filter((file) => file.name === SCHEMA);
  if (definitions.length !== 1) fail("hpke-schema");
  validateDefinitions(definitions[0]);
  const registries = files.filter((file) => Object.hasOwn(record(file.options ?? {}), OPTION));
  if (registries.length !== 1) fail("hpke-registry-owner");
  const input = registries[0].options[OPTION];
  keys(input, ["nativeEnums", "suites", "registries"]);
  const module = constants.modules.find((value) => value.name === "hpke");
  if (module === undefined) fail("hpke-scalars");
  const scalar = new Map(module.constants.map((value) => [value.name, value]));
  const families = new Map();
  for (const raw of list(input.nativeEnums, 3)) {
    keys(raw, ["enumType", "values"]);
    const family = [...FAMILIES.values()].find((value) => value.enumType === raw.enumType);
    if (family === undefined || families.has(raw.enumType)) fail("hpke-family");
    const definition = constants.enums.get(raw.enumType);
    if (definition === undefined) fail("hpke-family");
    const schema = list(definition.value);
    const zero = schema.filter((value) => value.number === 0);
    if (zero.length !== 1 || !zero[0].name.endsWith("_UNSPECIFIED")) fail("hpke-family");
    const values = new Map();
    const variants = new Set();
    const names = new Set();
    for (const binding of list(raw.values)) {
      keys(binding, ["schemaValue", "nativeVariant", "nativeConstant"]);
      const reference = resolveEnumReference(constants.enums, { enumType: raw.enumType, valueName: binding.schemaValue });
      if (reference.number > 65_535) fail("hpke-family");
      const variant = identifier(binding.nativeVariant, true);
      const name = scalarName(binding.nativeConstant);
      const constant = scalar.get(name);
      if (values.has(reference.valueName) || variants.has(variant) || names.has(name)) fail("hpke-duplicate");
      if (constant?.type !== "u16" || constant.unit !== "UNIT_IDENTIFIER" ||
          constant.enumReference?.enumType !== raw.enumType || constant.enumReference.valueName !== reference.valueName ||
          constant.value !== String(reference.number)) fail("hpke-scalar-binding");
      variants.add(variant); names.add(name);
      values.set(reference.valueName, { ...reference, variant, constant: name });
    }
    if (values.size !== schema.filter((value) => value.number !== 0).length ||
        schema.some((value) => value.number !== 0 && !values.has(value.name))) fail("hpke-incomplete");
    families.set(raw.enumType, { ...family, values });
  }
  if (families.size !== FAMILIES.size) fail("hpke-incomplete");
  const names = new Set();
  const suites = new Map();
  const triples = new Set();
  for (const raw of list(input.suites, MAX_SUITES)) {
    keys(raw, ["nativeName", "components", "aliasName"], ["nativeName"]);
    const name = identifier(raw.nativeName);
    if (names.has(name) || scalar.has(name) || Object.hasOwn(raw, "components") === Object.hasOwn(raw, "aliasName")) fail("hpke-suite");
    names.add(name);
    if (Object.hasOwn(raw, "aliasName")) {
      suites.set(name, { name, alias: identifier(raw.aliasName) });
      continue;
    }
    keys(raw.components, ["kem", "kdf", "aead"]);
    const components = {};
    for (const [key, expected] of FAMILIES) {
      const reference = resolveEnumReference(constants.enums, raw.components[key]);
      if (reference.enumType !== expected.enumType) fail("hpke-component-family");
      components[key] = families.get(reference.enumType).values.get(reference.valueName);
    }
    const triple = [...FAMILIES.keys()].map((key) => components[key].valueName).join(":");
    if (triples.has(triple)) fail("hpke-suite-duplicate");
    triples.add(triple);
    suites.set(name, { name, components });
  }
  const states = new Map();
  const resolve = (suite, depth) => {
    if (depth > MAX_DEPTH) fail("hpke-complexity");
    if (states.get(suite.name) === "done") return;
    if (states.get(suite.name) === "visiting") fail("hpke-alias-cycle");
    states.set(suite.name, "visiting");
    if (suite.alias !== undefined) {
      const target = suites.get(suite.alias);
      if (target === undefined) fail("hpke-alias");
      resolve(target, depth + 1);
      suite.components = target.components;
    }
    states.set(suite.name, "done");
  };
  for (const suite of suites.values()) resolve(suite, 0);
  const ordered = [];
  const registryFamilies = new Set();
  for (const raw of list(input.registries, 3)) {
    keys(raw, ["nativeName", "enumType", "members"]);
    const family = families.get(raw.enumType);
    const name = identifier(raw.nativeName);
    if (family === undefined || family.registry !== name || names.has(name) || registryFamilies.has(raw.enumType)) fail("hpke-registry");
    if (!Array.isArray(raw.members) || raw.members.length === 0 || raw.members.length > MAX_ITEMS) fail("hpke-shape");
    const seen = new Set();
    const members = raw.members.map((member) => {
      const value = family.values.get(member);
      if (value === undefined || seen.has(member)) fail("hpke-registry-member");
      seen.add(member);
      return value;
    });
    if (members.length !== family.values.size) fail("hpke-incomplete");
    names.add(name); registryFamilies.add(raw.enumType);
    ordered.push({ name, nativeType: family.nativeType, members });
  }
  if (registryFamilies.size !== FAMILIES.size) fail("hpke-incomplete");
  return { families, suites: [...suites.values()].sort((left, right) => compare(left.name, right.name)),
    registries: ordered.sort((left, right) => compare(left.name, right.name)), scalarModules: constants.modules };
}

const lexSource = (source) => {
  if (typeof source !== "string" || Buffer.byteLength(source) > MAX_SOURCE_BYTES) fail("hpke-source-size");
  return rustSourceTokens(source);
};
const tokenText = (lexed, token) => lexed.source.slice(token.start, token.end);
const sameTokens = (lexed, tokens, expected) => tokens.length === expected.length &&
  tokens.every((token, index) => token.kind === expected[index].kind &&
    tokenText(lexed, token) === expected[index].text);
const expectedTokens = (source) => rustSourceTokens(source).tokens;
const rootItems = (lexed, keyword, name) => lexed.tokens.flatMap((token, index) =>
  token.depth === 0 && token.kind === "identifier" && token.text === keyword &&
  (name === undefined || lexed.tokens[index + 1]?.text === name) ? [index] : []);

// Read complete root const declarations, including unfamiliar types. Ignoring a
// declaration solely because its type no longer matched would hide divergence.
function nativeConstants(lexed, code) {
  const result = [];
  for (const index of rootItems(lexed, "const")) {
    const tokens = lexed.tokens;
    if (tokens[index + 1]?.text === "fn") continue;
    const name = tokens[index + 1];
    if (name?.kind !== "identifier" || name.text.startsWith("r#") || tokens[index + 2]?.text !== ":") fail(code);
    let equals = index + 3;
    while (equals < tokens.length && !(tokens[equals].depth === 0 && tokens[equals].text === "=")) {
      if (tokens[equals].depth === 0 && [";", "const", "fn", "pub", "mod", "enum"].includes(tokens[equals].text)) fail(code);
      equals += 1;
    }
    let end = equals + 1;
    while (end < tokens.length && !(tokens[end].depth === 0 && tokens[end].text === ";")) {
      if (tokens[end].depth === 0 && ["const", "fn", "pub", "mod", "enum", "use", "struct", "trait", "impl"].includes(tokens[end].text)) fail(code);
      end += 1;
    }
    if (equals >= tokens.length || end >= tokens.length || equals === index + 3 || end === equals + 1) fail(code);
    const previous = tokens[index - 1];
    const restricted = previous?.text === ")" && previous.pair !== undefined &&
      tokens[previous.pair - 1]?.text === "pub" && tokens[previous.pair - 1]?.depth === 0;
    const visibility = previous?.text === "pub" && previous.depth === 0 ? "public" : restricted ? "restricted" : "private";
    result.push({ name: name.text, visibility,
      type: tokens.slice(index + 3, equals), expression: tokens.slice(equals + 1, end) });
  }
  return result;
}

/** Accept real root declarations only; comments/literal contents have no authority. */
export function validateHpkeNativeSources(contract, sources) {
  keys(sources, ["identifiers", "constants", "baseP256"]);
  const lexed = Object.fromEntries(Object.entries(sources).map(([key, value]) => [key, lexSource(value)]));
  const identifiers = lexed.identifiers;
  for (const family of contract.families.values()) {
    const matches = rootItems(identifiers, "enum", family.nativeType);
    if (matches.length !== 1) fail("hpke-source-enum");
    const index = matches[0];
    const tokens = identifiers.tokens;
    const opening = tokens[index + 2];
    const representation = expectedTokens("#[repr(u16)]");
    const attributeStart = index - 1 - representation.length;
    if (attributeStart < 0 || tokens[index - 1]?.text !== "pub" || opening?.text !== "{" || opening.pair === undefined ||
        !sameTokens(identifiers, tokens.slice(attributeStart, index - 1), representation)) fail("hpke-source-enum");
    const body = tokens.slice(index + 3, opening.pair);
    const observed = new Map();
    for (let offset = 0; offset < body.length; offset += 4) {
      const [variant, equals, constant, comma] = body.slice(offset, offset + 4);
      if (variant?.kind !== "identifier" || constant?.kind !== "identifier" || equals?.text !== "=" || comma?.text !== "," ||
          !/^[A-Z][A-Za-z0-9]*$/u.test(variant.text) || !/^[A-Z][A-Z0-9_]*$/u.test(constant.text) || observed.has(variant.text)) fail("hpke-source-enum");
      observed.set(variant.text, constant.text);
    }
    if (observed.size !== family.values.size || [...family.values.values()].some((value) => observed.get(value.variant) !== value.constant)) fail("hpke-source-enum");
  }
  for (const [key, moduleName] of [["constants", "hpke"], ["baseP256", "hpke_base_p256"]]) {
    const module = contract.scalarModules.find((value) => value.name === moduleName);
    if (module === undefined) fail("hpke-scalars");
    const constants = new Map(module.constants.map((value) => [value.name, value]));
    const declarations = nativeConstants(lexed[key], "hpke-source-scalar").filter((value) => value.visibility === "public");
    const seen = new Set();
    for (const value of declarations) {
      const constant = constants.get(value.name);
      if (seen.has(value.name) || constant === undefined ||
          !sameTokens(lexed[key], value.type, expectedTokens(constant.type)) ||
          !sameTokens(lexed[key], value.expression, expectedTokens(`crypto_core::contract_constants::${moduleName}::${value.name}`))) fail("hpke-source-scalar");
      seen.add(value.name);
    }
    if (seen.size !== constants.size) fail("hpke-source-scalar");
  }
  const modules = rootItems(identifiers, "mod", "contract_constants");
  const moduleExpected = expectedTokens('#[path = "generated/hpke_contract_constants.rs"] mod contract_constants;');
  const moduleStart = modules[0] - moduleExpected.findIndex((token) => token.text === "mod");
  if (modules.length !== 1 || moduleStart < 0 || !sameTokens(identifiers,
    identifiers.tokens.slice(moduleStart, moduleStart + moduleExpected.length), moduleExpected)) fail("hpke-source-owner");
  const declarations = nativeConstants(identifiers, "hpke-source-owner");
  const publicItems = rootItems(identifiers, "pub");
  for (const value of [...contract.suites, ...contract.registries]) {
    const expected = expectedTokens(`pub use contract_constants::${value.name};`);
    const exports = publicItems.filter((index) =>
      sameTokens(identifiers, identifiers.tokens.slice(index, index + expected.length), expected));
    if (exports.length !== 1 || declarations.some((constant) => constant.name === value.name)) fail("hpke-source-owner");
  }
}

/** Backend labels retain exact literal bytes from actual declaration spans. */
export function validateHpkeBackendSources(constantsSource, sources) {
  const bindings = new Map([
    ["mlkem512", "HPKE_KEM_ML_KEM_512"], ["mlkem1024p384", "HPKE_KEM_ML_KEM_1024_P384"],
    ["secp256k1", "HPKE_KEM_DHKEM_SECP256K1_HKDF_SHA256"], ["x448", "HPKE_KEM_DHKEM_X448_HKDF_SHA512"],
  ]);
  keys(sources, [...bindings.keys()]);
  const constants = lexSource(constantsSource);
  const functions = rootItems(constants, "fn", "encode_kem_suite_id");
  const expected = expectedTokens("pub(crate) const fn encode_kem_suite_id(kem_id: u16) -> [u8; 5] { let [high, low] = kem_id.to_be_bytes(); [b'K', b'E', b'M', high, low] }");
  if (functions.length !== 1) fail("hpke-source-context");
  const start = functions[0] - expected.findIndex((token) => token.text === "fn");
  const opening = constants.tokens.findIndex((token, index) => index > functions[0] && token.depth === 0 && token.text === "{");
  const brace = constants.tokens[opening];
  if (start < 0 || brace?.text !== "{" || brace.pair === undefined ||
      !sameTokens(constants, constants.tokens.slice(start, brace.pair + 1), expected)) fail("hpke-source-context");
  for (const [key, name] of bindings) {
    const lexed = lexSource(sources[key]);
    const declarations = nativeConstants(lexed, "hpke-source-context");
    const ids = declarations.filter((value) => value.name === "KEM_ID");
    const labels = declarations.filter((value) => value.name === "KEM_SUITE_ID");
    if (ids.length !== 1 || labels.length !== 1 || ids[0].visibility !== "private" || labels[0].visibility !== "private" ||
        !sameTokens(lexed, ids[0].type, expectedTokens("u16")) ||
        !sameTokens(lexed, ids[0].expression, expectedTokens(`crate::constants::${name}`)) ||
        !sameTokens(lexed, labels[0].type, expectedTokens("&[u8]")) ||
        !sameTokens(lexed, labels[0].expression, expectedTokens("&crate::constants::encode_kem_suite_id(KEM_ID)"))) fail("hpke-source-context");
  }
}

/** Generate owner-local native types; scalar IDs remain minimal-codec aliases. */
export function renderHpkeConstants(contract) {
  const lines = ["// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited", "//",
    "// SPDX-License-Identifier: MIT OR Apache-2.0", "",
    "// Generated from schema metadata. Regenerate with scripts/generate_error_contract.mjs.", "",
    "use super::{HpkeAeadId, HpkeKdfId, HpkeKemId, HpkeSuite};", ""];
  for (const suite of contract.suites) {
    lines.push("/// Schema-owned HPKE component triple; availability is provider policy.");
    if (suite.name !== suite.name.toUpperCase()) lines.push("#[allow(non_upper_case_globals)]");
    if (suite.alias !== undefined) lines.push(`pub const ${suite.name}: HpkeSuite = ${suite.alias};`);
    else lines.push(`pub const ${suite.name}: HpkeSuite = HpkeSuite::new(`,
      `    HpkeKemId::${suite.components.kem.variant},`, `    HpkeKdfId::${suite.components.kdf.variant},`,
      `    HpkeAeadId::${suite.components.aead.variant},`, ");");
    lines.push("");
  }
  for (const registry of contract.registries) {
    lines.push("/// Registered schema identities in the reviewed order.",
      `pub const ${registry.name}: [${registry.nativeType}; ${registry.members.length}] = [`,
      ...registry.members.map((value) => `    ${registry.nativeType}::${value.variant},`), "];", "");
  }
  return lines.join("\n");
}
