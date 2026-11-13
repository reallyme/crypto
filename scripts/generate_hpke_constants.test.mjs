// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { ContractConstantsGenerationError } from "./generate_contract_constants.mjs";
import { parseHpkeConstantsDescriptor, renderHpkeConstants, validateHpkeNativeSources,
  validateHpkeBackendSources } from "./generate_hpke_constants.mjs";

const PACKAGE = "reallyme.crypto.contract.v1";
const OPTION = `[${PACKAGE}.hpke_registry]`;
const type = (name) => `.${PACKAGE}.${name}`;
const field = (name, number, type, extra = {}) => ({ name, number, type, label: "LABEL_OPTIONAL", ...extra });
const message = (name, fields, extra = {}) => ({ name, field: fields, ...extra });
const enumType = (family) => `.reallyme.crypto.v1.Hpke${family}Id`;
const fixture = () => {
  const file = { name: "reallyme/crypto/contract/v1/hpke.proto", package: PACKAGE, messageType: [
    message("HpkeNativeEnumValue", [field("schema_value", 1, "TYPE_STRING"), field("native_variant", 2, "TYPE_STRING"), field("native_constant", 3, "TYPE_STRING")]),
    message("HpkeNativeEnum", [field("enum_type", 1, "TYPE_STRING"), field("values", 2, "TYPE_MESSAGE", { typeName: type("HpkeNativeEnumValue"), label: "LABEL_REPEATED" })]),
    message("HpkeSuiteComponents", ["kem", "kdf", "aead"].map((name, index) => field(name, index + 1, "TYPE_MESSAGE", { typeName: type("EnumValueReference") }))),
    message("HpkeNamedSuite", [field("native_name", 1, "TYPE_STRING"), field("components", 2, "TYPE_MESSAGE", { typeName: type("HpkeSuiteComponents"), oneofIndex: 0 }), field("alias_name", 3, "TYPE_STRING", { oneofIndex: 0 })], { oneofDecl: [{ name: "definition" }] }),
    message("HpkeOrderedRegistry", [field("native_name", 1, "TYPE_STRING"), field("enum_type", 2, "TYPE_STRING"), field("members", 3, "TYPE_STRING", { label: "LABEL_REPEATED" })]),
    message("HpkeConstantRegistry", [["native_enums", "HpkeNativeEnum"], ["suites", "HpkeNamedSuite"], ["registries", "HpkeOrderedRegistry"]].map(([name, target], index) => field(name, index + 1, "TYPE_MESSAGE", { typeName: type(target), label: "LABEL_REPEATED" }))),
  ], extension: [{ name: "hpke_registry", number: 51002, extendee: ".google.protobuf.FileOptions", type: "TYPE_MESSAGE", typeName: type("HpkeConstantRegistry"), label: "LABEL_OPTIONAL" }] };
  const enums = new Map();
  const constants = [];
  const nativeEnums = [];
  const components = {};
  const registries = [];
  for (const [family, variant, value] of [["Kem", "DhKemExample", 16], ["Kdf", "HkdfExample", 1], ["Aead", "AesExample", 1]]) {
    const upper = family.toUpperCase();
    const schemaValue = `HPKE_${upper}_ID_EXAMPLE`;
    const nativeConstant = `HPKE_${upper}_EXAMPLE`;
    const definition = { name: `Hpke${family}Id`, value: [{ name: `HPKE_${upper}_ID_UNSPECIFIED`, number: 0 }, { name: schemaValue, number: value }] };
    enums.set(enumType(family), definition);
    const reference = { enumType: enumType(family), valueName: schemaValue, number: value };
    constants.push({ name: nativeConstant, type: "u16", unit: "UNIT_IDENTIFIER", value: String(value), enumReference: reference });
    nativeEnums.push({ enumType: enumType(family), values: [{ schemaValue, nativeVariant: variant, nativeConstant }] });
    components[family.toLowerCase()] = { enumType: enumType(family), valueName: schemaValue };
    registries.push({ nativeName: `HPKE_REGISTERED_${upper === "KEM" ? "KEMS" : upper === "KDF" ? "KDFS" : "AEADS"}`, enumType: enumType(family), members: [schemaValue] });
  }
  const registry = { nativeEnums, suites: [{ nativeName: "EXAMPLE_SUITE", components }, { nativeName: "EXAMPLE_ALIAS", aliasName: "EXAMPLE_SUITE" }], registries };
  const document = { file: [file, { name: "reallyme/crypto/contract/v1/hpke_constants.proto", package: PACKAGE, options: { [OPTION]: registry } }] };
  const model = { enums, modules: [{ name: "hpke", constants }, { name: "hpke_base_p256", constants: [{ name: "LIMIT", type: "usize", unit: "UNIT_BYTES", value: "4" }] }] };
  return { document, model, registry };
};
const parse = (fixture) => parseHpkeConstantsDescriptor(fixture.document, fixture.model);
const rejects = (mutate, code) => {
  const value = fixture(); mutate(value);
  assert.throws(() => parse(value), (error) => error instanceof ContractConstantsGenerationError && error.code === code);
};
const sources = () => ({
  identifiers: `#[path = "generated/hpke_contract_constants.rs"]\nmod contract_constants;\n` +
    ["Kem", "Kdf", "Aead"].map((family) => `#[repr(u16)]\npub enum Hpke${family}Id {\n    ${family === "Kem" ? "DhKemExample" : family === "Kdf" ? "HkdfExample" : "AesExample"} = HPKE_${family.toUpperCase()}_EXAMPLE,\n}\n`).join("") +
    ["EXAMPLE_SUITE", "EXAMPLE_ALIAS", "HPKE_REGISTERED_KEMS", "HPKE_REGISTERED_KDFS", "HPKE_REGISTERED_AEADS"].map((name) => `pub use contract_constants::${name};\n`).join(""),
  constants: ["KEM", "KDF", "AEAD"].map((family) => `pub const HPKE_${family}_EXAMPLE: u16 = crypto_core::contract_constants::hpke::HPKE_${family}_EXAMPLE;\n`).join(""),
  baseP256: "pub const LIMIT: usize = crypto_core::contract_constants::hpke_base_p256::LIMIT;\n",
});

test("HPKE tuples, aliases and native registry arrays are generated from descriptor facts", () => {
  const contract = parse(fixture());
  validateHpkeNativeSources(contract, sources());
  const rust = renderHpkeConstants(contract);
  assert.match(rust, /pub const EXAMPLE_ALIAS: HpkeSuite = EXAMPLE_SUITE;/u);
  assert.match(rust, /HpkeKemId::DhKemExample/u);
  assert.match(rust, /HPKE_REGISTERED_KEMS: \[HpkeKemId; 1\]/u);
  assert.doesNotMatch(rust, /buffa|serde|crypto_proto|as u16|= 16/u);
});

test("component families, complete native bindings and scalar origins cannot drift", () => {
  rejects((value) => { value.registry.suites[0].components.kem = value.registry.suites[0].components.kdf; }, "hpke-component-family");
  rejects((value) => { value.registry.nativeEnums[0].values[0].nativeConstant = "HPKE_KDF_EXAMPLE"; }, "hpke-scalar-binding");
  rejects((value) => { value.model.modules[0].constants[0].value = "17"; }, "hpke-scalar-binding");
  rejects((value) => { delete value.model.modules[0].constants[0].enumReference; }, "hpke-scalar-binding");
  rejects((value) => { value.model.enums.get(enumType("Kem")).value.push({ name: "HPKE_KEM_ID_MORE", number: 17 }); }, "hpke-incomplete");
  rejects((value) => { value.registry.nativeEnums[0].values[0].schemaValue = "HPKE_KEM_ID_UNSPECIFIED"; }, "constants-enum-reference");
  rejects((value) => { value.registry.nativeEnums[0].values[0].nativeVariant = "Self"; }, "hpke-identifier");
  rejects((value) => { value.registry.nativeEnums[0].values[0].nativeVariant = "Example;fn injected()"; }, "hpke-identifier");
});

test("unknown, duplicate, cyclic and ambiguous suite metadata fail closed", () => {
  rejects((value) => { value.registry.extra = true; }, "hpke-fields");
  rejects((value) => { value.registry.suites[0].components.extra = {}; }, "hpke-fields");
  rejects((value) => { value.registry.suites[0].aliasName = "EXAMPLE_ALIAS"; }, "hpke-suite");
  rejects((value) => { value.registry.suites[1].aliasName = "EXAMPLE_ALIAS"; }, "hpke-alias-cycle");
  rejects((value) => { value.registry.suites[1].aliasName = "MISSING"; }, "hpke-alias");
  rejects((value) => { value.registry.suites[0] = { nativeName: "EXAMPLE_SUITE", aliasName: "EXAMPLE_ALIAS" }; }, "hpke-alias-cycle");
  rejects((value) => { value.registry.suites.push({ nativeName: "DUPLICATE", components: value.registry.suites[0].components }); }, "hpke-suite-duplicate");
  rejects((value) => { value.registry.suites[0].nativeName = "Self"; }, "hpke-identifier");
  rejects((value) => { value.registry.suites[0].nativeName = "NAME/*injection*/"; }, "hpke-identifier");
});

test("registry order is explicit while duplicate, zero and missing members reject", () => {
  const value = fixture();
  const definition = value.model.enums.get(enumType("Kem"));
  definition.value.push({ name: "HPKE_KEM_ID_SECOND", number: 17 });
  value.model.modules[0].constants.push({ name: "HPKE_KEM_SECOND", type: "u16", unit: "UNIT_IDENTIFIER", value: "17", enumReference: { enumType: enumType("Kem"), valueName: "HPKE_KEM_ID_SECOND", number: 17 } });
  value.registry.nativeEnums[0].values.push({ schemaValue: "HPKE_KEM_ID_SECOND", nativeVariant: "DhKemSecond", nativeConstant: "HPKE_KEM_SECOND" });
  value.registry.registries[0].members.unshift("HPKE_KEM_ID_SECOND");
  const result = parse(value).registries.find((registry) => registry.name === "HPKE_REGISTERED_KEMS");
  assert.deepEqual(result.members.map((member) => member.number), [17, 16]);
  rejects((value) => { value.registry.registries[0].members.push(value.registry.registries[0].members[0]); }, "hpke-registry-member");
  rejects((value) => { value.registry.registries[0].members[0] = "HPKE_KEM_ID_UNSPECIFIED"; }, "hpke-registry-member");
});

test("native source validation rejects independent numeric or tuple authority", () => {
  const contract = parse(fixture());
  const rejected = (mutate, code) => {
    const input = sources(); mutate(input);
    assert.throws(() => validateHpkeNativeSources(contract, input), (error) =>
      error instanceof ContractConstantsGenerationError && error.code === code);
  };
  rejected((value) => { value.identifiers = value.identifiers.replace("DhKemExample = HPKE_KEM_EXAMPLE", "DhKemExample = 16"); }, "hpke-source-enum");
  rejected((value) => { value.identifiers = value.identifiers.replace("DhKemExample = HPKE_KEM_EXAMPLE", "DhKemExample = HPKE_KDF_EXAMPLE"); }, "hpke-source-enum");
  rejected((value) => { value.constants = value.constants.replace("crypto_core::contract_constants::hpke::HPKE_KEM_EXAMPLE", "16"); }, "hpke-source-scalar");
  rejected((value) => { value.baseP256 = ""; }, "hpke-source-scalar");
  rejected((value) => { value.identifiers = value.identifiers.replace("pub use contract_constants::EXAMPLE_SUITE;", "pub const EXAMPLE_SUITE: HpkeSuite = unsafe_value();"); }, "hpke-source-owner");
});

test("maintenance owns one descriptor and formats owner output before writes", () => {
  const source = readFileSync(new URL("./generate_error_contract.mjs", import.meta.url), "utf8");
  assert.equal([...source.matchAll(/command\("buf",/gu)].length, 1);
  assert.match(source, /validateHpkeNativeSources\(hpkeContract/u);
  assert.match(source, /input: renderHpkeConstants\(hpkeContract\)/u);
  assert.match(source, /writeErrorContractOutput\(resolve\(root, HPKE_OUTPUT\), hpkeRust\)/u);
});

test("backend KEM identities and exact big-endian labels cannot regain numeric authority", () => {
  const constants = "pub(crate) const fn encode_kem_suite_id(kem_id: u16) -> [u8; 5] { let [high, low] = kem_id.to_be_bytes(); [b'K', b'E', b'M', high, low] }";
  const input = {};
  for (const [key, name] of [["mlkem512", "HPKE_KEM_ML_KEM_512"], ["mlkem1024p384", "HPKE_KEM_ML_KEM_1024_P384"],
    ["secp256k1", "HPKE_KEM_DHKEM_SECP256K1_HKDF_SHA256"], ["x448", "HPKE_KEM_DHKEM_X448_HKDF_SHA512"]]) {
    input[key] = `const KEM_ID: u16 = crate::constants::${name};\nconst KEM_SUITE_ID: &[u8] = &crate::constants::encode_kem_suite_id(KEM_ID);\n`;
  }
  validateHpkeBackendSources(constants, input);
  assert.throws(() => validateHpkeBackendSources(constants.replace("high, low]", "low, high]"), input),
    (error) => error instanceof ContractConstantsGenerationError && error.code === "hpke-source-context");
  input.mlkem512 = input.mlkem512.replace("crate::constants::HPKE_KEM_ML_KEM_512", "0x0040");
  assert.throws(() => validateHpkeBackendSources(constants, input),
    (error) => error instanceof ContractConstantsGenerationError && error.code === "hpke-source-context");
});

test("real comments and whitespace preserve canonical source ownership", () => {
  const contract = parse(fixture());
  const input = sources();
  input.identifiers = input.identifiers
    .replace('#[path = "generated/hpke_contract_constants.rs"]', '#[path /* nested /* note */ */ = "generated/hpke_contract_constants.rs"]')
    .replaceAll("#[repr(u16)]", "#[repr( /* note */ u16 )]")
    .replaceAll("pub enum", "pub /* doc */ enum")
    .replaceAll(" = HPKE_", " /* name */ = /* value */ HPKE_")
    .replaceAll("pub use", "pub /* export */ use");
  input.constants = input.constants.replaceAll("pub const", "pub /* note */ const")
    .replaceAll(": u16 =", ": u16 /* bound */ =")
    .replaceAll("crypto_core::", "crypto_core /* path */ ::");
  input.baseP256 = "/* ignored braces { [ /* nested */ */\n" + input.baseP256;
  validateHpkeNativeSources(contract, input);
});

test("commented and quoted scalar declarations cannot approve a divergent real alias", () => {
  const contract = parse(fixture());
  for (const wrap of [(value) => `/*\n${value}\n*/`, (value) => `const NOTE: &str = "\n${value}\n";`,
    (value) => `const NOTE: &[u8] = b"\n${value}\n";`, (value) => `const NOTE: &str = r###"\n${value}\n"###;`,
    (value) => `const NOTE: &[u8] = br###"\n${value}\n"###;`]) {
    const input = sources();
    const canonical = "pub const HPKE_KEM_EXAMPLE: u16 = crypto_core::contract_constants::hpke::HPKE_KEM_EXAMPLE;";
    input.constants = input.constants.replace(canonical,
      `${wrap(canonical)}\npub /* real */ const HPKE_KEM_EXAMPLE: u16 /* type */ = 1;`);
    assert.throws(() => validateHpkeNativeSources(contract, input), (error) =>
      error instanceof ContractConstantsGenerationError && error.code === "hpke-source-scalar");
  }
});

test("literal and nested declarations cannot replace a root enum or scalar", () => {
  const contract = parse(fixture());
  const input = sources();
  const canonical = "#[repr(u16)]\npub enum HpkeKemId {\n    DhKemExample = HPKE_KEM_EXAMPLE,\n}\n";
  input.identifiers = input.identifiers.replace(canonical,
    `const NOTE: &str = r###"${canonical}"###;\n` + canonical
      .replace("HPKE_KEM_EXAMPLE", "HPKE_KDF_EXAMPLE").replace("pub enum", "    pub /* real */ enum"));
  assert.throws(() => validateHpkeNativeSources(contract, input), (error) =>
    error instanceof ContractConstantsGenerationError && error.code === "hpke-source-enum");
  const nested = sources();
  nested.constants = `mod other { ${nested.constants} }`;
  assert.throws(() => validateHpkeNativeSources(contract, nested), (error) =>
    error instanceof ContractConstantsGenerationError && error.code === "hpke-source-scalar");
});

test("path and reexport authority comes from actual tokens and exact literal spans", () => {
  const contract = parse(fixture());
  const canonical = '#[path = "generated/hpke_contract_constants.rs"]\nmod contract_constants;';
  const input = sources();
  input.identifiers = input.identifiers.replace(canonical,
    `const NOTE: &str = r###"${canonical}"###;\n#[path = "wrong.rs"] mod contract_constants;`);
  assert.throws(() => validateHpkeNativeSources(contract, input), (error) =>
    error instanceof ContractConstantsGenerationError && error.code === "hpke-source-owner");
  const exportInput = sources();
  exportInput.identifiers = exportInput.identifiers.replace("pub use contract_constants::EXAMPLE_SUITE;",
    '/*\npub use contract_constants::EXAMPLE_SUITE;\n*/\npub /* real */ const EXAMPLE_SUITE: HpkeSuite = EXAMPLE_ALIAS;');
  assert.throws(() => validateHpkeNativeSources(contract, exportInput), (error) =>
    error instanceof ContractConstantsGenerationError && error.code === "hpke-source-owner");
});

const backendFixture = () => {
  const constants = "pub(crate) const fn encode_kem_suite_id(kem_id: u16) -> [u8; 5] { let [high, low] = kem_id.to_be_bytes(); [b'K', b'E', b'M', high, low] }";
  const input = Object.fromEntries([
    ["mlkem512", "HPKE_KEM_ML_KEM_512"], ["mlkem1024p384", "HPKE_KEM_ML_KEM_1024_P384"],
    ["secp256k1", "HPKE_KEM_DHKEM_SECP256K1_HKDF_SHA256"], ["x448", "HPKE_KEM_DHKEM_X448_HKDF_SHA512"],
  ].map(([name, target]) => [name,
    `const KEM_ID: u16 = crate::constants::${target};\nconst KEM_SUITE_ID: &[u8] = &crate::constants::encode_kem_suite_id(KEM_ID);`]));
  return { constants, input };
};

test("genuine backend comments retain exact byte labels without interpreting literals", () => {
  const { constants, input } = backendFixture();
  const annotated = constants.replace("let [high, low]", "let [ /* order */ high, low]")
    .replace("[b'K', b'E', b'M'", "[b'K', /* KEM */ b'E', b'M'");
  input.mlkem512 = input.mlkem512.replace("const KEM_ID", "const /* id */ KEM_ID")
    .replace(": u16 =", ": u16 /* type */ =");
  validateHpkeBackendSources(annotated, input);
});

test("comment and raw-string backend decoys cannot conceal changed byte order or IDs", () => {
  const { constants, input } = backendFixture();
  const changed = `const NOTE: &str = r###"${constants}"###;\n${constants
    .replace("high, low] }", "low, high] }").replace("pub(crate) const fn", "pub(crate) /* real */ const fn")}`;
  assert.throws(() => validateHpkeBackendSources(changed, input), (error) =>
    error instanceof ContractConstantsGenerationError && error.code === "hpke-source-context");
  const canonical = "const KEM_ID: u16 = crate::constants::HPKE_KEM_ML_KEM_512;";
  input.mlkem512 = input.mlkem512.replace(canonical,
    `/*\n${canonical}\n*/\nconst KEM_ID: u16 /* actual */ = 0x0041;`);
  assert.throws(() => validateHpkeBackendSources(constants, input), (error) =>
    error instanceof ContractConstantsGenerationError && error.code === "hpke-source-context");
  const labels = backendFixture();
  const canonicalLabel = "const KEM_SUITE_ID: &[u8] = &crate::constants::encode_kem_suite_id(KEM_ID);";
  labels.input.x448 = labels.input.x448.replace(canonicalLabel,
    `/*\n${canonicalLabel}\n*/\nconst KEM_SUITE_ID: &[u8] /* actual */ = b"KEMwrong";`);
  assert.throws(() => validateHpkeBackendSources(labels.constants, labels.input), (error) =>
    error instanceof ContractConstantsGenerationError && error.code === "hpke-source-context");
});

test("existing source-size diagnostics stay fixed for invalid maintenance inputs", () => {
  const contract = parse(fixture());
  for (const constants of [undefined, 1, " ".repeat(4_194_305)]) {
    const input = sources(); input.constants = constants;
    assert.throws(() => validateHpkeNativeSources(contract, input), (error) =>
      error instanceof ContractConstantsGenerationError && error.code === "hpke-source-size");
  }
});
