// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

// This module is pure. The existing maintenance entry point owns the single
// bounded Buf invocation, output formatting, and filesystem operations.

const PACKAGE = "reallyme.crypto.contract.v1";
const SCHEMA = "reallyme/crypto/contract/v1/constants.proto";
const OPTION = `[${PACKAGE}.constant_registry]`;
const MAX_FILES = 128;
const MAX_MODULES = 256;
const MAX_CONSTANTS = 4_096;
const MAX_RANGES = 4_096;
const MAX_NODES = 250_000;
const MAX_DEPTH = 64;
const MAX_IDENTIFIER_LENGTH = 128;
const MAX_CONSTANT_BYTES = 4_096;
const UINT32_MAX = 4_294_967_295n;
const TYPES = new Map([
  ["NATIVE_TYPE_U8", { rust: "u8", maximum: 255n }],
  ["NATIVE_TYPE_U16", { rust: "u16", maximum: 65_535n }],
  ["NATIVE_TYPE_U32", { rust: "u32", maximum: UINT32_MAX }],
  ["NATIVE_TYPE_U64", { rust: "u64", maximum: 18_446_744_073_709_551_615n }],
  // Public metadata must compile with the same value on native and WASM32.
  ["NATIVE_TYPE_USIZE", { rust: "usize", maximum: UINT32_MAX }],
  ["NATIVE_TYPE_I32", { rust: "i32", minimum: -2_147_483_648n, maximum: 2_147_483_647n }],
  ["NATIVE_TYPE_BYTES", { rust: "&[u8]" }],
]);
const UNITS = new Set(["UNIT_BYTES", "UNIT_BITS", "UNIT_KIBIBYTES", "UNIT_ITERATIONS",
  "UNIT_PASSES", "UNIT_LANES", "UNIT_EVALUATIONS", "UNIT_IDENTIFIER", "UNIT_DIMENSIONLESS",
  "UNIT_COUNT", "UNIT_LEVELS"]);
const RUST_KEYWORDS = new Set(["as", "async", "await", "become", "box", "break", "const",
  "continue", "crate", "do", "dyn", "else", "enum", "extern", "false", "final", "fn", "for",
  "gen", "if", "impl", "in", "let", "loop", "macro", "match", "mod", "move", "mut", "override",
  "priv", "pub", "ref", "return", "self", "static", "struct", "super", "trait", "true", "try",
  "type", "typeof", "union", "unsafe", "unsized", "use", "virtual", "where", "while", "yield"]);

/** Fixed diagnostics contain no descriptor or subprocess content. */
export class ContractConstantsGenerationError extends Error {
  constructor(code) {
    super("contract constants generation failed");
    this.name = "ContractConstantsGenerationError";
    this.code = code;
  }
}
const fail = (code) => { throw new ContractConstantsGenerationError(code); };
const record = (value) => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail("constants-shape");
  return value;
};
const list = (value, maximum, allowEmpty = false) => {
  if (!Array.isArray(value) || value.length > maximum || (!allowEmpty && value.length === 0)) fail("constants-shape");
  return value;
};
const keys = (value, permitted, required = permitted) => {
  record(value);
  if (Object.keys(value).some((name) => !permitted.includes(name)) ||
      required.some((name) => !Object.hasOwn(value, name))) fail("constants-fields");
};
const integer = (value, minimum, maximum) => {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail("constants-number");
  return value;
};
const identifier = (value, module = false) => {
  const pattern = module ? /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/u : /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$/u;
  if (typeof value !== "string" || value.length > MAX_IDENTIFIER_LENGTH || !pattern.test(value) ||
      (module && RUST_KEYWORDS.has(value))) fail("constants-identifier");
  return value;
};
const named = (values, name) => {
  const matches = list(values, MAX_CONSTANTS).map(record).filter((value) => value.name === name);
  if (matches.length !== 1) fail("constants-declaration");
  return matches[0];
};
const compare = (left, right) => left < right ? -1 : left > right ? 1 : 0;

function validateEnum(file, name, expected) {
  const definition = named(file.enumType, name);
  if (record(definition.options ?? {}).allowAlias === true) fail("constants-alias");
  const values = list(definition.value, MAX_CONSTANTS).map(record);
  const names = new Set();
  const numbers = new Set();
  for (const value of values) {
    integer(value.number, 0, 2_147_483_647);
    if (!expected.has(value.name) || names.has(value.name) || numbers.has(value.number)) fail("constants-enum");
    names.add(value.name);
    numbers.add(value.number);
  }
  if (names.size !== expected.size || values[0].number !== 0 ||
      values[0].name !== `${name === "NativeType" ? "NATIVE_TYPE" : "UNIT"}_UNSPECIFIED`) fail("constants-enum");
}

function validateMessage(file, name, expected, oneof = false) {
  const message = named(file.messageType, name);
  const fields = list(message.field, MAX_CONSTANTS).map(record);
  if (fields.length !== expected.length || Object.hasOwn(message, "nestedType") ||
      Object.hasOwn(message, "enumType") || Object.hasOwn(message, "extension")) fail("constants-declaration");
  if (oneof) {
    const oneofs = list(message.oneofDecl, 1).map(record);
    if (oneofs.length !== 1 || oneofs[0].name !== "value") fail("constants-oneof");
  } else if (Object.hasOwn(message, "oneofDecl")) fail("constants-oneof");
  const seen = new Set();
  for (const field of fields) {
    const declaration = expected.find((entry) => entry.name === field.name);
    if (declaration === undefined || seen.has(field.name) || field.number !== declaration.number ||
        field.type !== declaration.type || field.label !== (declaration.repeated ? "LABEL_REPEATED" : "LABEL_OPTIONAL") ||
        field.typeName !== declaration.typeName || field.proto3Optional === true ||
        Object.hasOwn(field, "defaultValue") ||
        (declaration.oneof ? field.oneofIndex !== 0 : Object.hasOwn(field, "oneofIndex"))) fail("constants-field");
    seen.add(field.name);
  }
}

function validateDefinitions(file) {
  if (file.package !== PACKAGE || (file.syntax !== undefined && file.syntax !== "proto2") ||
      list(file.enumType, 2).length !== 2 || list(file.messageType, 6).length !== 6) fail("constants-schema");
  validateEnum(file, "NativeType", new Set(["NATIVE_TYPE_UNSPECIFIED", ...TYPES.keys()]));
  validateEnum(file, "Unit", new Set(["UNIT_UNSPECIFIED", ...UNITS]));
  const field = (name, number, type, extra = {}) => ({ name, number, type, ...extra });
  const message = (name) => `.${PACKAGE}.${name}`;
  validateMessage(file, "Constant", [field("native_name", 1, "TYPE_STRING"),
    field("native_type", 2, "TYPE_ENUM", { typeName: message("NativeType") }),
    field("unit", 3, "TYPE_ENUM", { typeName: message("Unit") }),
    field("unsigned_value", 4, "TYPE_UINT64", { oneof: true }),
    field("signed_value", 5, "TYPE_SINT64", { oneof: true }),
    field("bytes_value", 6, "TYPE_BYTES", { oneof: true }),
    field("constant_reference", 7, "TYPE_MESSAGE", { typeName: message("ConstantReference"), oneof: true }),
    field("enum_reference", 8, "TYPE_MESSAGE", { typeName: message("EnumValueReference"), oneof: true })], true);
  validateMessage(file, "ConstantReference", [field("native_module", 1, "TYPE_STRING"), field("native_name", 2, "TYPE_STRING")]);
  validateMessage(file, "EnumValueReference", [field("enum_type", 1, "TYPE_STRING"), field("value_name", 2, "TYPE_STRING")]);
  validateMessage(file, "ConstantRange", [field("minimum_name", 1, "TYPE_STRING"), field("maximum_name", 2, "TYPE_STRING")]);
  validateMessage(file, "ConstantModule", [field("native_module", 1, "TYPE_STRING"),
    field("constants", 2, "TYPE_MESSAGE", { typeName: message("Constant"), repeated: true }),
    field("ranges", 3, "TYPE_MESSAGE", { typeName: message("ConstantRange"), repeated: true })]);
  validateMessage(file, "ConstantRegistry", [field("modules", 1, "TYPE_MESSAGE", { typeName: message("ConstantModule"), repeated: true })]);
  const extensions = list(file.extension, 1).map(record);
  const extension = extensions[0];
  if (extensions.length !== 1 || extension.name !== "constant_registry" ||
      extension.extendee !== ".google.protobuf.FileOptions" || extension.label !== "LABEL_OPTIONAL" ||
      extension.type !== "TYPE_MESSAGE" || extension.typeName !== message("ConstantRegistry")) fail("constants-extension");
  integer(extension.number, 1_000, 536_870_911);
  if (extension.number >= 19_000 && extension.number <= 19_999) fail("constants-extension");
}

function validateOptionSites(files) {
  const known = new Set();
  const fileOptions = new Set();
  const extensionNumbers = new Set();
  for (const file of files) {
    for (const value of list(file.extension ?? [], MAX_CONSTANTS, true).map(record)) {
      if (file.package !== PACKAGE) continue;
      const name = identifier(value.name, true);
      const key = `[${PACKAGE}.${name}]`;
      const number = integer(value.number, 1_000, 536_870_911);
      if (typeof value.extendee !== "string" || value.extendee.length > 512 ||
          (number >= 19_000 && number <= 19_999)) fail("constants-extension");
      const numericKey = `${value.extendee}:${number}`;
      if (known.has(key) || extensionNumbers.has(numericKey)) fail("constants-extension");
      known.add(key);
      if (value.extendee === ".google.protobuf.FileOptions") fileOptions.add(key);
      extensionNumbers.add(numericKey);
    }
  }
  let nodes = 0;
  const visit = (value, rootOptions, depth) => {
    nodes += 1;
    if (nodes > MAX_NODES || depth > MAX_DEPTH) fail("constants-complexity");
    if (Array.isArray(value)) {
      if (value.length > MAX_CONSTANTS) fail("constants-complexity");
      for (const item of value) visit(item, rootOptions, depth + 1);
    } else if (value !== null && typeof value === "object") {
      for (const [key, item] of Object.entries(value)) {
        if (key.startsWith(`[${PACKAGE}.`) && !known.has(key)) fail("constants-option");
        if (fileOptions.has(key) && value !== rootOptions) fail("constants-owner");
        visit(item, rootOptions, depth + 1);
      }
    }
  };
  for (const file of files) visit(file, file.options, 0);
}

function enumIndex(files) {
  const result = new Map();
  const visit = (owner, prefix, depth) => {
    if (depth > MAX_DEPTH) fail("constants-complexity");
    for (const definition of list(owner.enumType ?? [], MAX_CONSTANTS, true).map(record)) {
      if (typeof definition.name !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(definition.name)) fail("constants-enum-reference");
      const name = `${prefix}.${definition.name}`;
      if (result.has(name)) fail("constants-enum-reference");
      result.set(name, definition);
      if (result.size > MAX_CONSTANTS) fail("constants-complexity");
    }
    for (const message of list(owner.nestedType ?? owner.messageType ?? [], MAX_CONSTANTS, true).map(record)) {
      if (typeof message.name !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(message.name)) fail("constants-enum-reference");
      visit(message, `${prefix}.${message.name}`, depth + 1);
    }
  };
  for (const file of files) {
    if (typeof file.package !== "string" || file.package.length > 512 ||
        !/^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/u.test(file.package)) fail("constants-enum-reference");
    visit(file, `.${file.package}`, 0);
  }
  return result;
}

/** Resolve one positive identity directly from its defining descriptor. */
export function resolveEnumReference(index, raw) {
  keys(raw, ["enumType", "valueName"]);
  if (typeof raw.enumType !== "string" || raw.enumType.length > 512 ||
      !/^\.(?:[A-Za-z_][A-Za-z0-9_]*\.)+[A-Za-z_][A-Za-z0-9_]*$/u.test(raw.enumType)) fail("constants-enum-reference");
  const valueName = identifier(raw.valueName);
  const definition = index.get(raw.enumType);
  if (definition === undefined || record(definition.options ?? {}).allowAlias === true) fail("constants-enum-reference");
  const names = new Set();
  const numbers = new Set();
  const values = list(definition.value, MAX_CONSTANTS).map(record);
  for (const value of values) {
    const name = identifier(value.name);
    const number = integer(value.number, -2_147_483_648, 2_147_483_647);
    if (names.has(name) || numbers.has(number)) fail("constants-enum-reference");
    names.add(name); numbers.add(number);
  }
  const value = values.find((entry) => entry.name === valueName);
  if (value === undefined || value.number <= 0) fail("constants-enum-reference");
  const reserved = new Set(list(definition.reservedName ?? [], MAX_CONSTANTS, true).map((name) => identifier(name)));
  if (reserved.has(valueName)) fail("constants-enum-reference");
  for (const rawRange of list(definition.reservedRange ?? [], MAX_CONSTANTS, true).map(record)) {
    const start = integer(rawRange.start, -2_147_483_648, 2_147_483_647);
    const end = integer(rawRange.end, start, 2_147_483_647);
    if (value.number >= start && value.number <= end) fail("constants-enum-reference");
  }
  return { enumType: raw.enumType, valueName, number: value.number };
}

function parseValue(raw, index) {
  keys(raw, ["nativeName", "nativeType", "unit", "unsignedValue", "signedValue", "bytesValue", "constantReference", "enumReference"],
    ["nativeName", "nativeType", "unit"]);
  const name = identifier(raw.nativeName);
  const type = TYPES.get(raw.nativeType);
  if (type === undefined || !UNITS.has(raw.unit)) fail("constants-type");
  const values = ["unsignedValue", "signedValue", "bytesValue", "constantReference", "enumReference"].filter((key) => Object.hasOwn(raw, key));
  if (values.length !== 1) fail("constants-value");
  const key = values[0];
  const value = raw[key];
  if (key === "constantReference") {
    keys(value, ["nativeModule", "nativeName"]);
    return { name, type: type.rust, unit: raw.unit, reference: {
      module: identifier(value.nativeModule, true), name: identifier(value.nativeName),
    } };
  }
  if (key === "enumReference") {
    if (raw.unit !== "UNIT_IDENTIFIER" || type.rust === "&[u8]") fail("constants-unit");
    const reference = resolveEnumReference(index, value);
    if (BigInt(reference.number) > type.maximum) fail("constants-overflow");
    return { name, type: type.rust, unit: raw.unit, value: String(reference.number), enumReference: reference };
  }
  if (type.rust === "&[u8]") {
    if (raw.unit !== "UNIT_BYTES" || key !== "bytesValue" || typeof value !== "string" ||
        value.length > Math.ceil(MAX_CONSTANT_BYTES / 3) * 4 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) fail("constants-bytes");
    const bytes = Buffer.from(value, "base64");
    if (bytes.length > MAX_CONSTANT_BYTES || bytes.toString("base64") !== value) fail("constants-bytes");
    return { name, type: type.rust, unit: raw.unit, value };
  }
  if (typeof value !== "string" || value.length > 21 ||
      !/^(?:0|[1-9][0-9]*|-[1-9][0-9]*)$/u.test(value)) fail("constants-decimal");
  const signed = type.rust === "i32";
  if (key !== (signed ? "signedValue" : "unsignedValue")) fail("constants-value");
  if (signed && raw.unit !== "UNIT_IDENTIFIER" && raw.unit !== "UNIT_DIMENSIONLESS") fail("constants-unit");
  const number = BigInt(value);
  if (number < (type.minimum ?? 0n) || number > type.maximum) fail("constants-overflow");
  return { name, type: type.rust, unit: raw.unit, value };
}

/** Consume the already bounded/decoded descriptor used by error generation. */
export function parseContractConstantsDescriptor(document) {
  const files = list(record(document).file, MAX_FILES).map(record);
  const fileNames = new Set();
  for (const file of files) {
    if (typeof file.name !== "string" || file.name.length > 512 ||
        !/^(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_.-]+\.proto$/u.test(file.name) || fileNames.has(file.name)) fail("constants-file");
    fileNames.add(file.name);
  }
  const definitions = files.filter((file) => file.name === SCHEMA);
  if (definitions.length !== 1) fail("constants-schema");
  validateDefinitions(definitions[0]);
  validateOptionSites(files);
  const index = enumIndex(files);
  const modules = new Map();
  let count = 0;
  let rangeCount = 0;
  for (const file of files) {
    const options = record(file.options ?? {});
    if (!Object.hasOwn(options, OPTION)) continue;
    const registry = record(options[OPTION]);
    keys(registry, ["modules"]);
    const local = new Set();
    for (const raw of list(registry.modules, MAX_MODULES).map(record)) {
      keys(raw, ["nativeModule", "constants", "ranges"], ["nativeModule", "constants"]);
      const name = identifier(raw.nativeModule, true);
      if (local.has(name)) fail("constants-duplicate");
      local.add(name);
      if (!modules.has(name)) modules.set(name, { name, constants: new Map(), ranges: new Map() });
      if (modules.size > MAX_MODULES) fail("constants-complexity");
      const module = modules.get(name);
      for (const value of list(raw.constants, MAX_CONSTANTS).map(record)) {
        count += 1;
        if (count > MAX_CONSTANTS) fail("constants-complexity");
        const constant = parseValue(value, index);
        if (module.constants.has(constant.name)) fail("constants-duplicate");
        module.constants.set(constant.name, constant);
      }
      for (const range of list(raw.ranges ?? [], MAX_RANGES, true).map(record)) {
        rangeCount += 1;
        if (rangeCount > MAX_RANGES) fail("constants-complexity");
        keys(range, ["minimumName", "maximumName"]);
        const minimum = identifier(range.minimumName);
        const maximum = identifier(range.maximumName);
        const key = `${minimum}:${maximum}`;
        if (module.ranges.has(key)) fail("constants-duplicate");
        module.ranges.set(key, { minimum, maximum });
      }
    }
  }
  if (modules.size === 0) fail("constants-missing");
  const states = new Map();
  const resolve = (module, constant, depth) => {
    if (depth > MAX_DEPTH) fail("constants-complexity");
    const key = `${module.name}:${constant.name}`;
    if (states.get(key) === "done") return;
    if (states.get(key) === "visiting") fail("constants-reference-cycle");
    states.set(key, "visiting");
    if (constant.reference !== undefined) {
      const targetModule = modules.get(constant.reference.module);
      const target = targetModule?.constants.get(constant.reference.name);
      if (target === undefined) fail("constants-reference");
      resolve(targetModule, target, depth + 1);
      if (target.type !== constant.type || target.unit !== constant.unit) fail("constants-reference-type");
      constant.value = target.value;
    }
    states.set(key, "done");
  };
  for (const module of modules.values()) {
    for (const constant of module.constants.values()) resolve(module, constant, 0);
  }
  for (const module of modules.values()) {
    for (const range of module.ranges.values()) {
      const minimum = module.constants.get(range.minimum);
      const maximum = module.constants.get(range.maximum);
      if (minimum === undefined || maximum === undefined || minimum.type === "&[u8]" ||
          minimum.type !== maximum.type || minimum.unit !== maximum.unit ||
          BigInt(minimum.value) > BigInt(maximum.value)) fail("constants-range");
    }
  }
  return { enums: index, modules: [...modules.values()].sort((left, right) => compare(left.name, right.name)).map((module) => ({
    name: module.name,
    constants: [...module.constants.values()].sort((left, right) => compare(left.name, right.name)),
    ranges: [...module.ranges.values()].sort((left, right) => compare(left.minimum, right.minimum) || compare(left.maximum, right.maximum)),
  })) };
}

/** Check known schema reasons without rejecting future within-family wire codes. */
export function validateErrorReasonRanges(errorContract, constantContract) {
  const bounds = new Map([
    ["primitive", ["PRIMITIVE_REASON_CODE_MIN", "PRIMITIVE_REASON_CODE_MAX"]],
    ["provider", ["PROVIDER_REASON_CODE_MIN", "PROVIDER_REASON_CODE_MAX"]],
    ["backend", ["BACKEND_REASON_CODE_MIN", "BACKEND_REASON_CODE_MAX"]],
  ]);
  const module = constantContract.modules.find((value) => value.name === "proto_wire");
  if (module === undefined) fail("constants-reason-range");
  const constants = new Map(module.constants.map((value) => [value.name, value]));
  const intervals = [];
  for (const branch of errorContract.branches) {
    const names = bounds.get(branch.name);
    if (names === undefined) fail("constants-reason-range");
    const values = names.map((name) => constants.get(name));
    if (values.some((value) => value === undefined || value.type !== "i32" || value.unit !== "UNIT_IDENTIFIER")) fail("constants-reason-range");
    const minimum = BigInt(values[0].value);
    const maximum = BigInt(values[1].value);
    if (minimum <= 0n || minimum > maximum) fail("constants-reason-range");
    if (intervals.some((range) => minimum <= range.maximum && maximum >= range.minimum)) fail("constants-reason-range");
    intervals.push({ minimum, maximum });
    for (const reason of errorContract.reasons.filter((value) => value.branch?.name === branch.name)) {
      const code = BigInt(reason.number);
      if (code < minimum || code > maximum) fail("constants-reason-range");
    }
  }
}

/** Emit only native literals; codecs, descriptor machinery and errors stay absent. */
export function renderContractConstants(contract) {
  const lines = ["// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited", "//",
    "// SPDX-License-Identifier: MIT OR Apache-2.0", "",
    "// Generated from immutable schema metadata. Regenerate with scripts/generate_error_contract.mjs.", ""];
  for (const module of contract.modules) {
    lines.push(`/// Immutable \`${module.name}\` contract constants.`, `pub mod ${module.name} {`);
    for (const constant of module.constants) {
      const value = constant.reference !== undefined ? `super::${constant.reference.module}::${constant.reference.name}` :
        constant.type === "&[u8]" ? `&[${[...Buffer.from(constant.value, "base64")].map((byte) => `0x${byte.toString(16).padStart(2, "0")}`).join(", ")}]` : constant.value;
      lines.push(`    /// Exact ${constant.unit.slice("UNIT_".length).toLowerCase()} value declared by the schema.`,
        `    pub const ${constant.name}: ${constant.type} = ${value};`);
    }
    lines.push("}", "");
  }
  return lines.join("\n");
}
