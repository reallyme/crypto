// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { existsSync, readdirSync } from "node:fs";

const operationRouteLedgerPath = "docs/operation-route-ledger.json";

const cryptoProtoPath = "crates/proto/proto/reallyme/crypto/v1/crypto.proto";
const generatedCryptoRustPath = "crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.rs";
const ffiSourceRoot = "crates/ffi/src";
const wasmPackageSourceRoot = "crates/wasm/src";
const primitiveCrateRoots = [
  "crates/aes-kw",
  "crates/aes256-gcm",
  "crates/aes256-gcm-siv",
  "crates/argon2id",
  "crates/chacha20-poly1305",
  "crates/concat-kdf",
  "crates/constant-time",
  "crates/csprng",
  "crates/ed25519",
  "crates/hkdf",
  "crates/hmac",
  "crates/kmac",
  "crates/ml-dsa-44",
  "crates/ml-dsa-65",
  "crates/ml-dsa-87",
  "crates/ml-kem-1024",
  "crates/ml-kem-512",
  "crates/ml-kem-768",
  "crates/p256",
  "crates/p384",
  "crates/p521",
  "crates/pbkdf2",
  "crates/rsa",
  "crates/secp256k1",
  "crates/sha2",
  "crates/sha2-256",
  "crates/sha3",
  "crates/sha3-256",
  "crates/slh-dsa",
  "crates/x-wing",
  "crates/x25519",
];

const reviewedRouteStatuses = new Set([
  "public_dispatch_authority",
  "operation_facade_authority",
  "operation_response_branch_authority",
  "primary_structured_boundary",
  "primary_operation_response_forwarder",
  "dispatch_backed_signature_trait_routes",
  "declared_operation_contract",
  "exact_static_instance_and_overload_facade_routes",
  "jvm_package_facade",
  "android_package_has_no_android-owned_callable_route_and_reuses_kotlin_public_api",
  "public_protobuf_adapter_surface",
  "operation_backed_c_abi_scalar_routes",
  "validated_jni_exports",
  "validated_wasm_exports",
  "validated_swift_direct_routes",
  "validated_kotlin_direct_routes",
  "validated_typescript_direct_routes",
  "typescript_generic_facade",
]);

const ambientProviderNames = [
  "deriveP256SharedSecret",
  "deriveX25519SharedSecret",
  "ed25519DeriveKeypair",
  "ed25519GenerateKeypair",
  "generateP256Keypair",
  "generateSecp256k1Keypair",
  "signEd25519",
  "signP256DerPrehash",
  "signSecp256k1",
  "verifyEd25519",
  "verifyP256DerPrehash",
  "verifySecp256k1",
  "x25519DeriveKeypair",
  "x25519GenerateKeypair",
];

const wasmRuntimeFeatures = [
  "aes",
  "ed25519",
  "ml-dsa-44",
  "ml-dsa-65",
  "ml-dsa-87",
  "ml-kem-512",
  "ml-kem-768",
  "ml-kem-1024",
  "p256",
  "secp256k1",
  "slh-dsa",
  "x25519",
];

const requireArray = (value, description, fail) => {
  if (!Array.isArray(value)) {
    fail(`${description} must be an array`);
  }
  return value;
};

const requireString = (value, description, fail) => {
  if (typeof value !== "string" || value.length === 0) {
    fail(`${description} must be a non-empty string`);
  }
  return value;
};

const sortedUnique = (values) => [...new Set(values)].sort((left, right) => left.localeCompare(right));

const listSourceFiles = (root, extension, fail) => {
  if (!existsSync(root)) {
    return [];
  }
  const paths = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = `${directory}/${entry.name}`;
      if (entry.isSymbolicLink()) {
        fail(`operation route source tree must not contain symbolic link ${path}`);
      } else if (entry.isDirectory()) {
        visit(path);
      } else if (entry.isFile() && entry.name.endsWith(extension)) {
        paths.push(path);
      }
    }
  };
  visit(root);
  return paths.sort((left, right) => left.localeCompare(right));
};

const extractBraceDelimitedBlock = (source, marker, description, fail) => {
  const markerIndex = source.indexOf(marker);
  if (markerIndex === -1) {
    fail(`${description} is missing ${marker}`);
  }
  const openIndex = source.indexOf("{", markerIndex + marker.length);
  if (openIndex === -1) {
    fail(`${description} is missing an opening brace after ${marker}`);
  }
  let depth = 0;
  for (let index = openIndex; index < source.length; index += 1) {
    if (source[index] === "{") {
      depth += 1;
    } else if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) {
        return source.slice(openIndex + 1, index);
      }
    }
  }
  fail(`${description} has an unterminated block after ${marker}`);
};

const assertGeneratedDropZeroizesFields = ({
  readText,
  fail,
  area,
  typeName,
  fields,
}) => {
  const source = readText(generatedCryptoRustPath);
  const implementation = extractBraceDelimitedBlock(
    source,
    `impl ::core::ops::Drop for ${typeName}`,
    `${area} generated secret cleanup`,
    fail,
  );
  for (const field of fields) {
    const required = `::zeroize::Zeroize::zeroize(&mut self.${field});`;
    if (!implementation.includes(required)) {
      fail(`${area} generated secret cleanup must zeroize ${typeName}.${field}`);
    }
  }
};

const assertSameSet = (actual, expected, description, fail) => {
  const actualSorted = sortedUnique(actual);
  const expectedSorted = sortedUnique(expected);
  const missing = expectedSorted.filter((value) => !actualSorted.includes(value));
  const unexpected = actualSorted.filter((value) => !expectedSorted.includes(value));
  if (missing.length !== 0 || unexpected.length !== 0) {
    const missingText = missing.length === 0 ? "none" : missing.join(", ");
    const unexpectedText = unexpected.length === 0 ? "none" : unexpected.join(", ");
    fail(`${description} mismatch; missing: ${missingText}; unexpected: ${unexpectedText}`);
  }
};

const routeGroupById = (ledger, fail) => {
  const groups = new Map();
  for (const group of requireArray(ledger.route_groups, "operation route ledger route_groups", fail)) {
    const id = requireString(group.id, "operation route ledger route group id", fail);
    if (groups.has(id)) {
      fail(`operation route ledger duplicates route group ${id}`);
    }
    groups.set(id, group);
  }
  return groups;
};

const ownerSet = (ledger, fail) => {
  const owners = new Set();
  for (const owner of requireArray(ledger.owners, "operation route ledger owners", fail)) {
    const id = requireString(owner.id, "operation route ledger owner id", fail);
    if (owners.has(id)) {
      fail(`operation route ledger duplicates owner ${id}`);
    }
    owners.add(id);
  }
  return owners;
};

export const flattenRouteGroupSymbols = (group, fail = (message) => {
  throw new Error(message);
}) => {
  const entries = [];
  if (group.symbols !== undefined) {
    const symbols = requireArray(group.symbols, `${group.id}.symbols`, fail);
    if (symbols.length !== 0 || group.owner !== undefined) {
      const owner = requireString(group.owner, `${group.id}.owner`, fail);
      for (const symbol of symbols) {
        entries.push({ groupId: group.id, owner, symbol: requireString(symbol, `${group.id}.symbols[]`, fail) });
      }
    }
  }
  if (group.symbols_by_owner !== undefined) {
    if (group.symbols_by_owner === null || typeof group.symbols_by_owner !== "object" || Array.isArray(group.symbols_by_owner)) {
      fail(`${group.id}.symbols_by_owner must be an object`);
    }
    for (const [owner, symbols] of Object.entries(group.symbols_by_owner)) {
      requireString(owner, `${group.id}.symbols_by_owner owner`, fail);
      const symbolList = requireArray(symbols, `${group.id}.symbols_by_owner.${owner}`, fail);
      if (symbolList.length === 0) {
        fail(`${group.id}.symbols_by_owner.${owner} must not be empty`);
      }
      for (const symbol of symbolList) {
        entries.push({ groupId: group.id, owner, symbol: requireString(symbol, `${group.id}.${owner} symbol`, fail) });
      }
    }
  }
  return entries;
};

export const findUnsupportedOperationResponsePlaceholders = (ledger, fail = (message) => {
  throw new Error(message);
}) => {
  const groups = routeGroupById(ledger, fail);
  const protoBranches = groups.get("rust.operation_response.branches");
  if (protoBranches === undefined) {
    fail("operation route ledger is missing rust.operation_response.branches");
  }
  return flattenRouteGroupSymbols(protoBranches, fail).filter(
    (entry) => entry.symbol.includes("=> unsupported_algorithm"),
  );
};

export const assertLedgerRoutesAreMapped = (ledger, fail) => {
  if (ledger.schema_version !== 1) {
    fail("operation route ledger schema_version must be 1");
  }
  const owners = ownerSet(ledger, fail);
  const groups = routeGroupById(ledger, fail);
  if (groups.size === 0) {
    fail("operation route ledger must contain route groups");
  }
  for (const group of groups.values()) {
    requireString(group.lane, `${group.id}.lane`, fail);
    requireString(group.path, `${group.id}.path`, fail);
    const currentStatus = requireString(group.current_status, `${group.id}.current_status`, fail);
    if (!reviewedRouteStatuses.has(currentStatus)) {
      fail(`${group.id} uses unreviewed route status ${currentStatus}`);
    }
    const hasSymbols = group.symbols !== undefined;
    const hasSymbolsByOwner = group.symbols_by_owner !== undefined;
    if (hasSymbols && hasSymbolsByOwner) {
      fail(`${group.id} must use either symbols or symbols_by_owner, not both`);
    }
    const seenSymbols = new Set();
    for (const entry of flattenRouteGroupSymbols(group, fail)) {
      if (!owners.has(entry.owner)) {
        fail(`${group.id} maps ${entry.symbol} to unknown owner ${entry.owner}`);
      }
      if (entry.symbol.includes("*")) {
        fail(`${group.id} uses wildcard route symbol ${entry.symbol}`);
      }
      if (seenSymbols.has(entry.symbol)) {
        fail(`${group.id} maps route symbol ${entry.symbol} more than once`);
      }
      seenSymbols.add(entry.symbol);
    }
    const hiddenSymbols = requireArray(
      group.intentionally_hidden_symbols ?? [],
      `${group.id}.intentionally_hidden_symbols`,
      fail,
    );
    for (const hidden of hiddenSymbols) {
      const owner = requireString(hidden.owner, `${group.id}.intentionally_hidden_symbols[].owner`, fail);
      const symbol = requireString(hidden.symbol, `${group.id}.intentionally_hidden_symbols[].symbol`, fail);
      requireString(hidden.reason, `${group.id}.intentionally_hidden_symbols[].reason`, fail);
      if (!owners.has(owner)) {
        fail(`${group.id} maps hidden symbol ${symbol} to unknown owner ${owner}`);
      }
      if (seenSymbols.has(symbol)) {
        fail(`${group.id} maps route symbol ${symbol} more than once`);
      }
      seenSymbols.add(symbol);
    }
    const rootOnlySymbols = requireArray(
      group.root_only_symbols ?? [],
      `${group.id}.root_only_symbols`,
      fail,
    );
    for (const rootOnly of rootOnlySymbols) {
      const owner = requireString(
        rootOnly.owner,
        `${group.id}.root_only_symbols[].owner`,
        fail,
      );
      const symbol = requireString(
        rootOnly.symbol,
        `${group.id}.root_only_symbols[].symbol`,
        fail,
      );
      requireString(rootOnly.reason, `${group.id}.root_only_symbols[].reason`, fail);
      if (!owners.has(owner)) {
        fail(`${group.id} maps root-only symbol ${symbol} to unknown owner ${owner}`);
      }
      if (!seenSymbols.has(symbol)) {
        fail(`${group.id} root-only symbol ${symbol} must also be a mapped public route`);
      }
    }
    const reusedGroups = requireArray(
      group.reused_route_groups ?? [],
      `${group.id}.reused_route_groups`,
      fail,
    );
    if (seenSymbols.size === 0 && reusedGroups.length === 0) {
      fail(`${group.id} must map at least one route or reuse a mapped route group`);
    }
    const seenReusedGroups = new Set();
    for (const reusedGroup of reusedGroups) {
      requireString(reusedGroup, `${group.id}.reused_route_groups[]`, fail);
      if (!groups.has(reusedGroup)) {
        fail(`${group.id} reuses unknown route group ${reusedGroup}`);
      }
      if (reusedGroup === group.id) {
        fail(`${group.id} must not reuse itself`);
      }
      if (seenReusedGroups.has(reusedGroup)) {
        fail(`${group.id} reuses route group ${reusedGroup} more than once`);
      }
      seenReusedGroups.add(reusedGroup);
    }
  }
};

const ledgerSymbolsForGroup = (ledger, groupId, fail) => {
  const group = routeGroupById(ledger, fail).get(groupId);
  if (group === undefined) {
    fail(`operation route ledger is missing ${groupId}`);
  }
  return flattenRouteGroupSymbols(group, fail).map((entry) => entry.symbol);
};

export const extractProtoOperationRouteSymbols = (source, fail) => {
  const request = extractBraceDelimitedBlock(
    source,
    "message CryptoOperationRequest",
    "crypto protobuf contract",
    fail,
  );
  const operation = extractBraceDelimitedBlock(
    request,
    "oneof operation",
    "CryptoOperationRequest",
    fail,
  );
  return [...operation.matchAll(/\b[A-Za-z_][A-Za-z0-9_.]*\s+([a-z][a-z0-9_]*)\s*=\s*[0-9]+\s*;/gu)]
    .map((match) => `CryptoOperationRequest.${match[1]}`);
};

const extractProtoOperationFields = (source, messageName, oneofName, fail) => {
  const message = extractBraceDelimitedBlock(
    source,
    `message ${messageName}`,
    "crypto protobuf contract",
    fail,
  );
  const oneof = extractBraceDelimitedBlock(
    message,
    `oneof ${oneofName}`,
    messageName,
    fail,
  );
  return [...oneof.matchAll(
    /\b[A-Za-z_][A-Za-z0-9_.]*\s+([a-z][a-z0-9_]*)\s*=\s*([0-9]+)\s*;/gu,
  )].map((match) => `${match[1]}=${match[2]}`);
};

export const assertProtoOperationResultsMatchRequests = ({ readText, fail }) => {
  const source = readText(cryptoProtoPath);
  assertSameSet(
    extractProtoOperationFields(source, "CryptoOperationResult", "result", fail),
    extractProtoOperationFields(source, "CryptoOperationRequest", "operation", fail),
    "CryptoOperationRequest/CryptoOperationResult branch and field-number parity",
    fail,
  );
};

export const extractOperationResponseRouteSymbols = (source, fail) => {
  const processFunction = extractBraceDelimitedBlock(
    source,
    "fn process_operation_request",
    "Rust operation-response operation dispatcher",
    fail,
  );
  const operationMatch = extractBraceDelimitedBlock(
    processFunction,
    "match operation",
    "Rust operation-response operation dispatcher",
    fail,
  );
  const declaredVariants = [...operationMatch.matchAll(/\bCryptoOperation::([A-Za-z0-9_]+)\s*\(/gu)]
    .map((match) => match[1]);
  const routes = [];
  const handledVariants = [];

  for (const match of operationMatch.matchAll(
    /CryptoOperation::([A-Za-z0-9_]+)\(request\)\s*=>\s*(?:(?!CryptoOperation::)[\s\S])*?process_(?:encoded_)?request\(\s*\*request\s*,\s*(process_[a-z0-9_]+)\s*,/gu,
  )) {
    handledVariants.push(match[1]);
    routes.push(`CryptoOperation::${match[1]} => ${match[2]}`);
  }

  for (const match of operationMatch.matchAll(
    /CryptoOperation::([A-Za-z0-9_]+)\(request\)\s*=>\s*(?:\{\s*)?(process_[a-z0-9_]+_request)\(\s*\*request\s*\)/gu,
  )) {
    const semanticHandler = match[2].replace(/_request$/u, "");
    handledVariants.push(match[1]);
    routes.push(`CryptoOperation::${match[1]} => ${semanticHandler}`);
  }

  for (const match of operationMatch.matchAll(
    /((?:\s*(?:\|\s*)?CryptoOperation::[A-Za-z0-9_]+\([^)]*\)\s*)+)=>\s*unsupported_response\(\)/gu,
  )) {
    for (const variant of match[1].matchAll(/CryptoOperation::([A-Za-z0-9_]+)/gu)) {
      handledVariants.push(variant[1]);
      routes.push(`CryptoOperation::${variant[1]} => unsupported_algorithm`);
    }
  }

  assertSameSet(
    handledVariants,
    declaredVariants,
    "Rust operation-response branch parser coverage",
    fail,
  );
  return routes;
};

export const assertProtoOperationsMatchLedger = ({ ledger, readText, fail }) => {
  const source = readText(cryptoProtoPath);
  assertSameSet(
    extractProtoOperationRouteSymbols(source, fail),
    ledgerSymbolsForGroup(ledger, "protobuf.crypto_operation_request.oneof", fail),
    "CryptoOperationRequest operation ledger",
    fail,
  );
};

export const assertOperationResponseBranchesMatchLedger = ({ ledger, readText, fail }) => {
  const source = readText("crates/crypto/src/operation_contract/request.rs");
  assertSameSet(
    extractOperationResponseRouteSymbols(source, fail),
    ledgerSymbolsForGroup(ledger, "rust.operation_response.branches", fail),
    "Rust operation-response branch ledger",
    fail,
  );
};

const extractRustPublicUseFunctions = (source) => {
  const names = [];
  for (const match of source.matchAll(/\bpub\s+use\s+[A-Za-z_][A-Za-z0-9_:]*::\{([\s\S]*?)\}\s*;/gu)) {
    for (const entry of match[1].split(",")) {
      const name = entry.trim().split(/\s+as\s+/u)[0];
      if (/^[a-z_][A-Za-z0-9_]*$/u.test(name)) {
        names.push(name);
      }
    }
  }
  for (const match of source.matchAll(
    /\bpub\s+use\s+[A-Za-z_][A-Za-z0-9_:]*::([a-z_][A-Za-z0-9_]*)(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?\s*;/gu,
  )) {
    names.push(match[1]);
  }
  return names;
};

const extractRustPublicFunctions = (source) => [
  ...source.matchAll(/\bpub\s+(?:async\s+)?fn\s+([a-z_][A-Za-z0-9_]*)\s*\(/gu),
].map((match) => match[1]);

const hiddenSymbolsForGroup = (ledger, groupId, fail) => {
  const group = routeGroupById(ledger, fail).get(groupId);
  if (group === undefined) {
    fail(`operation route ledger is missing ${groupId}`);
  }
  return requireArray(
    group.intentionally_hidden_symbols ?? [],
    `${groupId}.intentionally_hidden_symbols`,
    fail,
  ).map((entry) => requireString(entry.symbol, `${groupId} hidden symbol`, fail));
};

const rootOnlySymbolsForGroup = (ledger, groupId, fail) => {
  const group = routeGroupById(ledger, fail).get(groupId);
  if (group === undefined) {
    fail(`operation route ledger is missing ${groupId}`);
  }
  return requireArray(
    group.root_only_symbols ?? [],
    `${groupId}.root_only_symbols`,
    fail,
  ).map((entry) => requireString(entry.symbol, `${groupId} root-only symbol`, fail));
};

export const assertRustDispatchExportsMatchLedger = ({ ledger, readText, fail }) => {
  const dispatchExports = extractRustPublicUseFunctions(
    readText("crates/crypto/dispatch/src/lib.rs"),
  );
  assertSameSet(
    dispatchExports,
    ledgerSymbolsForGroup(ledger, "rust.dispatch.exports", fail),
    "Rust dispatch public function ledger",
    fail,
  );

  const rootSource = readText("crates/crypto/src/lib.rs");
  const rootDispatchModule = /\bpub\s+mod\s+dispatch\s*;/u.test(rootSource)
    ? readText(localRustModulePath("dispatch", fail))
    : extractBraceDelimitedBlock(
        rootSource,
        "pub mod dispatch",
        "root Rust dispatch facade",
        fail,
      );
  const rootExports = [
    ...extractRustPublicUseFunctions(rootDispatchModule),
    ...extractRustPublicFunctions(rootDispatchModule),
  ];
  const rootLedgerExports = ledgerSymbolsForGroup(ledger, "rust.root.dispatch.exports", fail)
    .map((symbol) => symbol.replace(/^dispatch::/u, ""));
  const hiddenExports = hiddenSymbolsForGroup(ledger, "rust.root.dispatch.exports", fail)
    .map((symbol) => symbol.replace(/^dispatch::/u, ""));
  const rootOnlyExports = rootOnlySymbolsForGroup(ledger, "rust.root.dispatch.exports", fail)
    .map((symbol) => symbol.replace(/^dispatch::/u, ""));
  assertSameSet(rootExports, rootLedgerExports, "root Rust dispatch facade ledger", fail);
  assertSameSet(
    dispatchExports,
    [
      ...rootLedgerExports.filter((symbol) => !rootOnlyExports.includes(symbol)),
      ...hiddenExports,
    ],
    "root Rust dispatch hidden-route ledger",
    fail,
  );
};

const localRustModulePath = (moduleName, fail) => {
  const filePath = `crates/crypto/src/${moduleName}.rs`;
  if (existsSync(filePath)) {
    return filePath;
  }
  const modulePath = `crates/crypto/src/${moduleName}/mod.rs`;
  if (existsSync(modulePath)) {
    return modulePath;
  }
  fail(`root Rust facade declares ${moduleName}, but no local module source exists`);
};

export const assertRootStructuredRoutesMatchLedger = ({
  ledger,
  readText,
  fail,
  modulePaths,
}) => {
  const structuredModuleNames = new Set([
    "operation_contract",
    "operation_response",
    "operation_response",
  ]);
  const modules = modulePaths ?? [...readText("crates/crypto/src/lib.rs")
    .matchAll(/\bpub\s+mod\s+([a-z_][A-Za-z0-9_]*)\s*;/gu)]
    .filter((match) => structuredModuleNames.has(match[1]))
    .map((match) => ({
      moduleName: match[1],
      path: localRustModulePath(match[1], fail),
    }));
  const routes = [];
  for (const { moduleName, path } of modules) {
    requireString(moduleName, "root Rust structured module name", fail);
    requireString(path, `root Rust structured module ${moduleName} path`, fail);
    const source = readText(path);
    const functions = [
      ...extractRustPublicFunctions(source),
      ...extractRustPublicUseFunctions(source),
    ];
    for (const functionName of sortedUnique(functions)) {
      routes.push(`${moduleName}::${functionName}`);
    }
  }
  assertSameSet(
    routes,
    ledgerSymbolsForGroup(ledger, "rust.root.operation_contract", fail),
    "root Rust structured operation route ledger",
    fail,
  );
};

const assertCAbiExportsMatchLedger = ({ ledger, readText, fail }) => {
  const header = readText("crates/ffi/abi/reallyme_crypto_ffi.h");
  const headerSymbols = [...header.matchAll(/\brm_crypto_status_t\s+(rm_crypto_[a-z0-9_]+)\s*\(/g)].map(
    (match) => match[1],
  );
  assertSameSet(headerSymbols, ledgerSymbolsForGroup(ledger, "c_abi.exports", fail), "C ABI operation ledger", fail);
};

export const assertJniExportsMatchLedger = ({ ledger, readText, fail, sourcePaths }) => {
  const exportedNames = [];
  for (const path of sourcePaths ?? listSourceFiles(ffiSourceRoot, ".rs", fail)) {
    const source = readText(path);
    for (const match of source.matchAll(
      /\bpub\s+(?:unsafe\s+)?extern\s+"system"\s+fn\s+(Java_[A-Za-z0-9_]+)/gu,
    )) {
      exportedNames.push(match[1]);
    }
  }
  assertSameSet(exportedNames, ledgerSymbolsForGroup(ledger, "jni.exports", fail), "JNI export ledger", fail);
};

export const assertWasmExportsMatchLedger = ({ ledger, readText, fail, sourcePaths }) => {
  const exportedNames = [];
  for (const path of sourcePaths ?? listSourceFiles(wasmPackageSourceRoot, ".rs", fail)) {
    const source = readText(path);
    for (const match of source.matchAll(/#\[\s*wasm_bindgen\([^)]*\bjs_name\s*=\s*([A-Za-z0-9_]+)[^)]*\)\s*\]/g)) {
      const functionStart = source.indexOf("pub fn", match.index + match[0].length);
      const exportAttributes = functionStart === -1
        ? ""
        : source.slice(match.index, functionStart);
      if (exportAttributes.includes('#[cfg(feature = "test-vectors")]')) {
        continue;
      }
      exportedNames.push(match[1]);
    }
  }
  const ledgerExports = ledgerSymbolsForGroup(ledger, "wasm.exports", fail);
  assertSameSet(exportedNames, ledgerExports, "wasm-bindgen public export ledger", fail);

  const moduleTypes = readText("packages/ts/src/wasmModuleTypes.ts");
  const declaredExports = [...moduleTypes.matchAll(/\bexport\s+declare\s+function\s+([A-Za-z0-9_]+)\s*\(/g)]
    .map((match) => match[1])
    .filter((name) => name !== "initSync");
  assertSameSet(declaredExports, ledgerExports, "TypeScript wasm module declaration ledger", fail);
};

export const assertNoHandWrittenStructuredJsonContract = ({ readText, fail, sourcePaths }) => {
  const checkedFiles = sourcePaths ?? [
    "crates/crypto/src/operation_contract/request.rs",
    "crates/ffi/src/operation_response.rs",
    "crates/wasm/src/operation_response.rs",
    "packages/ts/src/operationResponse.ts",
    "packages/ts/src/cryptoFacade.ts",
    "packages/ts/src/wasmProvider.ts",
    "packages/swift/Sources/ReallyMeCrypto/OperationResponse.swift",
    "packages/kotlin/src/main/kotlin/me/really/crypto/CryptoFacade.kt",
    "packages/kotlin/src/main/kotlin/me/really/crypto/OperationResponse.kt",
    ...listSourceFiles("crates/crypto/src/operation_contract", ".rs", fail),
  ];
  for (const path of checkedFiles) {
    const source = readText(path);
    const forbiddenJsonApis = [
      ["JavaScript JSON parsing or serialization", /\bJSON\s*(?:\.\s*(?:parse|stringify)\b|\[\s*["'](?:parse|stringify)["']\s*\])/u],
      ["Rust serde_json", /\bserde_json\s*::/u],
      ["Swift JSON serialization", /\b(?:JSONSerialization|JSONDecoder|JSONEncoder)\b/u],
      ["Kotlin/Java JSON serialization", /\b(?:JSONObject|ObjectMapper|Gson|kotlinx\.serialization\.json)\b/u],
    ];
    for (const [description, pattern] of forbiddenJsonApis) {
      if (pattern.test(source)) {
        fail(`${path} must not define a hand-written structured operation JSON contract with ${description}`);
      }
    }
  }
};

export const assertHashSemanticOwnership = ({
  readText,
  fail,
  pathExists = existsSync,
}) => {
  const requiredRoutes = [
    ["crates/crypto/src/dispatch.rs", "crate::operations::hash::digest"],
    ["crates/crypto/src/sha2.rs", "crate::operations::hash::sha2_256"],
    ["crates/crypto/src/sha2.rs", "crate::operations::hash::sha2_384"],
    ["crates/crypto/src/sha2.rs", "crate::operations::hash::sha2_512"],
    ["crates/crypto/src/sha3.rs", "crate::operations::hash::sha3_224"],
    ["crates/crypto/src/sha3.rs", "crate::operations::hash::sha3_256"],
    ["crates/crypto/src/sha3.rs", "crate::operations::hash::sha3_384"],
    ["crates/crypto/src/sha3.rs", "crate::operations::hash::sha3_512"],
    ["crates/crypto/src/operation_contract/operations.rs", "crate::operations::hash::digest"],
    ["crates/ffi/src/sha2_256.rs", "reallyme_crypto::operations::hash::sha2_256"],
    ["crates/ffi/src/sha2.rs", "reallyme_crypto::operations::hash::sha2_384"],
    ["crates/ffi/src/sha2.rs", "reallyme_crypto::operations::hash::sha2_512"],
    ["crates/ffi/src/sha3.rs", "reallyme_crypto::operations::hash::sha3_224"],
    ["crates/ffi/src/sha3_256.rs", "reallyme_crypto::operations::hash::sha3_256"],
    ["crates/ffi/src/sha3.rs", "reallyme_crypto::operations::hash::sha3_384"],
    ["crates/ffi/src/sha3.rs", "reallyme_crypto::operations::hash::sha3_512"],
    ["crates/ffi/src/constant_time.rs", "reallyme_crypto::operations::constant_time::equal"],
  ];

  for (const [path, required] of requiredRoutes) {
    if (!readText(path).includes(required)) {
      fail(`${path} must route hash and constant-time behavior through ${required}`);
    }
  }

  const forbiddenDirectHashCalls = [
    ["crates/ffi/src/sha2_256.rs", "crypto_sha2_256::digest"],
    ["crates/ffi/src/sha2.rs", "crypto_sha2::digest_sha2_"],
    ["crates/ffi/src/sha3_256.rs", "crypto_sha3_256::digest"],
    ["crates/ffi/src/sha3.rs", "crypto_sha3::digest_sha3_"],
  ];
  for (const [path, forbidden] of forbiddenDirectHashCalls) {
    if (readText(path).includes(forbidden)) {
      fail(`${path} retains direct hash and constant-time primitive semantics through ${forbidden}`);
    }
  }

  if (pathExists("crates/crypto/dispatch/src/hash.rs")) {
    fail("the published dispatch crate retains the removed hash selector");
  }

  const hashProductionDocumentationPaths = [
    "crates/crypto/src/lib.rs",
    "crates/crypto/src/operations/hash.rs",
    "crates/crypto/src/operations/constant_time.rs",
    "crates/crypto/dispatch/src/lib.rs",
    "crates/crypto/dispatch/src/registry/signature.rs",
    "crates/ffi/src/lib.rs",
    "crates/ffi/src/sha2.rs",
    "crates/ffi/src/sha2_256.rs",
    "crates/ffi/src/sha3.rs",
    "crates/ffi/src/sha3_256.rs",
    "crates/ffi/src/constant_time.rs",
  ];
  const inlineDocumentationTest = /(?:^|\n)\s*\/\/[\/!]?\s*```(?:rust(?:,[a-z_-]+)*)?\s*(?:\n|$)/u;
  for (const path of hashProductionDocumentationPaths) {
    if (inlineDocumentationTest.test(readText(path))) {
      fail(`${path} must keep compile-checked examples in a separate README or documentation file`);
    }
  }
};

export const assertMacSemanticOwnership = ({
  readText,
  fail,
  pathExists = existsSync,
}) => {
  const requiredRoutes = [
    ["crates/crypto/src/dispatch.rs", "crate::operations::mac::authenticate"],
    ["crates/crypto/src/dispatch.rs", "crate::operations::mac::verify"],
    ["crates/crypto/src/hmac.rs", "crate::operations::mac::authenticate_tag"],
    ["crates/crypto/src/hmac.rs", "crate::operations::mac::verify"],
    ["crates/crypto/src/operation_contract/operations.rs", "crate::operations::mac::authenticate"],
    ["crates/crypto/src/operation_contract/operations.rs", "crate::operations::mac::verify"],
    ["crates/ffi/src/hmac.rs", "reallyme_crypto::hmac"],
  ];

  for (const [path, required] of requiredRoutes) {
    if (!readText(path).includes(required)) {
      fail(`${path} must route MAC behavior through ${required}`);
    }
  }

  if (readText("crates/ffi/src/hmac.rs").includes("crypto_hmac::")) {
    fail("crates/ffi/src/hmac.rs retains direct MAC primitive semantics through crypto_hmac");
  }

  const requiredMacCleanup = [
    ["CryptoMacAuthenticateRequest", ["key", "message"]],
    ["CryptoMacVerifyRequest", ["key", "message", "tag"]],
  ];
  for (const [typeName, fields] of requiredMacCleanup) {
    assertGeneratedDropZeroizesFields({ readText, fail, area: "MAC", typeName, fields });
  }

  const kotlinHmac = readText("packages/kotlin/src/main/kotlin/me/really/crypto/Hmac.kt");
  if (!kotlinHmac.includes("expectedTag.fill(0)")) {
    fail("MAC Kotlin HMAC verification must clear its temporary expected tag");
  }

  const typeScriptHmac = readText("packages/ts/src/hmac.ts");
  if (!typeScriptHmac.includes("expectedTag.fill(0)")) {
    fail("MAC TypeScript HMAC verification must clear its temporary expected tag");
  }

  const swiftHmac = readText("packages/swift/Sources/ReallyMeCrypto/Hmac.swift");
  if (!swiftHmac.includes("isValidAuthenticationCode")) {
    fail("MAC Swift HMAC verification must delegate comparison to CryptoKit");
  }

  const removedCompatibilityPaths = [
    "crates/crypto/dispatch/src/mac.rs",
    "crates/crypto/dispatch/src/algorithms/hmac.rs",
  ];
  for (const path of removedCompatibilityPaths) {
    if (pathExists(path)) {
      fail(`${path} retains the superseded MAC selector`);
    }
  }

  const dispatchCargo = readText("crates/crypto/dispatch/Cargo.toml");
  if (dispatchCargo.includes("dep:crypto-hmac") || dispatchCargo.includes("crypto-hmac =")) {
    fail("the published dispatch crate retains the removed MAC HMAC primitive dependency");
  }

  const macProductionDocumentationPaths = [
    "crates/crypto/src/dispatch.rs",
    "crates/crypto/src/hmac.rs",
    "crates/crypto/src/operations/mac.rs",
    "crates/crypto/src/operation_contract/operations.rs",
    generatedCryptoRustPath,
    "crates/crypto/dispatch/src/lib.rs",
    "crates/ffi/src/hmac.rs",
  ];
  const inlineDocumentationTest = /(?:^|\n)\s*\/\/[\/!]?\s*```(?:rust(?:,[a-z_-]+)*)?\s*(?:\n|$)/u;
  for (const path of macProductionDocumentationPaths) {
    if (inlineDocumentationTest.test(readText(path))) {
      fail(`${path} must keep compile-checked examples in a separate README or documentation file`);
    }
  }
};

export const assertAeadSemanticOwnership = ({
  readText,
  fail,
  pathExists = existsSync,
}) => {
  const requiredRoutes = [
    ["crates/crypto/src/dispatch.rs", "crate::operations::aead::seal"],
    ["crates/crypto/src/dispatch.rs", "crate::operations::aead::open"],
    ["crates/crypto/src/aes.rs", "crate::operations::aead::seal"],
    ["crates/crypto/src/aes.rs", "crate::operations::aead::open"],
    ["crates/crypto/src/aes_gcm_siv.rs", "crate::operations::aead::seal"],
    ["crates/crypto/src/aes_gcm_siv.rs", "crate::operations::aead::open"],
    ["crates/crypto/src/chacha20_poly1305.rs", "crate::operations::aead::seal"],
    ["crates/crypto/src/chacha20_poly1305.rs", "crate::operations::aead::open"],
    ["crates/crypto/src/operation_contract/operations.rs", "crate::operations::aead::seal"],
    ["crates/crypto/src/operation_contract/operations.rs", "crate::operations::aead::open"],
    ["crates/ffi/src/aes256_gcm/encrypt.rs", "reallyme_crypto::aes"],
    ["crates/ffi/src/aes256_gcm/decrypt.rs", "reallyme_crypto::aes"],
    ["crates/ffi/src/aes256_gcm/mod.rs", "reallyme_crypto::aes"],
    ["crates/ffi/src/aes256_gcm_siv.rs", "reallyme_crypto::aes_gcm_siv"],
    ["crates/ffi/src/chacha20_poly1305.rs", "reallyme_crypto::chacha20_poly1305"],
    ["crates/ffi/src/aes256_gcm/encrypt.rs", "reallyme_crypto::operations::aead::seal"],
    ["crates/ffi/src/aes256_gcm_siv.rs", "reallyme_crypto::operations::aead::seal"],
    ["crates/ffi/src/chacha20_poly1305.rs", "reallyme_crypto::operations::aead::seal"],
    ["crates/ffi/src/aes256_gcm/decrypt.rs", "reallyme_crypto::operations::aead::open"],
    ["crates/ffi/src/aes256_gcm_siv.rs", "reallyme_crypto::operations::aead::open"],
    ["crates/ffi/src/chacha20_poly1305.rs", "reallyme_crypto::operations::aead::open"],
    ["crates/wasm/src/aead.rs", "crypto_runtime::aes"],
    ["crates/wasm/src/aead.rs", "crypto_runtime::aes_gcm_siv"],
    ["crates/wasm/src/aead.rs", "crypto_runtime::chacha20_poly1305"],
  ];

  for (const [path, required] of requiredRoutes) {
    if (!readText(path).includes(required)) {
      fail(`${path} must route AEAD behavior through ${required}`);
    }
  }

  const forbiddenDirectAeadImports = [
    ["crates/ffi/src/aes256_gcm/encrypt.rs", "crypto_aes256_gcm::"],
    ["crates/ffi/src/aes256_gcm/decrypt.rs", "crypto_aes256_gcm::"],
    ["crates/ffi/src/aes256_gcm/mod.rs", "crypto_aes256_gcm::"],
    ["crates/ffi/src/aes256_gcm_siv.rs", "crypto_aes256_gcm_siv::"],
    ["crates/ffi/src/chacha20_poly1305.rs", "crypto_chacha20_poly1305::"],
    ["crates/wasm/src/aead.rs", "crypto_aes256_gcm::"],
    ["crates/wasm/src/aead.rs", "crypto_aes256_gcm_siv::"],
    ["crates/wasm/src/aead.rs", "crypto_chacha20_poly1305::"],
  ];
  for (const [path, forbidden] of forbiddenDirectAeadImports) {
    if (readText(path).includes(forbidden)) {
      fail(`${path} retains direct AEAD primitive semantics through ${forbidden}`);
    }
  }

  const removedCompatibilityPaths = [
    "crates/crypto/dispatch/src/registry/aead.rs",
    "crates/crypto/dispatch/src/algorithms/aes256_gcm.rs",
    "crates/crypto/dispatch/src/algorithms/aes256_gcm_siv.rs",
    "crates/crypto/dispatch/src/algorithms/chacha20_poly1305.rs",
  ];
  for (const path of removedCompatibilityPaths) {
    if (pathExists(path)) {
      fail(`${path} retains the superseded AEAD selector`);
    }
  }

  const dispatchCargo = readText("crates/crypto/dispatch/Cargo.toml");
  const forbiddenDispatchDependencies = [
    "dep:crypto-aes256-gcm",
    "dep:crypto-aes256-gcm-siv",
    "dep:crypto-chacha20-poly1305",
    "crypto-aes256-gcm =",
    "crypto-aes256-gcm-siv =",
    "crypto-chacha20-poly1305 =",
  ];
  for (const dependency of forbiddenDispatchDependencies) {
    if (dispatchCargo.includes(dependency)) {
      fail(`the published dispatch crate retains the removed AEAD primitive dependency ${dependency}`);
    }
  }

  const zeroizingOpenRoutes = [
    ["crates/ffi/src/aes256_gcm/decrypt.rs", 3],
    ["crates/ffi/src/aes256_gcm_siv.rs", 1],
    ["crates/ffi/src/chacha20_poly1305.rs", 2],
  ];
  for (const [path, expectedCount] of zeroizingOpenRoutes) {
    const source = readText(path);
    const actualCount = source.split("reallyme_crypto::operations::aead::open").length - 1;
    if (actualCount !== expectedCount) {
      fail(`${path} must obtain every FFI plaintext from the zeroizing AEAD operation owner`);
    }
  }

  const requiredAeadCleanup = [
    ["CryptoAeadSealRequest", ["key", "plaintext"]],
    ["CryptoAeadOpenRequest", ["key"]],
    ["CryptoAeadOpenResult", ["plaintext"]],
  ];
  for (const [typeName, fields] of requiredAeadCleanup) {
    assertGeneratedDropZeroizesFields({ readText, fail, area: "AEAD", typeName, fields });
  }
};

export const assertKeyWrapSemanticOwnership = ({
  readText,
  fail,
}) => {
  const requiredRoutes = [
    ["crates/crypto/src/aes_kw.rs", "crate::operations::key_wrap::wrap_key"],
    ["crates/crypto/src/aes_kw.rs", "crate::operations::key_wrap::unwrap_key"],
    ["crates/crypto/src/operation_contract/operations.rs", "crate::operations::key_wrap::wrap_key"],
    ["crates/crypto/src/operation_contract/operations.rs", "crate::operations::key_wrap::unwrap_key"],
    ["crates/ffi/src/aes_kw.rs", "reallyme_crypto::operations::key_wrap::wrap_key"],
    ["crates/ffi/src/aes_kw.rs", "reallyme_crypto::operations::key_wrap::unwrap_key"],
    ["crates/wasm/src/key_wrap.rs", "crypto_runtime::operations::key_wrap::wrap_key"],
    ["crates/wasm/src/key_wrap.rs", "crypto_runtime::operations::key_wrap::unwrap_key"],
  ];

  for (const [path, required] of requiredRoutes) {
    if (!readText(path).includes(required)) {
      fail(`${path} must route AES-KW behavior through ${required}`);
    }
  }

  const forbiddenDirectKeyWrapSemantics = [
    ["crates/crypto/src/operation_contract/operations.rs", "crate::aes_kw::"],
    ["crates/ffi/Cargo.toml", "crypto-aes-kw"],
    ["crates/ffi/src/aes_kw.rs", "use crypto_aes_kw"],
    ["crates/ffi/src/aes_kw.rs", "wrap_key_aes128"],
    ["crates/ffi/src/aes_kw.rs", "wrap_key_aes192"],
    ["crates/ffi/src/aes_kw.rs", "wrap_key_aes256"],
    ["crates/ffi/src/aes_kw.rs", "unwrap_key_aes128"],
    ["crates/ffi/src/aes_kw.rs", "unwrap_key_aes192"],
    ["crates/ffi/src/aes_kw.rs", "unwrap_key_aes256"],
    ["crates/ffi/src/aes_kw.rs", "Aes128KwKek"],
    ["crates/ffi/src/aes_kw.rs", "Aes192KwKek"],
    ["crates/ffi/src/aes_kw.rs", "Aes256KwKek"],
    ["crates/wasm/src/key_wrap.rs", "use crypto_aes_kw"],
    ["crates/wasm/src/key_wrap.rs", "wrap_key_aes128"],
    ["crates/wasm/src/key_wrap.rs", "wrap_key_aes192"],
    ["crates/wasm/src/key_wrap.rs", "wrap_key_aes256"],
    ["crates/wasm/src/key_wrap.rs", "unwrap_key_aes128"],
    ["crates/wasm/src/key_wrap.rs", "unwrap_key_aes192"],
    ["crates/wasm/src/key_wrap.rs", "unwrap_key_aes256"],
    ["crates/wasm/src/key_wrap.rs", "Aes128KwKek"],
    ["crates/wasm/src/key_wrap.rs", "Aes192KwKek"],
    ["crates/wasm/src/key_wrap.rs", "Aes256KwKek"],
  ];
  for (const [path, forbidden] of forbiddenDirectKeyWrapSemantics) {
    if (readText(path).includes(forbidden)) {
      fail(`${path} retains direct AES-KW primitive semantics through ${forbidden}`);
    }
  }

  const requiredKeyWrapCleanup = [
    ["CryptoKeyWrapRequest", ["wrapping_key", "key_to_wrap"]],
    ["CryptoKeyWrapResult", ["wrapped_key"]],
    ["CryptoKeyUnwrapRequest", ["wrapping_key"]],
    ["CryptoKeyUnwrapResult", ["key"]],
  ];
  for (const [typeName, fields] of requiredKeyWrapCleanup) {
    assertGeneratedDropZeroizesFields({ readText, fail, area: "AES-KW", typeName, fields });
  }
};

export const assertKdfSemanticOwnership = ({
  readText,
  fail,
}) => {
  const requiredRoutes = [
    ["crates/crypto/src/argon2id.rs", "crate::operations::kdf::derive_argon2id"],
    ["crates/crypto/src/pbkdf2.rs", "crate::operations::kdf::derive_pbkdf2"],
    ["crates/crypto/src/hkdf.rs", "crate::operations::kdf::derive_hkdf"],
    ["crates/crypto/src/kmac.rs", "crate::operations::kdf::derive_kmac256"],
    ["crates/crypto/src/concat_kdf.rs", "crate::operations::kdf::derive_jwa_concat_kdf_sha256"],
    ["crates/crypto/src/operation_contract/kdf.rs", "crate::operations::kdf::derive_kmac256"],
    ["crates/crypto/src/operation_contract/kdf.rs", "crate::operations::kdf::derive_hkdf"],
    ["crates/crypto/src/operation_contract/kdf.rs", "crate::operations::kdf::derive_pbkdf2_from_raw"],
    ["crates/crypto/src/operation_contract/kdf.rs", "crate::operations::kdf::derive_jwa_concat_kdf_sha256"],
    ["crates/ffi/src/argon2id.rs", "reallyme_crypto::operations::kdf::derive_argon2id"],
    ["crates/ffi/src/pbkdf2.rs", "reallyme_crypto::operations::kdf::derive_pbkdf2_from_raw"],
    ["crates/ffi/src/hkdf.rs", "reallyme_crypto::operations::kdf::derive_hkdf"],
    ["crates/ffi/src/kmac.rs", "reallyme_crypto::operations::kdf::derive_kmac256"],
  ];

  for (const [path, required] of requiredRoutes) {
    if (!readText(path).includes(required)) {
      fail(`${path} must route KDF behavior through ${required}`);
    }
  }

  const forbiddenDirectKdfSemantics = [
    ["crates/ffi/src/argon2id.rs", "crypto_argon2id::derive_key"],
    ["crates/ffi/src/pbkdf2.rs", "crypto_pbkdf2::derive_key"],
    ["crates/ffi/src/hkdf.rs", "crypto_hkdf::derive"],
    ["crates/ffi/src/kmac.rs", "crypto_kmac::derive_kmac256"],
    ["crates/crypto/src/operation_contract/operations.rs", "CryptoKmac256DeriveRequest"],
    ["crates/crypto/src/operation_contract/operations.rs", "CryptoHkdfDeriveRequest"],
    ["crates/crypto/src/operation_contract/operations.rs", "CryptoKdfDeriveKeyRequest"],
    ["crates/crypto/src/operation_contract/operations.rs", "CryptoJwaConcatKdfSha256DeriveRequest"],
  ];
  for (const [path, forbidden] of forbiddenDirectKdfSemantics) {
    if (readText(path).includes(forbidden)) {
      fail(`${path} retains direct KDF primitive semantics through ${forbidden}`);
    }
  }

  const prevalidationChecks = [
    ["crates/ffi/src/argon2id.rs", "reallyme_crypto::operations::kdf::derive_argon2id"],
    ["crates/ffi/src/pbkdf2.rs", "reallyme_crypto::operations::kdf::derive_pbkdf2_from_raw"],
    ["crates/ffi/src/hkdf.rs", "derive_to_output::<16>"],
    ["crates/ffi/src/kmac.rs", "reallyme_crypto::operations::kdf::derive_kmac256"],
  ];
  for (const [path, executionMarker] of prevalidationChecks) {
    const source = readText(path);
    const preflight = source.indexOf("let output_status = unsafe { write_fixed(");
    const execution = source.indexOf(executionMarker);
    if (preflight < 0 || execution < 0 || preflight > execution || !source.includes("&[]")) {
      fail(`${path} must prevalidate output pointers before KDF execution`);
    }
  }

  const requiredKdfCleanup = [
    ["CryptoKmac256DeriveRequest", ["key", "context", "customization"]],
    ["CryptoKmac256DeriveResult", ["derived_key"]],
    ["CryptoHkdfDeriveRequest", ["input_key_material", "salt", "info"]],
    ["CryptoHkdfDeriveResult", ["output_key_material"]],
    ["CryptoKdfDeriveKeyRequest", ["password", "salt"]],
    ["CryptoKdfDeriveKeyResult", ["derived_key"]],
    ["CryptoJwaConcatKdfSha256DeriveRequest", ["shared_secret", "algorithm_id", "party_u_info", "party_v_info"]],
    ["CryptoJwaConcatKdfSha256DeriveResult", ["derived_key"]],
  ];
  for (const [typeName, fields] of requiredKdfCleanup) {
    assertGeneratedDropZeroizesFields({ readText, fail, area: "KDF", typeName, fields });
  }

  assertContainsKdf(
    readText,
    fail,
    "crates/hkdf/src/derive.rs",
    "SimpleHkdf::<Sha3_256>",
    "audited generic HKDF-SHA3 implementation",
  );
  const hkdfSource = readText("crates/hkdf/src/derive.rs");
  for (const forbidden of ["fn hmac_sha3_256", "fn derive_sha3_256"]) {
    if (hkdfSource.includes(forbidden)) {
      fail(`crates/hkdf/src/derive.rs retains custom HKDF-SHA3 semantics through ${forbidden}`);
    }
  }
  assertContainsKdf(
    readText,
    fail,
    "crates/pbkdf2/src/constants.rs",
    "PBKDF2_MODERN_MIN_ITERATIONS",
    "PBKDF2 modern policy constant",
  );
  assertContainsKdf(
    readText,
    fail,
    "crates/crypto/src/operations/kdf.rs",
    "Pbkdf2Iterations::from_u32_modern",
    "PBKDF2 modern policy constructor",
  );
  assertContainsKdf(
    readText,
    fail,
    "Cargo.lock",
    "7b6b86fb906e40929519c1a38dc349a7f5595778cc00cc20b55eec34fddeb9ec",
    "pinned KMAC dependency checksum",
  );
  assertContainsKdf(
    readText,
    fail,
    "packages/swift/Sources/ReallyMeCrypto/Pbkdf2.swift",
    "clear(&derived)",
    "Swift accumulated PBKDF2 output cleanup",
  );
  assertContainsKdf(
    readText,
    fail,
    "packages/swift/Tests/ReallyMeCryptoTests/Pbkdf2SecurityTests.swift",
    "testProviderFailureClearsPreviouslyAccumulatedOutput",
    "Swift injectable PBKDF2 cleanup regression test",
  );
  assertContainsKdf(
    readText,
    fail,
    "packages/kotlin/src/main/kotlin/me/really/crypto/Pbkdf2.kt",
    "iterations > MAX_ITERATIONS",
    "Kotlin PBKDF2 checked provider range",
  );
  assertContainsKdf(
    readText,
    fail,
    "packages/kotlin/src/test/kotlin/me/really/crypto/ReallyMeCryptoTest.kt",
    "pbkdf2IterationConversionEnforcesPublicWorkBounds",
    "Kotlin PBKDF2 work-factor boundary test",
  );
  assertContainsKdf(
    readText,
    fail,
    "packages/ts/src/pbkdf2.ts",
    "PBKDF2_MIN_ITERATIONS = 100_000",
    "TypeScript PBKDF2 modern policy floor",
  );
};

const assertContainsKdf = (readText, fail, path, required, description) => {
  if (!readText(path).includes(required)) {
    fail(`${path} must contain ${description}`);
  }
};

export const assertSignatureSemanticOwnership = ({
  readText,
  fail,
}) => {
  const requiredRoutes = [
    ["crates/crypto/src/operations/signature.rs", "crypto_dispatch::generate_keypair"],
    ["crates/crypto/src/operations/signature.rs", "crypto_dispatch::derive_keypair"],
    ["crates/crypto/src/operations/signature.rs", "crypto_dispatch::sign"],
    ["crates/crypto/src/operations/signature.rs", "crypto_dispatch::verify"],
    ["crates/crypto/src/operations/signature.rs", "is_supported_signature_algorithm"],
    ["crates/crypto/src/ed25519.rs", "crate::operations::signature::generate_key_pair"],
    ["crates/crypto/src/ed25519.rs", "crate::operations::signature::derive_key_pair"],
    ["crates/crypto/src/ed25519.rs", "crate::operations::signature::sign"],
    ["crates/crypto/src/p256.rs", "crate::operations::signature::generate_key_pair"],
    ["crates/crypto/src/p256.rs", "crate::operations::signature::derive_key_pair"],
    ["crates/crypto/src/p256.rs", "crate::operations::signature::sign"],
    ["crates/crypto/src/p384.rs", "crate::operations::signature::generate_key_pair"],
    ["crates/crypto/src/p384.rs", "crate::operations::signature::derive_key_pair"],
    ["crates/crypto/src/p384.rs", "crate::operations::signature::sign"],
    ["crates/crypto/src/p521.rs", "crate::operations::signature::generate_key_pair"],
    ["crates/crypto/src/p521.rs", "crate::operations::signature::derive_key_pair"],
    ["crates/crypto/src/p521.rs", "crate::operations::signature::sign"],
    ["crates/crypto/src/secp256k1.rs", "crate::operations::signature::generate_key_pair"],
    ["crates/crypto/src/secp256k1.rs", "crate::operations::signature::derive_key_pair"],
    ["crates/crypto/src/secp256k1.rs", "crate::operations::signature::sign"],
    ["crates/crypto/src/operation_contract/signature.rs", "crate::operations::signature::generate_key_pair"],
    ["crates/crypto/src/operation_contract/signature.rs", "crate::operations::signature::derive_key_pair"],
    ["crates/crypto/src/operation_contract/signature.rs", "crate::operations::signature::sign"],
    ["crates/crypto/src/operation_contract/signature.rs", "crate::operations::signature::verify"],
    ["crates/ffi/src/ed25519.rs", "reallyme_crypto::operations::signature::generate_key_pair"],
    ["crates/ffi/src/ed25519.rs", "reallyme_crypto::operations::signature::derive_key_pair"],
    ["crates/ffi/src/ed25519.rs", "reallyme_crypto::operations::signature::sign"],
    ["crates/ffi/src/p256.rs", "reallyme_crypto::operations::signature::generate_key_pair"],
    ["crates/ffi/src/p256.rs", "reallyme_crypto::operations::signature::derive_key_pair"],
    ["crates/ffi/src/p256.rs", "reallyme_crypto::operations::signature::sign"],
    ["crates/ffi/src/p384.rs", "reallyme_crypto::operations::signature::generate_key_pair"],
    ["crates/ffi/src/p384.rs", "reallyme_crypto::operations::signature::derive_key_pair"],
    ["crates/ffi/src/p384.rs", "reallyme_crypto::operations::signature::sign"],
    ["crates/ffi/src/p521.rs", "reallyme_crypto::operations::signature::generate_key_pair"],
    ["crates/ffi/src/p521.rs", "reallyme_crypto::operations::signature::derive_key_pair"],
    ["crates/ffi/src/p521.rs", "reallyme_crypto::operations::signature::sign"],
    ["crates/ffi/src/secp256k1.rs", "reallyme_crypto::operations::signature::generate_key_pair"],
    ["crates/ffi/src/secp256k1.rs", "reallyme_crypto::operations::signature::derive_key_pair"],
    ["crates/ffi/src/secp256k1.rs", "reallyme_crypto::operations::signature::sign"],
  ];

  for (const [path, required] of requiredRoutes) {
    if (!readText(path).includes(required)) {
      fail(`${path} must route signature behavior through ${required}`);
    }
  }

  const operationsSource = readText("crates/crypto/src/operation_contract/operations.rs");
  for (const forbidden of [
    "CryptoSignatureGenerateKeyPairRequest",
    "CryptoSignatureDeriveKeyPairRequest",
    "CryptoSignatureSignRequest",
    "CryptoSignatureVerifyRequest",
  ]) {
    if (operationsSource.includes(forbidden)) {
      fail(`crates/crypto/src/operation_contract/operations.rs retains signature semantics through ${forbidden}`);
    }
  }

  const ed25519Native = readText("crates/ed25519/src/native/sign.rs");
  if (!ed25519Native.includes("ED25519_SECRET_KEY_LEN") || ed25519Native.includes("64 =>")) {
    fail("crates/ed25519/src/native/sign.rs must enforce the signature Ed25519 32-byte seed-only contract");
  }
  if (readText("crates/ed25519/src/lib.rs").includes("mod wasm")) {
    fail("crates/ed25519 must use the package-owned Rust implementation for the WASM lane");
  }

  const ffiEd25519 = readText("crates/ffi/src/ed25519.rs");
  if (ffiEd25519.includes("ED25519_EXPANDED_SECRET_KEY_LEN")) {
    fail("crates/ffi/src/ed25519.rs must not expose expanded Ed25519 signing keys");
  }
  const tsEd25519 = readText("packages/ts/src/ed25519.ts");
  if (!tsEd25519.includes("ED25519_SECRET_KEY_LENGTH = 32")) {
    fail("packages/ts/src/ed25519.ts must retain the signature Ed25519 32-byte seed contract");
  }

  for (const [path, forbidden] of [
    ["crates/crypto/src/ed25519.rs", "crypto_ed25519::generate_ed25519_keypair("],
    ["crates/crypto/src/ed25519.rs", "crypto_ed25519::generate_ed25519_keypair_from_seed("],
    ["crates/crypto/src/secp256k1.rs", "crypto_secp256k1::generate_secp256k1_keypair("],
    ["crates/crypto/src/secp256k1.rs", "crypto_secp256k1::generate_secp256k1_keypair_from_secret_key("],
  ]) {
    if (readText(path).includes(forbidden)) {
      fail(`${path} retains direct signature key-management semantics through ${forbidden}`);
    }
  }

  const rootReadme = readText("crates/crypto/README.md");
  if (!rootReadme.includes("reallyme_crypto::operations::signature::{generate_key_pair, sign, verify}")) {
    fail("crates/crypto/README.md must teach the signature operation owner");
  }

  const swiftSecp256k1 = readText("packages/swift/Sources/ReallyMeCrypto/Secp256k1.swift");
  for (const required of [
    "static func generateKeyPair(",
    "clearSecretCandidate(&secretKey",
    "ReallyMeCryptoMemory.bestEffortClear(&secretKey)",
    "randomize: true",
  ]) {
    if (!swiftSecp256k1.includes(required)) {
      fail("Swift secp256k1 must preserve randomized secret-operation contexts and candidate cleanup");
    }
  }
  const swiftSecp256k1Tests = readText(
    "packages/swift/Tests/ReallyMeCryptoTests/Secp256k1SecurityTests.swift",
  );
  if (!swiftSecp256k1Tests.includes("testSecp256k1AcceptedSecretCandidateIsClearedAfterDerivationFailure")) {
    fail("Swift secp256k1 must regression-test accepted-candidate cleanup after derivation failure");
  }

  for (const [path, forbidden] of [
    ["packages/swift/Sources/ReallyMeCrypto/CryptoFacade.swift", "ReallyMeSignatureKeyPair: Equatable"],
    ["packages/swift/Sources/ReallyMeCrypto/P256SecureEnclaveEcdsa.swift", "ReallyMeSignatureHandleKeyPair: Equatable"],
    ["packages/swift/Sources/ReallyMeCryptoProtoAdapters/ProtoAdapters.swift", "ReallyMeSignatureKeyPairProtoValue: Equatable"],
  ]) {
    if (readText(path).includes(forbidden)) {
      fail(`${path} must not expose variable-time synthesized equality for signature key material`);
    }
  }
};

export const assertBip340SemanticOwnership = ({
  readText,
  fail,
}) => {
  const requiredRoutes = [
    ["crates/crypto/src/operations/signature.rs", "generate_bip340_key_pair"],
    ["crates/crypto/src/operations/signature.rs", "derive_bip340_key_pair"],
    ["crates/crypto/src/operations/signature.rs", "derive_bip340_public_key"],
    ["crates/crypto/src/operations/signature.rs", "sign_bip340"],
    ["crates/crypto/src/operations/signature.rs", "verify_bip340"],
    ["crates/crypto/src/secp256k1.rs", "crate::operations::signature::sign_bip340"],
    ["crates/crypto/src/secp256k1.rs", "crate::operations::signature::generate_bip340_key_pair"],
    ["crates/crypto/src/secp256k1.rs", "crate::operations::signature::derive_bip340_key_pair"],
    ["crates/crypto/src/operation_contract/request_signature.rs", "process_bip340_schnorr_sign_request"],
    ["crates/crypto/src/operation_contract/signature.rs", "process_bip340_schnorr_sign"],
    ["crates/crypto/src/operation_contract/signature.rs", "crate::operations::signature::sign_bip340"],
    ["crates/crypto/src/operation_contract/signature.rs", "crate::operations::signature::generate_bip340_key_pair"],
    ["crates/crypto/src/operation_contract/signature.rs", "crate::operations::signature::derive_bip340_key_pair"],
    ["crates/crypto/src/operation_contract/signature.rs", "crate::operations::signature::verify_bip340"],
    ["crates/ffi/src/bip340_schnorr.rs", "reallyme_crypto::operations::signature::sign_bip340"],
    ["crates/ffi/src/bip340_schnorr.rs", "reallyme_crypto::operations::signature::verify_bip340"],
  ];

  for (const [path, required] of requiredRoutes) {
    if (!readText(path).includes(required)) {
      fail(`${path} must route BIP-340 behavior through ${required}`);
    }
  }

  const rootSecp256k1 = readText("crates/crypto/src/secp256k1.rs");
  for (const forbidden of [
    "sign_bip340_schnorr,",
    "verify_bip340_schnorr,",
    "derive_bip340_schnorr_public_key,",
  ]) {
    if (rootSecp256k1.includes(forbidden)) {
      fail("crates/crypto/src/secp256k1.rs must not re-export direct BIP-340 primitive semantics");
    }
  }

  const operationResponse = readText("crates/crypto/src/operation_contract/request.rs");
  if (operationResponse.includes("CryptoOperation::Bip340SchnorrSign(_)")) {
    fail("BIP-340 operation-response sign must not remain an unsupported placeholder");
  }

  for (const [typeName, fields] of [
    ["CryptoBip340SchnorrSignRequest", ["message32", "secret_key", "aux_rand32"]],
  ]) {
    assertGeneratedDropZeroizesFields({ readText, fail, area: "BIP-340", typeName, fields });
  }

  const ffiSecp256k1 = readText("crates/ffi/src/secp256k1.rs");
  if (ffiSecp256k1.includes("rm_crypto_bip340_schnorr_")) {
    fail("BIP-340 C ABI routes must live in crates/ffi/src/bip340_schnorr.rs");
  }

  const bip340ResponseTests = readText(
    "crates/crypto/tests/bip340_operation_response_tests.rs",
  );
  for (const required of [
    "CryptoOperationResultBranch::SignatureGenerateKeyPair",
    "CryptoOperationResultBranch::SignatureDeriveKeyPair",
    "CryptoOperationResultBranch::Bip340SchnorrSign",
    "CryptoOperationResultBranch::SignatureVerify",
    "CRYPTO_ERROR_REASON_PROVIDER_UNSUPPORTED_ALGORITHM",
  ]) {
    if (!bip340ResponseTests.includes(required)) {
      fail("BIP-340 must cover every BIP-340 generated result shape and the reserved generic sign route");
    }
  }

  const secp256k1Manifest = readText("crates/secp256k1/Cargo.toml");
  if (!secp256k1Manifest.includes('wasm = [\n    "dep:getrandom",\n    "dep:k256",\n    "dep:ecdsa",\n    "dep:sha2",\n]')) {
    fail("crates/secp256k1 must compile the Rust implementation for the WASM lane");
  }

  const wasmBoundaryTests = readText(
    "crates/secp256k1/tests/wasm_boundary_tests.rs",
  );
  for (const required of [
    "wasm_lane_uses_package_owned_rust_bip340",
    "verify_bip340_schnorr(&signature, &MESSAGE32, &public_key).unwrap()",
    "verify_bip340_schnorr(&signature, &[0x24; 32], &public_key).is_err()",
  ]) {
    if (!wasmBoundaryTests.includes(required)) {
      fail("BIP-340 must regression-test package-owned WASM BIP-340 behavior");
    }
  }

  const protobufDocs = readText("docs/protobuf.md");
  if (protobufDocs.includes("BIP-340 verification has\nno dedicated protobuf request")) {
    fail("protobuf documentation must not preserve a direct-only BIP-340 verification route");
  }
};

export const assertRsaSemanticOwnership = ({
  readText,
  fail,
}) => {
  const requiredRoutes = [
    ["crates/crypto/src/operations/signature.rs", "verify_rsa_pkcs1v15"],
    ["crates/crypto/src/operations/signature.rs", "verify_rsa_pss"],
    ["crates/crypto/src/rsa.rs", "crate::operations::signature::verify_rsa_pkcs1v15"],
    ["crates/crypto/src/rsa.rs", "crate::operations::signature::verify_rsa_pss"],
    ["crates/crypto/src/operation_contract/request.rs", "process_rsa_verify"],
    ["crates/crypto/src/operation_contract/signature.rs", "process_rsa_verify"],
    ["crates/crypto/src/operation_contract/signature.rs", "crate::operations::signature::verify_rsa_pkcs1v15"],
    ["crates/crypto/src/operation_contract/signature.rs", "crate::operations::signature::verify_rsa_pss"],
    ["crates/ffi/src/rsa.rs", "reallyme_crypto::operations::signature::verify_rsa_pkcs1v15"],
    ["crates/ffi/src/rsa.rs", "reallyme_crypto::operations::signature::verify_rsa_pss"],
    ["crates/wasm/src/rsa.rs", "use crypto_runtime::rsa::{"],
  ];

  for (const [path, required] of requiredRoutes) {
    if (!readText(path).includes(required)) {
      fail(`${path} must route RSA verify behavior through ${required}`);
    }
  }

  const rootLib = readText("crates/crypto/src/lib.rs");
  if (rootLib.includes("pub mod rsa {")) {
    fail("crates/crypto/src/lib.rs must keep RSA as a thin module declaration");
  }

  const rootRsa = readText("crates/crypto/src/rsa.rs");
  for (const forbidden of ["verify_rsa_pkcs1v15,", "verify_rsa_pss,"]) {
    if (rootRsa.includes(forbidden)) {
      fail("crates/crypto/src/rsa.rs must not re-export direct RSA primitive verification");
    }
  }

  const operationResponse = readText("crates/crypto/src/operation_contract/request.rs");
  if (operationResponse.includes("CryptoOperation::RsaVerify(_)")) {
    fail("RSA operation-response verify must not remain an unsupported placeholder");
  }

  const operationTests = readText("crates/crypto/tests/rsa_operation_response_tests.rs");
  if (!operationTests.includes("every_public_rsa_suite_matches_semantic_owner_facade_and_generated_response")) {
    fail("RSA must exercise every RSA suite through the semantic owner and generated response");
  }
  if (!operationTests.includes("semantic_owner_supports_rfc8017_short_encoded_message_and_typed_rejection")) {
    fail("RSA must document the supported RSA-PSS non-byte-aligned modulus decision with a test");
  }

  const primitiveTests = readText("crates/rsa/tests/rsa_pss_edge_tests.rs");
  if (!primitiveTests.includes("pss_accepts_rfc8017_em_len_one_byte_shorter_than_modulus")) {
    fail("RSA must prove RFC 8017 emLen = k - 1 with an RSA-PSS vector");
  }
};

export const assertKeyAgreementSemanticOwnership = ({
  readText,
  fail,
}) => {
  const requiredRoutes = [
    ["crates/crypto/src/operations/key_agreement.rs", "derive_shared_secret"],
    ["crates/crypto/src/operations/key_agreement.rs", "is_key_agreement_algorithm"],
    ["crates/crypto/src/x25519.rs", "crate::operations::key_agreement::derive_shared_secret"],
    ["crates/crypto/src/p256.rs", "crate::operations::key_agreement::derive_shared_secret"],
    ["crates/crypto/src/p384.rs", "crate::operations::key_agreement::derive_shared_secret"],
    ["crates/crypto/src/p521.rs", "crate::operations::key_agreement::derive_shared_secret"],
    ["crates/crypto/src/operation_contract/operations.rs", "crate::operations::key_agreement::derive_shared_secret"],
    ["crates/crypto/src/operation_contract/operations.rs", "crate::operations::key_agreement::derive_key_pair"],
    ["crates/crypto/src/operation_contract/request.rs", "CryptoOperationResultBranch::KeyAgreementDeriveSharedSecret"],
    ["crates/crypto/src/operation_contract/request.rs", "CryptoOperationResultBranch::KeyAgreementDeriveKeyPair"],
    ["crates/ffi/src/x25519.rs", "reallyme_crypto::operations::key_agreement::derive_shared_secret"],
    ["crates/ffi/src/x25519.rs", "reallyme_crypto::operations::key_agreement::generate_key_pair"],
    ["crates/ffi/src/p256.rs", "reallyme_crypto::operations::key_agreement::derive_shared_secret"],
    ["crates/ffi/src/p384.rs", "reallyme_crypto::operations::key_agreement::derive_shared_secret"],
    ["crates/ffi/src/p521.rs", "reallyme_crypto::operations::key_agreement::derive_shared_secret"],
  ];

  for (const [path, required] of requiredRoutes) {
    if (!readText(path).includes(required)) {
      fail(`${path} must route key-agreement behavior through ${required}`);
    }
  }

  const rootLib = readText("crates/crypto/src/lib.rs");
  if (rootLib.includes("pub mod x25519 {")) {
    fail("crates/crypto/src/lib.rs must keep X25519 as a thin module declaration");
  }

  const forbiddenDirectRoutes = [
    ["crates/ffi/src/x25519.rs", "crypto_x25519::derive_x25519_shared_secret"],
    ["crates/ffi/src/x25519.rs", "crypto_x25519::generate_x25519_keypair"],
    ["crates/ffi/src/p256.rs", "crypto_p256::derive_p256_shared_secret"],
    ["crates/ffi/src/p384.rs", "crypto_p384::derive_p384_shared_secret"],
    ["crates/ffi/src/p521.rs", "crypto_p521::derive_p521_shared_secret"],
    ["crates/crypto/src/p256.rs", "derive_p256_shared_secret,"],
    ["crates/crypto/src/p384.rs", "derive_p384_shared_secret,"],
    ["crates/crypto/src/p521.rs", "derive_p521_shared_secret,"],
  ];
  for (const [path, forbidden] of forbiddenDirectRoutes) {
    if (readText(path).includes(forbidden)) {
      fail(`${path} retains direct key-agreement semantics through ${forbidden}`);
    }
  }

  const protoOperations = readText("crates/crypto/src/operation_contract/operations.rs");
  const protoSharedSecret = extractBraceDelimitedBlock(
    protoOperations,
    "pub(super) fn process_key_agreement_derive_shared_secret",
    "key-agreement protobuf shared-secret route",
    fail,
  );
  if (protoSharedSecret.includes("crypto_dispatch::derive_shared_secret")) {
    fail("key-agreement protobuf shared-secret route retains direct dispatch semantics");
  }
  const protoDeriveKeyPair = extractBraceDelimitedBlock(
    protoOperations,
    "pub(super) fn process_key_agreement_derive_key_pair",
    "key-agreement protobuf derive-keypair route",
    fail,
  );
  if (protoDeriveKeyPair.includes("crypto_dispatch::derive_keypair")) {
    fail("key-agreement protobuf derive-keypair route retains direct dispatch semantics");
  }

  const operationTests = readText("crates/crypto/tests/key_agreement_operation_tests.rs");
  for (const required of [
    "key_agreement_owner_round_trips_raw_shared_secret_outputs",
    "repository_vectors_match_owner_and_public_facades_without_implicit_kdf",
    "key_agreement_owner_rejects_invalid_public_key_material",
    "x25519_all_zero_peer_output_fails_as_invalid_shared_secret",
    "assert_zeroizing_vec",
  ]) {
    if (!operationTests.includes(required)) {
      fail(`key-agreement operation tests must cover ${required}`);
    }
  }

  const operationResponseTests = readText(
    "crates/crypto/tests/key_agreement_operation_response_tests.rs",
  );
  for (const required of [
    "operation_response_exposes_every_key_agreement_result_branch",
    "operation_response_returns_typed_errors_for_every_key_agreement_invalid_key_path",
    "operation_response_fails_closed_for_unknown_key_agreement_routes",
  ]) {
    if (!operationResponseTests.includes(required)) {
      fail(`key-agreement generated operation-response tests must cover ${required}`);
    }
  }

  const schemaTests = readText("crates/proto/tests/operation_contract_schema_tests.rs");
  if (!schemaTests.includes("provider_owned_platform_operations_remain_outside_the_rust_transport")) {
    fail("schema tests must keep provider-owned platform operations outside the Rust transport");
  }

  const swiftSharedSecretCleanup = [
    "packages/swift/Sources/ReallyMeCrypto/X25519.swift",
    "packages/swift/Sources/ReallyMeCrypto/P256Ecdh.swift",
    "packages/swift/Sources/ReallyMeCrypto/P384Ecdh.swift",
    "packages/swift/Sources/ReallyMeCrypto/P521Ecdh.swift",
    "packages/swift/Sources/ReallyMeCrypto/P256SecureEnclaveEcdh.swift",
  ];
  for (const path of swiftSharedSecretCleanup) {
    if (!readText(path).includes("ReallyMeCryptoMemory.bestEffortClear(&bytes)")) {
      fail(`${path} must clear owned Swift shared-secret copies before validation errors`);
    }
  }

  const swiftEcdh = readText("packages/swift/Sources/ReallyMeCrypto/P256SecureEnclaveEcdh.swift");
  const swiftEcdsa = readText("packages/swift/Sources/ReallyMeCrypto/P256SecureEnclaveEcdsa.swift");
  if (!swiftEcdsa.includes("storageTagPrefix + Array(SHA256.hash") ||
      !swiftEcdh.includes("storageTagPrefix + Array(SHA256.hash")) {
    fail("Swift Secure Enclave signing and ECDH must use purpose-separated Keychain tags");
  }
  if (!swiftEcdsa.includes("lifecycleLock") || !swiftEcdh.includes("lifecycleLock")) {
    fail("Swift Secure Enclave signing and ECDH must serialize persistent-key lifecycle changes");
  }
  for (const [path, source] of [
    ["packages/swift/Sources/ReallyMeCrypto/P256SecureEnclaveEcdh.swift", swiftEcdh],
    ["packages/swift/Sources/ReallyMeCrypto/P256SecureEnclaveEcdsa.swift", swiftEcdsa],
  ]) {
    if (!source.includes("privateKeyExists(tag: tag)") || !source.includes("kSecMatchLimit as String: kSecMatchLimitOne")) {
      fail(`${path} must fail closed for duplicate Secure Enclave tags and use one-match lookup`);
    }
  }

  const swiftEcdhTests = readText("packages/swift/Tests/ReallyMeCryptoTests/ReallyMeCryptoNativeKeyAgreementTests.swift");
  for (const required of [
    "testP256SecureEnclaveEcdhRejectsDuplicateTagWhenAvailable",
    "testP256SecureEnclaveEcdhDeleteIsIdempotentAndLookupFailsClosedWhenAvailable",
  ]) {
    if (!swiftEcdhTests.includes(required)) {
      fail(`Swift ECDH tests must cover Secure Enclave lifecycle control ${required}`);
    }
  }
  const swiftEcdsaTests = readText("packages/swift/Tests/ReallyMeCryptoTests/ReallyMeCryptoSecureEnclaveSigningTests.swift");
  for (const required of [
    "testP256SecureEnclaveSigningRejectsDuplicateTagWhenAvailable",
    "testP256SecureEnclaveSigningAndEcdhTagsArePurposeSeparatedWhenAvailable",
  ]) {
    if (!swiftEcdsaTests.includes(required)) {
      fail(`Swift signing tests must cover Secure Enclave lifecycle control ${required}`);
    }
  }

  const androidPlatformKeys = readText(
    "packages/kotlin-android/src/main/kotlin/me/really/crypto/AndroidPlatformKeys.kt",
  );
  for (const required of [
    "KeyProperties.PURPOSE_AGREE_KEY",
    "KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT",
    "KeyProperties.SECURITY_LEVEL_STRONGBOX",
    "privateKey.encoded != null",
    "ReallyMeCryptoException.PlatformKeyAlreadyExists",
    "ReallyMeCryptoException.PlatformKeyNotFound",
    "ReallyMeCryptoException.HardwareUnavailable",
    "@Synchronized",
  ]) {
    if (!androidPlatformKeys.includes(required)) {
      fail(`Android platform keys must preserve handle-backed hardware control ${required}`);
    }
  }
  const androidPlatformKeyTests = readText(
    "packages/kotlin-android/src/androidTest/kotlin/me/really/crypto/ReallyMeCryptoAndroidInstrumentedTest.kt",
  );
  for (const required of [
    "p256AndroidKeystoreSigningIsHardwareBackedOrFailsClosed",
    "p256AndroidKeystoreEcdhIsHardwareBackedOrFailsClosed",
    "p256AndroidStrongBoxSigningWhenAdvertised",
    "PlatformKeyAlreadyExists",
    "PlatformKeyNotFound",
  ]) {
    if (!androidPlatformKeyTests.includes(required)) {
      fail(`Android instrumentation must cover platform-key lifecycle ${required}`);
    }
  }
};

export const assertWasmHostProviderContract = ({
  readText,
  enforceFinalArchitecture,
  fail,
  pathExists = existsSync,
  sourcePaths,
}) => {
  const checkedPaths = sourcePaths ?? [
    ...listSourceFiles(wasmPackageSourceRoot, ".rs", fail),
    "packages/ts/src/wasmModuleTypes.ts",
    ...(enforceFinalArchitecture
      ? primitiveCrateRoots.flatMap((root) => listSourceFiles(root, ".rs", fail))
      : []),
  ];
  for (const path of checkedPaths) {
    const source = readText(path);
    if (/#\s*\[\s*wasm_bindgen(?:\([^)]*\))?\s*\][\s\S]{0,256}extern\s+"C"/.test(source)) {
      fail(`${path} exposes an ambient wasm host-provider extern block`);
    }
    for (const name of ambientProviderNames) {
      if (source.includes(name)) {
        fail(`${path} exposes ambient wasm host-provider binding ${name}`);
      }
    }
  }

  if (!enforceFinalArchitecture) {
    return;
  }

  const wasmCargo = readText("crates/wasm/Cargo.toml");
  for (const feature of wasmRuntimeFeatures) {
    if (!wasmCargo.includes(`"${feature}"`)) {
      fail(
        `release package mode must expose operation-response through package-owned Rust WASM feature ${feature}`,
      );
    }
  }
  for (const root of primitiveCrateRoots) {
    if (pathExists(`${root}/src/wasm`)) {
      fail(`${root}/src/wasm must be removed so release packages cannot bind ambient host providers`);
    }
  }
};

const assertFinalOperationArchitecture = ({ ledger, fail }) => {
  const unsupportedPlaceholders = findUnsupportedOperationResponsePlaceholders(ledger, fail);
  if (unsupportedPlaceholders.length !== 0) {
    fail(
      `operation-response routes still contain unsupported placeholders: ${unsupportedPlaceholders.map((entry) => entry.symbol).join(", ")}`,
    );
  }

  for (const group of requireArray(ledger.route_groups, "operation route ledger route_groups", fail)) {
    if (!reviewedRouteStatuses.has(group.current_status)) {
      fail(`${group.id} uses unreviewed route status ${group.current_status}`);
    }
  }
};

export const assertCryptoOperationRouteReadiness = ({
  readJson,
  readText,
  fail,
  releasePackagesMode = false,
}) => {
  const ledger = readJson(operationRouteLedgerPath);
  assertLedgerRoutesAreMapped(ledger, fail);
  assertProtoOperationsMatchLedger({ ledger, readText, fail });
  assertProtoOperationResultsMatchRequests({ readText, fail });
  assertOperationResponseBranchesMatchLedger({ ledger, readText, fail });
  assertRustDispatchExportsMatchLedger({ ledger, readText, fail });
  assertRootStructuredRoutesMatchLedger({ ledger, readText, fail });
  assertCAbiExportsMatchLedger({ ledger, readText, fail });
  assertJniExportsMatchLedger({ ledger, readText, fail });
  assertWasmExportsMatchLedger({ ledger, readText, fail });
  assertNoHandWrittenStructuredJsonContract({ readText, fail });
  assertHashSemanticOwnership({ readText, fail });
  assertMacSemanticOwnership({ readText, fail });
  assertAeadSemanticOwnership({ readText, fail });
  assertKeyWrapSemanticOwnership({ readText, fail });
  assertKdfSemanticOwnership({ readText, fail });
  assertSignatureSemanticOwnership({ readText, fail });
  assertBip340SemanticOwnership({ readText, fail });
  assertRsaSemanticOwnership({ readText, fail });
  assertKeyAgreementSemanticOwnership({ readText, fail });
  // Unsupported operation placeholders and unreviewed route statuses are not
  // permitted in any validation mode. Release-package mode additionally closes
  // ambient host-provider exposure.
  assertWasmHostProviderContract({ readText, enforceFinalArchitecture: releasePackagesMode, fail });
  assertFinalOperationArchitecture({ ledger, fail });
};
