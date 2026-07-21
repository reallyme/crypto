#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  assertJniExportsMatchLedger,
  assertNoHandWrittenStructuredJsonContract,
  assertProtoOperationResultsMatchRequests,
  assertProtoOperationsMatchLedger,
  assertOperationResponseBranchesMatchLedger,
  assertRootStructuredRoutesMatchLedger,
  assertRustDispatchExportsMatchLedger,
  assertHashSemanticOwnership,
  assertMacSemanticOwnership,
  assertAeadSemanticOwnership,
  assertKeyWrapSemanticOwnership,
  assertKdfSemanticOwnership,
  assertSignatureSemanticOwnership,
  assertBip340SemanticOwnership,
  assertRsaSemanticOwnership,
  assertKeyAgreementSemanticOwnership,
  assertWasmExportsMatchLedger,
  assertWasmHostProviderContract,
  assertLedgerRoutesAreMapped,
  extractProtoOperationRouteSymbols,
  extractOperationResponseRouteSymbols,
  findUnsupportedOperationResponsePlaceholders,
  flattenRouteGroupSymbols,
} from "./crypto_operation_route_readiness.mjs";

const fail = (message) => {
  throw new Error(message);
};

const minimalLedger = {
  schema_version: 1,
  owners: [
    { id: "operation.hash.digest" },
    { id: "operation.signature.rsa.verify" },
  ],
  route_groups: [
    {
      id: "protobuf.crypto_operation_request.oneof",
      lane: "protobuf-contract",
      path: "crypto.proto",
      current_status: "declared_operation_contract",
      symbols_by_owner: {
        "operation.hash.digest": ["CryptoOperationRequest.hash"],
        "operation.signature.rsa.verify": ["CryptoOperationRequest.rsa_verify"],
      },
    },
    {
      id: "rust.operation_response.branches",
      lane: "rust-protobuf-branch",
      path: "crates/crypto/src/operation_contract/request.rs",
      current_status: "operation_response_branch_authority",
      symbols_by_owner: {
        "operation.hash.digest": ["CryptoOperation::Hash => process_hash"],
        "operation.signature.rsa.verify": ["CryptoOperation::RsaVerify => unsupported_algorithm"],
      },
    },
    {
      id: "c_abi.exports",
      lane: "c-abi",
      path: "reallyme_crypto_ffi.h",
      current_status: "operation_backed_c_abi_scalar_routes",
      symbols_by_owner: {
        "operation.signature.rsa.verify": ["rm_crypto_rsa_verify_pss"],
      },
    },
  ],
};

const flattened = flattenRouteGroupSymbols(minimalLedger.route_groups[0], fail);
assert.deepEqual(flattened, [
  {
    groupId: "protobuf.crypto_operation_request.oneof",
    owner: "operation.hash.digest",
    symbol: "CryptoOperationRequest.hash",
  },
  {
    groupId: "protobuf.crypto_operation_request.oneof",
    owner: "operation.signature.rsa.verify",
    symbol: "CryptoOperationRequest.rsa_verify",
  },
]);

const expectedUnsupportedPlaceholder = [
  {
    groupId: "rust.operation_response.branches",
    owner: "operation.signature.rsa.verify",
    symbol: "CryptoOperation::RsaVerify => unsupported_algorithm",
  },
];
assert.deepEqual(
  findUnsupportedOperationResponsePlaceholders(minimalLedger, fail),
  expectedUnsupportedPlaceholder,
);

const unsupportedOnlyLedger = {
  ...minimalLedger,
  route_groups: minimalLedger.route_groups.filter((group) => group.id !== "c_abi.exports"),
};
assert.deepEqual(
  findUnsupportedOperationResponsePlaceholders(unsupportedOnlyLedger, fail),
  expectedUnsupportedPlaceholder,
);

const multiplyOwnedRouteLedger = {
  schema_version: 1,
  owners: minimalLedger.owners,
  route_groups: [
    {
      id: "duplicate.route",
      lane: "test",
      path: "test",
      current_status: "declared_operation_contract",
      symbols_by_owner: {
        "operation.hash.digest": ["sameSymbol"],
        "operation.signature.rsa.verify": ["sameSymbol"],
      },
    },
  ],
};
assert.throws(
  () => assertLedgerRoutesAreMapped(multiplyOwnedRouteLedger, fail),
  /maps route symbol sameSymbol more than once/,
);

const multiplyOwnedHiddenRouteLedger = {
  schema_version: 1,
  owners: minimalLedger.owners,
  route_groups: [
    {
      id: "duplicate.hidden.route",
      lane: "test",
      path: "test",
      current_status: "declared_operation_contract",
      symbols: ["sameSymbol"],
      owner: "operation.hash.digest",
      intentionally_hidden_symbols: [
        {
          owner: "operation.signature.rsa.verify",
          symbol: "sameSymbol",
          reason: "test fixture",
        },
      ],
    },
  ],
};
assert.throws(
  () => assertLedgerRoutesAreMapped(multiplyOwnedHiddenRouteLedger, fail),
  /maps route symbol sameSymbol more than once/,
);

const unreviewedStatusLedger = {
  ...minimalLedger,
  route_groups: minimalLedger.route_groups.map((group, index) => index === 0
    ? { ...group, current_status: "unreviewed_status" }
    : group),
};
assert.throws(
  () => assertLedgerRoutesAreMapped(unreviewedStatusLedger, fail),
  /uses unreviewed route status unreviewed_status/,
);

const emptyRouteGroupLedger = {
  schema_version: 1,
  owners: minimalLedger.owners,
  route_groups: [
    {
      id: "empty.route",
      lane: "test",
      path: "test",
      current_status: "declared_operation_contract",
    },
  ],
};
assert.throws(
  () => assertLedgerRoutesAreMapped(emptyRouteGroupLedger, fail),
  /must map at least one route or reuse a mapped route group/,
);

const readText = (path) => readFileSync(path, "utf8");
const readJson = (path) => JSON.parse(readText(path));
const repositoryLedger = readJson("docs/operation-route-ledger.json");
const repositoryUnsupportedPlaceholders = findUnsupportedOperationResponsePlaceholders(
  repositoryLedger,
  fail,
);
assert.equal(repositoryUnsupportedPlaceholders.length, 0);

assert.doesNotThrow(() => assertProtoOperationsMatchLedger({
  ledger: repositoryLedger,
  readText,
  fail,
}));
assert.doesNotThrow(() => assertProtoOperationResultsMatchRequests({
  readText,
  fail,
}));
assert.doesNotThrow(() => assertOperationResponseBranchesMatchLedger({
  ledger: repositoryLedger,
  readText,
  fail,
}));
assert.doesNotThrow(() => assertRustDispatchExportsMatchLedger({
  ledger: repositoryLedger,
  readText,
  fail,
}));
assert.doesNotThrow(() => assertHashSemanticOwnership({
  readText,
  fail,
}));
assert.doesNotThrow(() => assertMacSemanticOwnership({
  readText,
  fail,
}));
assert.doesNotThrow(() => assertAeadSemanticOwnership({
  readText,
  fail,
}));
assert.doesNotThrow(() => assertKeyWrapSemanticOwnership({
  readText,
  fail,
}));
assert.doesNotThrow(() => assertKdfSemanticOwnership({
  readText,
  fail,
}));
assert.doesNotThrow(() => assertSignatureSemanticOwnership({
  readText,
  fail,
}));
assert.doesNotThrow(() => assertBip340SemanticOwnership({
  readText,
  fail,
}));
assert.doesNotThrow(() => assertRsaSemanticOwnership({
  readText,
  fail,
}));
assert.doesNotThrow(() => assertKeyAgreementSemanticOwnership({
  readText,
  fail,
}));

const protoSource = readText("crates/proto/proto/reallyme/crypto/v1/crypto.proto");
assert.equal(extractProtoOperationRouteSymbols(protoSource, fail).length, 32);
const processSource = readText("crates/crypto/src/operation_contract/request.rs");
assert.equal(extractOperationResponseRouteSymbols(processSource, fail).length, 32);

assert.throws(
  () => assertWasmHostProviderContract({
    readText: () => '#[wasm_bindgen]\nextern "C" { fn encrypt(); }',
    enforceFinalArchitecture: false,
    fail,
    sourcePaths: ["crates/example/src/provider.rs"],
  }),
  /ambient wasm host-provider extern block/,
);

assert.throws(
  () => assertWasmHostProviderContract({
    readText,
    enforceFinalArchitecture: true,
    fail,
    pathExists: (path) => path === "crates/aes256-gcm/src/wasm",
    sourcePaths: [],
  }),
  /crates\/aes256-gcm\/src\/wasm must be removed/,
);

const withSourceMutation = (targetPath, mutate) => (path) => {
  const source = readText(path);
  return path === targetPath ? mutate(source) : source;
};

assert.throws(
  () => assertHashSemanticOwnership({
    readText: withSourceMutation(
      "crates/ffi/src/sha2_256.rs",
      (source) => source.replace(
        "reallyme_crypto::operations::hash::sha2_256(message)",
        "crypto_sha2_256::digest(message)",
      ),
    ),
    fail,
  }),
  /must route hash and constant-time behavior|retains direct hash and constant-time primitive semantics/,
);

assert.throws(
  () => assertHashSemanticOwnership({
    readText: withSourceMutation(
      "crates/crypto/src/operations/hash.rs",
      (source) => `${source}\n/// \`\`\`rust\n/// let digest = b"inline test";\n/// \`\`\`\n`,
    ),
    fail,
  }),
  /must keep compile-checked examples in a separate README or documentation file/,
);

assert.throws(
  () => assertMacSemanticOwnership({
    readText: withSourceMutation(
      "crates/ffi/src/hmac.rs",
      (source) => source.replace(
        "reallyme_crypto::hmac",
        "crypto_hmac",
      ),
    ),
    fail,
  }),
  /must route MAC behavior|retains direct MAC primitive semantics/,
);

assert.throws(
  () => assertMacSemanticOwnership({
    readText: withSourceMutation(
      "crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.rs",
      (source) => source.replace(
        "        ::zeroize::Zeroize::zeroize(&mut self.message);\n",
        "",
      ),
    ),
    fail,
  }),
  /must zeroize CryptoMacAuthenticateRequest.message/,
);

assert.throws(
  () => assertMacSemanticOwnership({
    readText: withSourceMutation(
      "packages/ts/src/hmac.ts",
      (source) => source.replace("expectedTag.fill(0);", ""),
    ),
    fail,
  }),
  /TypeScript HMAC verification must clear its temporary expected tag/,
);

assert.throws(
  () => assertMacSemanticOwnership({
    readText,
    fail,
    pathExists: (path) => path === "crates/crypto/dispatch/src/mac.rs",
  }),
  /retains the superseded MAC selector/,
);

assert.throws(
  () => assertAeadSemanticOwnership({
    readText: withSourceMutation(
      "crates/ffi/src/chacha20_poly1305.rs",
      (source) => source.replace(
        "reallyme_crypto::chacha20_poly1305",
        "crypto_chacha20_poly1305",
      ),
    ),
    fail,
  }),
  /must route AEAD behavior|retains direct AEAD primitive semantics/,
);

assert.throws(
  () => assertAeadSemanticOwnership({
    readText: withSourceMutation(
      "crates/wasm/src/aead.rs",
      (source) => source.replace("crypto_runtime::aes", "crypto_aes256_gcm"),
    ),
    fail,
  }),
  /must route AEAD behavior|retains direct AEAD primitive semantics/,
);

assert.throws(
  () => assertAeadSemanticOwnership({
    readText,
    fail,
    pathExists: (path) => path === "crates/crypto/dispatch/src/registry/aead.rs",
  }),
  /retains the superseded AEAD selector/,
);

assert.throws(
  () => assertAeadSemanticOwnership({
    readText: withSourceMutation(
      "crates/ffi/src/aes256_gcm/decrypt.rs",
      (source) => source.replace(
        "reallyme_crypto::operations::aead::open",
        "reallyme_crypto::aes::decrypt",
      ),
    ),
    fail,
  }),
  /must obtain every FFI plaintext from the zeroizing AEAD operation owner/,
);

assert.throws(
  () => assertAeadSemanticOwnership({
    readText: withSourceMutation(
      "crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.rs",
      (source) => source.replace(
        "        ::zeroize::Zeroize::zeroize(&mut self.plaintext);\n",
        "",
      ),
    ),
    fail,
  }),
  /must zeroize CryptoAeadSealRequest.plaintext|must zeroize CryptoAeadOpenResult.plaintext/,
);

assert.throws(
  () => assertKeyWrapSemanticOwnership({
    readText: withSourceMutation(
      "crates/ffi/src/aes_kw.rs",
      (source) => source.replaceAll(
        "reallyme_crypto::operations::key_wrap",
        "crypto_aes_kw",
      ),
    ),
    fail,
  }),
  /must route AES-KW behavior|retains direct AES-KW primitive semantics/,
);

assert.throws(
  () => assertKeyWrapSemanticOwnership({
    readText: withSourceMutation(
      "crates/ffi/Cargo.toml",
      (source) => source.replace(
        "[dependencies]\n",
        "[dependencies]\ncrypto-aes-kw = \"0.2.1\"\n",
      ),
    ),
    fail,
  }),
  /retains direct AES-KW primitive semantics/,
);

assert.throws(
  () => assertKeyWrapSemanticOwnership({
    readText: withSourceMutation(
      "crates/wasm/src/key_wrap.rs",
      (source) => source.replaceAll(
        "crypto_runtime::operations::key_wrap",
        "crypto_aes_kw",
      ),
    ),
    fail,
  }),
  /must route AES-KW behavior|retains direct AES-KW primitive semantics/,
);

assert.throws(
  () => assertKeyWrapSemanticOwnership({
    readText: withSourceMutation(
      "crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.rs",
      (source) => source.replace(
        "        ::zeroize::Zeroize::zeroize(&mut self.wrapped_key);\n",
        "",
      ),
    ),
    fail,
  }),
  /must zeroize CryptoKeyWrapResult.wrapped_key/,
);

assert.throws(
  () => assertKdfSemanticOwnership({
    readText: withSourceMutation(
      "crates/ffi/src/pbkdf2.rs",
      (source) => source.replace(
        "reallyme_crypto::operations::kdf::derive_pbkdf2_from_raw",
        "crypto_pbkdf2::derive_key",
      ),
    ),
    fail,
  }),
  /must route KDF behavior|retains direct KDF primitive semantics/,
);

assert.throws(
  () => assertKdfSemanticOwnership({
    readText: withSourceMutation(
      "crates/hkdf/src/derive.rs",
      (source) => source.replace("SimpleHkdf::<Sha3_256>", "Hkdf::<Sha3_256>"),
    ),
    fail,
  }),
  /audited generic HKDF-SHA3 implementation/,
);

assert.throws(
  () => assertKdfSemanticOwnership({
    readText: withSourceMutation(
      "crates/proto/src/generated/buffa/reallyme.crypto.v1.crypto.rs",
      (source) => source.replace(
        "        ::zeroize::Zeroize::zeroize(&mut self.output_key_material);\n",
        "",
      ),
    ),
    fail,
  }),
  /must zeroize CryptoHkdfDeriveResult.output_key_material/,
);

assert.throws(
  () => assertSignatureSemanticOwnership({
    readText: withSourceMutation(
      "crates/ffi/src/ed25519.rs",
      (source) => source.replace(
        "reallyme_crypto::operations::signature::sign",
        "crypto_ed25519::sign_ed25519",
      ),
    ),
    fail,
  }),
  /must route signature behavior/,
);

assert.throws(
  () => assertSignatureSemanticOwnership({
    readText: withSourceMutation(
      "crates/ffi/src/ed25519.rs",
      (source) => `${source}\npub const ED25519_EXPANDED_SECRET_KEY_LEN: usize = 64;\n`,
    ),
    fail,
  }),
  /must not expose expanded Ed25519 signing keys/,
);

assert.throws(
  () => assertSignatureSemanticOwnership({
    readText: withSourceMutation(
      "crates/crypto/src/ed25519.rs",
      (source) => `${source}\nfn removed_route() { crypto_ed25519::generate_ed25519_keypair(); }\n`,
    ),
    fail,
  }),
  /retains direct signature key-management semantics/,
);

assert.throws(
  () => assertSignatureSemanticOwnership({
    readText: withSourceMutation(
      "crates/crypto/README.md",
      (source) => source.replace(
        "reallyme_crypto::operations::signature::{generate_key_pair, sign, verify}",
        "reallyme_crypto::dispatch::{generate_keypair, sign, verify}",
      ),
    ),
    fail,
  }),
  /must teach the signature operation owner/,
);

assert.throws(
  () => assertSignatureSemanticOwnership({
    readText: withSourceMutation(
      "packages/swift/Tests/ReallyMeCryptoTests/Secp256k1SecurityTests.swift",
      (source) => source.replace(
        "testSecp256k1AcceptedSecretCandidateIsClearedAfterDerivationFailure",
        "removedCleanupRegression",
      ),
    ),
    fail,
  }),
  /must regression-test accepted-candidate cleanup/,
);

assert.throws(
  () => assertSignatureSemanticOwnership({
    readText: withSourceMutation(
      "packages/swift/Sources/ReallyMeCrypto/P256SecureEnclaveEcdsa.swift",
      (source) => source.replace(
        "ReallyMeSignatureHandleKeyPair: Sendable",
        "ReallyMeSignatureHandleKeyPair: Equatable, Sendable",
      ),
    ),
    fail,
  }),
  /must not expose variable-time synthesized equality/,
);

assert.throws(
  () => assertBip340SemanticOwnership({
    readText: withSourceMutation(
      "crates/ffi/src/bip340_schnorr.rs",
      (source) => source.replace(
        "reallyme_crypto::operations::signature::sign_bip340",
        "crypto_secp256k1::sign_bip340_schnorr",
      ),
    ),
    fail,
  }),
  /must route BIP-340 behavior/,
);

assert.throws(
  () => assertBip340SemanticOwnership({
    readText: withSourceMutation(
      "crates/crypto/src/operation_contract/request.rs",
      (source) => source.replace(
        "CryptoOperation::Bip340SchnorrSign(request)",
        "CryptoOperation::Bip340SchnorrSign(_)",
      ),
    ),
    fail,
  }),
  /must not remain an unsupported placeholder/,
);

assert.throws(
  () => assertBip340SemanticOwnership({
    readText: withSourceMutation(
      "crates/crypto/src/operation_contract/signature.rs",
      (source) => source.replace(
        "crate::operations::signature::verify_bip340",
        "crypto_secp256k1::verify_bip340_schnorr",
      ),
    ),
    fail,
  }),
  /must route BIP-340 behavior/,
);

assert.throws(
  () => assertBip340SemanticOwnership({
    readText: withSourceMutation(
      "crates/crypto/tests/bip340_operation_response_tests.rs",
      (source) => source.replaceAll(
        "CryptoOperationResultBranch::SignatureVerify",
        "removedBip340VerifyResultBranch",
      ),
    ),
    fail,
  }),
  /must cover every BIP-340 generated result shape/,
);

assert.throws(
  () => assertBip340SemanticOwnership({
    readText: withSourceMutation(
      "crates/secp256k1/Cargo.toml",
      (source) => source.replace(
        'wasm = [\n    "dep:getrandom",\n    "dep:k256",\n    "dep:ecdsa",\n    "dep:sha2",\n]',
        'wasm = [\n    "dep:getrandom",\n    "dep:wasm-bindgen",\n]',
      ),
    ),
    fail,
  }),
  /must compile the Rust implementation for the WASM lane/,
);

assert.throws(
  () => assertBip340SemanticOwnership({
    readText: withSourceMutation(
      "crates/secp256k1/tests/wasm_boundary_tests.rs",
      (source) => source.replace(
        "wasm_lane_uses_package_owned_rust_bip340",
        "removed_package_owned_bip340_regression",
      ),
    ),
    fail,
  }),
  /must regression-test package-owned WASM BIP-340 behavior/,
);

assert.throws(
  () => assertRsaSemanticOwnership({
    readText: withSourceMutation(
      "crates/ffi/src/rsa.rs",
      (source) => source.replace(
        "reallyme_crypto::operations::signature::verify_rsa_pss",
        "crypto_rsa::verify_rsa_pss",
      ),
    ),
    fail,
  }),
  /must route RSA verify behavior/,
);

assert.throws(
  () => assertRsaSemanticOwnership({
    readText: withSourceMutation(
      "crates/crypto/src/operation_contract/request.rs",
      (source) => source.replace(
        "CryptoOperation::RsaVerify(request)",
        "CryptoOperation::RsaVerify(_)",
      ),
    ),
    fail,
  }),
  /must not remain an unsupported placeholder/,
);

assert.throws(
  () => assertKeyAgreementSemanticOwnership({
    readText: withSourceMutation(
      "crates/ffi/src/x25519.rs",
      (source) => source.replace(
        "reallyme_crypto::operations::key_agreement::derive_shared_secret",
        "crypto_x25519::derive_x25519_shared_secret",
      ),
    ),
    fail,
  }),
  /must route key-agreement behavior|retains direct key-agreement semantics/,
);

assert.throws(
  () => assertKeyAgreementSemanticOwnership({
    readText: withSourceMutation(
      "packages/swift/Sources/ReallyMeCrypto/P256SecureEnclaveEcdh.swift",
      (source) => source.replace("        } else if try privateKeyExists(tag: tag) {\n            throw ReallyMeCryptoError.invalidInput\n", ""),
    ),
    fail,
  }),
  /must fail closed for duplicate Secure Enclave tags/,
);

assert.throws(
  () => assertKeyAgreementSemanticOwnership({
    readText: withSourceMutation(
      "crates/crypto/src/operation_contract/request.rs",
      (source) => source.replace(
        "CryptoOperationResultBranch::KeyAgreementDeriveSharedSecret",
        "CryptoOperationResultBranch::Hash",
      ),
    ),
    fail,
  }),
  /must route key-agreement behavior/,
);

assert.throws(
  () => assertKeyAgreementSemanticOwnership({
    readText: withSourceMutation(
      "packages/swift/Tests/ReallyMeCryptoTests/ReallyMeCryptoNativeKeyAgreementTests.swift",
      (source) => source.replace(
        "testP256SecureEnclaveEcdhDeleteIsIdempotentAndLookupFailsClosedWhenAvailable",
        "removedKeyAgreementLifecycleTest",
      ),
    ),
    fail,
  }),
  /must cover Secure Enclave lifecycle control/,
);

assert.throws(
  () => assertProtoOperationsMatchLedger({
    ledger: repositoryLedger,
    readText: withSourceMutation(
      "crates/proto/proto/reallyme/crypto/v1/crypto.proto",
      (source) => source.replace(
        "CryptoHpkePskOpenRequest hpke_psk_open = 67;",
        "CryptoHpkePskOpenRequest hpke_psk_open = 67;\n    CryptoHashRequest audit_only = 68;",
      ),
    ),
    fail,
  }),
  /CryptoOperationRequest operation ledger mismatch/,
);

assert.throws(
  () => assertProtoOperationResultsMatchRequests({
    readText: withSourceMutation(
      "crates/proto/proto/reallyme/crypto/v1/crypto.proto",
      (source) => source.replace(
        "CryptoHpkeOpenResult hpke_psk_open = 67;",
        "CryptoHpkeOpenResult hpke_psk_open = 68;",
      ),
    ),
    fail,
  }),
  /CryptoOperationRequest\/CryptoOperationResult branch and field-number parity mismatch/,
);

assert.throws(
  () => assertOperationResponseBranchesMatchLedger({
    ledger: repositoryLedger,
    readText: withSourceMutation(
      "crates/crypto/src/operation_contract/request.rs",
      (source) => source.replace(
        "CryptoOperation::Hash(request) => process_hash_request(*request),",
        "CryptoOperation::Hash(request) => process_mac_verify_request(*request),",
      ),
    ),
    fail,
  }),
  /Rust operation-response branch ledger mismatch/,
);

assert.throws(
  () => assertJniExportsMatchLedger({
    ledger: repositoryLedger,
    readText: withSourceMutation(
      "crates/ffi/src/kotlin_proto.rs",
      (source) => `${source}\npub extern "system" fn Java_me_really_crypto_Unmapped_route() {}\n`,
    ),
    fail,
  }),
  /JNI export ledger mismatch/,
);

assert.throws(
  () => assertNoHandWrittenStructuredJsonContract({
    readText: () => 'const parseOperation = JSON["parse"];',
    fail,
    sourcePaths: ["fixture.ts"],
  }),
  /hand-written structured operation JSON contract/,
);

const wasmLedger = {
  route_groups: [
    {
      id: "wasm.exports",
      symbols: ["allowedExport"],
      owner: "operation.hash.digest",
    },
  ],
};
assert.throws(
  () => assertWasmExportsMatchLedger({
    ledger: wasmLedger,
    readText: (path) => path === "packages/ts/src/wasmModuleTypes.ts"
      ? "export declare function allowedExport(): Uint8Array;"
      : "#[wasm_bindgen(js_name = unmappedExport)]",
    fail,
    sourcePaths: ["new_wasm_module.rs"],
  }),
  /wasm-bindgen public export ledger mismatch/,
);

const rootStructuredLedger = {
  route_groups: [
    {
      id: "rust.root.operation_contract",
      symbols: ["operation_contract::process_operation_response"],
      owner: "operation.proto.process",
    },
  ],
};
assert.doesNotThrow(() => assertRootStructuredRoutesMatchLedger({
  ledger: rootStructuredLedger,
  readText: (path) => path === "operation_contract.rs"
    ? "pub fn process_operation_response() {}"
    : "",
  fail,
  modulePaths: [
    { moduleName: "operation_contract", path: "operation_contract.rs" },
  ],
}));
assert.throws(
  () => assertRootStructuredRoutesMatchLedger({
    ledger: rootStructuredLedger,
    readText: (path) => path === "operation_contract.rs"
      ? "pub fn process_operation_response() {}\npub fn unmapped_route() {}"
      : "",
    fail,
    modulePaths: [
      { moduleName: "operation_contract", path: "operation_contract.rs" },
    ],
  }),
  /root Rust structured operation route ledger mismatch/,
);
