// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

export type ReallyMeWasmInitOutput = Readonly<{
  memory: unknown;
}>;

export declare function initSync(module: {
  module: Uint8Array;
}): ReallyMeWasmInitOutput;

export declare function aes256GcmOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertextWithTag: Uint8Array,
): Uint8Array;

export declare function aes256GcmSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array;

export declare function aes256GcmSivOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertextWithTag: Uint8Array,
): Uint8Array;

export declare function aes256GcmSivSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array;

export declare function aes256KwUnwrapKey(
  wrappingKey: Uint8Array,
  wrappedKey: Uint8Array,
): Uint8Array;

export declare function aes256KwWrapKey(
  wrappingKey: Uint8Array,
  keyToWrap: Uint8Array,
): Uint8Array;

export declare function argon2idDeriveKey(
  kdfVersion: number,
  secret: Uint8Array,
  salt: Uint8Array,
): Uint8Array;

export declare function base64urlDecode(encoded: string): Uint8Array;

export declare function base64urlEncode(bytes: Uint8Array): string;

export declare function dagCborComputeCid(bytes: Uint8Array): string;

export declare function dagCborVerifyCid(cid: string, bytes: Uint8Array): unknown;

export declare function multibaseBase58btcEncode(bytes: Uint8Array): string;

export declare function multibaseBase64urlEncode(bytes: Uint8Array): string;

export declare function multibaseDecode(encoded: string): Uint8Array;

export declare function multicodecLookupPrefix(bytes: Uint8Array): unknown;

export declare function multicodecPrefixForName(codecName: string): unknown;

export declare function multikeyEncode(
  codecName: string,
  publicKey: Uint8Array,
): string;

export declare function multikeyParse(multikey: string): unknown;

export declare function hpkeOpenBase(
  suite: number,
  recipientSecretKey: Uint8Array,
  encapsulatedKey: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array;

export declare function hpkeSealBase(
  suite: number,
  recipientPublicKey: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): unknown;

export declare function hpkeSealBaseDerand(
  suite: number,
  recipientPublicKey: Uint8Array,
  encapsulationRandomness: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): unknown;

export declare function mlKem512GenerateKeypair(): unknown;

export declare function mlKem512DeriveKeypair(secretKey: Uint8Array): unknown;

export declare function mlKem512Encapsulate(publicKey: Uint8Array): unknown;

export declare function mlKem512EncapsulateDerand(
  publicKey: Uint8Array,
  randomness: Uint8Array,
): unknown;

export declare function mlKem512Decapsulate(
  ciphertext: Uint8Array,
  secretKey: Uint8Array,
): Uint8Array;

export declare function mlKem768GenerateKeypair(): unknown;

export declare function mlKem768DeriveKeypair(secretKey: Uint8Array): unknown;

export declare function mlKem768Encapsulate(publicKey: Uint8Array): unknown;

export declare function mlKem768EncapsulateDerand(
  publicKey: Uint8Array,
  randomness: Uint8Array,
): unknown;

export declare function mlKem768Decapsulate(
  ciphertext: Uint8Array,
  secretKey: Uint8Array,
): Uint8Array;

export declare function mlKem1024GenerateKeypair(): unknown;

export declare function mlKem1024DeriveKeypair(secretKey: Uint8Array): unknown;

export declare function mlKem1024Encapsulate(publicKey: Uint8Array): unknown;

export declare function mlKem1024EncapsulateDerand(
  publicKey: Uint8Array,
  randomness: Uint8Array,
): unknown;

export declare function mlKem1024Decapsulate(
  ciphertext: Uint8Array,
  secretKey: Uint8Array,
): Uint8Array;

export declare function mlDsa44GenerateKeypair(): unknown;

export declare function mlDsa44DeriveKeypair(secretKey: Uint8Array): unknown;

export declare function mlDsa44Sign(
  secretKey: Uint8Array,
  message: Uint8Array,
): Uint8Array;

export declare function mlDsa44Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): void;

export declare function mlDsa65GenerateKeypair(): unknown;

export declare function mlDsa65DeriveKeypair(secretKey: Uint8Array): unknown;

export declare function mlDsa65Sign(
  secretKey: Uint8Array,
  message: Uint8Array,
): Uint8Array;

export declare function mlDsa65Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): void;

export declare function mlDsa87GenerateKeypair(): unknown;

export declare function mlDsa87DeriveKeypair(secretKey: Uint8Array): unknown;

export declare function mlDsa87Sign(
  secretKey: Uint8Array,
  message: Uint8Array,
): Uint8Array;

export declare function mlDsa87Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): void;

export declare function slhDsaSha2128sGenerateKeypair(): unknown;

export declare function slhDsaSha2128sDeriveKeypair(
  skSeed: Uint8Array,
  skPrf: Uint8Array,
  pkSeed: Uint8Array,
): unknown;

export declare function slhDsaSha2128sSign(
  secretKey: Uint8Array,
  message: Uint8Array,
): Uint8Array;

export declare function slhDsaSha2128sVerify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): void;

export declare function chacha20Poly1305Open(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertextWithTag: Uint8Array,
): Uint8Array;

export declare function chacha20Poly1305Seal(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array;

export declare function xchacha20Poly1305Open(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertextWithTag: Uint8Array,
): Uint8Array;

export declare function xchacha20Poly1305Seal(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array;

export declare function xWing1024Decapsulate(
  ciphertext: Uint8Array,
  secretKey: Uint8Array,
): Uint8Array;

export declare function xWing1024DeriveKeypair(secretKey: Uint8Array): unknown;

export declare function xWing1024Encapsulate(publicKey: Uint8Array): unknown;

export declare function xWing1024EncapsulateDerand(
  publicKey: Uint8Array,
  seed: Uint8Array,
): unknown;

export declare function xWing1024GenerateKeypair(): unknown;

export declare function xWing768Decapsulate(
  ciphertext: Uint8Array,
  secretKey: Uint8Array,
): Uint8Array;

export declare function xWing768DeriveKeypair(secretKey: Uint8Array): unknown;

export declare function xWing768Encapsulate(publicKey: Uint8Array): unknown;

export declare function xWing768EncapsulateDerand(
  publicKey: Uint8Array,
  seed: Uint8Array,
): unknown;

export declare function xWing768GenerateKeypair(): unknown;
