// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/** Providers compiled into the TypeScript package. */
export const REALLYME_CRYPTO_PROVIDERS = [
  "@noble/curves",
  "@noble/hashes",
  "ReallyMe Rust WASM",
] as const;

export type ReallyMeCryptoProvider = (typeof REALLYME_CRYPTO_PROVIDERS)[number];

/**
 * Compile-time provider catalog used by package consumers and conformance
 * tests to assert that TypeScript crypto is backed by explicit provider
 * packages.
 */
export const compiledProviders: readonly ReallyMeCryptoProvider[] =
  REALLYME_CRYPTO_PROVIDERS;
