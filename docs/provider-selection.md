<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Provider Selection

Provider selection is explicit, deterministic, and fail-closed. A missing,
unsupported, unavailable, or malformed provider does not silently fall back to a
different implementation.

Rust algorithm dispatch exposes an inspectable `ProviderDecision` before
execution. The record identifies the requested operation and algorithm,
selected or rejected disposition, provider kind, native or WASM lane, fixed
policy reason, key residency, key-copy boundary, output cleanup policy, and the
fact that fallback is prohibited. Dispatch rejects an operation/algorithm or
feature mismatch with a typed unsupported error and does not try another lane.
The dispatch policy is published by `crates/crypto/dispatch`; semantic
implementations remain in their owning primitive or protocol crate.

## Provider Manifest

`provider_manifest.json` records every package-exposed algorithm and the lane
status for Swift, Kotlin/JVM, Android, and TypeScript/WASM. Lane statuses are:

- `supported`: the lane has a normal package route.
- `provider_aware`: the lane has an explicit provider requirement, such as a
  Rust C ABI library or hardware-backed provider.
- `partial`: the lane intentionally exposes only part of the operation family.
- `unsupported`: the lane must return typed unsupported behavior.

Every lane also records provider names, whether Rust is used, the package API,
and the required fallback behavior.

## Fallback Policy

The only accepted fallback behaviors are typed provider failure, typed
unsupported algorithm, or explicit provider required. SDK adapters must not
catch provider failure and retry another provider unless that selection is a
documented operation policy with tests and manifest coverage.

Provider errors must not include keys, plaintexts, protocol contexts, file
paths, raw provider exception text, or untrusted input.

## Platform Keys

Hardware-backed keys are residency objects. Swift Secure Enclave and Android
Keystore or StrongBox routes use opaque handles and lifecycle controls;
they are not serialized private keys and are not interchangeable with raw-key
facade parameters.

Android P-256 signing and ECDH use `ReallyMeAndroidPlatformKeys` in the Android
AAR. Application tags are hashed into purpose-separated aliases, requested
StrongBox residency never downgrades to TEE, and post-generation `KeyInfo`
inspection rejects software-backed, purpose-mismatched, and indeterminate
security-level keys. The complete platform-key API requires API 31 so signing
and ECDH both use exact security-level evidence; Android's
`PURPOSE_AGREE_KEY` contract also begins there.

Hardware-backed operations must fail closed when the platform, access policy,
handle, entitlement, or hardware state is unavailable. Tests cover handle
validation, duplicate handles, round trips where hardware is available, and
typed unsupported behavior where it is not.
