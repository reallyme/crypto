<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Algorithm Lifecycle

ReallyMe Crypto changes algorithm support only with matching code, vectors,
provider policy, generated contracts, package documentation, and release
readiness checks.

## Adding An Algorithm

An added algorithm needs:

- a typed algorithm identifier and domain errors;
- one semantic operation owner;
- provider-manifest entries for every SDK lane;
- positive vectors and malformed-input or tamper vectors;
- protobuf identifiers or an explicit decision that the operation is facade
  only;
- SDK package tests for every supported lane;
- release-readiness assertions for generated code, package exports, and
  provider policy.

## Changing Support

Provider support can move from unsupported to supported only when the selected
provider is explicit and tested. A supported lane can move to unsupported only
with a release note, stable typed failure behavior, and conformance evidence
that callers do not see traps, raw backend exceptions, or silent fallback.

Raw-key routes and platform-resident routes are separate lifecycle surfaces.
For example, P-256 ECDSA over raw keys and P-256 Secure Enclave signing have
different residency, nondeterminism, lifecycle, and access-control behavior.

## Removing Or Reserving

Public removals require semver review. Protobuf field numbers, enum values,
and names that are removed from the public contract must be reserved. Package
facades must document replacements and tests must prove removed names do not
remain accidentally exported.

`CryptoOperationResponse` is the structured response contract. Replacements
for any future removal must be available before the old surface is retired.

## Negative Coverage

Every exposed primitive needs happy-path and negative coverage. Required
negative cases include invalid lengths and encodings, tampered ciphertexts,
tags, signatures, proofs, wrong AAD or context, unsupported suites, empty input
where forbidden, maximum accepted input, and checked arithmetic boundaries.
