<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Release Notes

## 0.2.0

- ReallyMe Crypto now treats the canonical SDK contract as the combination of
  protobuf messages and enums, provider manifest policy, typed errors,
  algorithm identifiers, and cross-language conformance vectors.
- The legacy `reallyme.codec.v1` protobuf/package surface was removed from
  this repository because Codec is now consumed from the standalone
  ReallyMe Codec packages. This is a package and repository surface removal,
  not a `reallyme.crypto.v1` wire break; the Crypto protobuf changes in this
  release are additive. The `reallyme.codec.v1` package name is permanently retired in this repository and must not be reused here.
