<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Dependency Boundaries

ReallyMe Crypto treats dependency direction as part of the security contract.
The workspace enforces this dependency order:

```text
bindings and transports
-> public facade
-> operation interfaces
-> provider interfaces
-> algorithm implementations
```

Dependencies may point only to the same layer or a lower layer in that order.
Algorithm implementations must not depend on SDK transports, generated package
glue, provider registries, or public facades. Provider interfaces may depend on
algorithm implementations and typed model values, but they must not call C ABI,
JNI, Swift, Kotlin, or TypeScript adapters.

## Codec And Protobuf

`crates/proto` owns generated protobuf messages, binary protobuf limits,
restricted ProtoJSON request decoding, strict unknown-field policy, and bounded
typed wire decoding. Secret-bearing JSON selectors are rejected before value
deserialization. The operation layer may depend on that public wire contract, but
generated protobuf code does not own semantic operation behavior.

ReallyMe Codec dependencies are release-provenance dependencies. Rust
publishable crates use reviewed crates.io `reallyme-codec-*` packages with
lockfile source and checksum evidence. Swift, Kotlin/JVM, Android, and
TypeScript use their ecosystem-specific codec packages, each with separate
package-manager provenance.

## Package Dependencies

Package lanes use the package manager for their ecosystem:

- Rust crates resolve through Cargo with locked registry checksums.
- TypeScript resolves `@reallyme/codec` and pinned crypto dependencies through
  npm lockfiles and package checks.
- Swift resolves the Codec package through SwiftPM and `Package.resolved`.
- Kotlin/JVM and Android use strict Gradle dependency verification and Maven
  provenance records.

External path dependencies are not release evidence unless an approved strategy
records the exact checkout and package identity. Release checks reject
unrecorded local sibling dependency paths for publishable artifacts.

## Build And Runtime Boundaries

Generated code, native binaries, and WASM artifacts are release artifacts.
Readiness checks inspect generated freshness, raw WASM import/export parity,
Gradle verification metadata, native-resource manifests, C ABI headers, and
Swift binary artifact checksums before package publication.
