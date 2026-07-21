<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# ReallyMe Kotlin Vector Conformance

This Gradle project is a Kotlin/JVM conformance harness, not the ReallyMe
Kotlin or Android SDK. It verifies shared vectors against JCA/JCE and
BouncyCastle provider behavior.

The SDK package lives at `packages/kotlin` and consumes the ReallyMe C ABI
where platform providers are not sufficient.

Dependency verification metadata is committed in
`gradle/verification-metadata.xml`. Regenerate it only as a reviewed
supply-chain event:

```sh
./gradlew --write-verification-metadata sha256 help
```

## Run

```sh
cd crates/conformance/platform/kotlin
./gradlew test --rerun-tasks
```

Set `REALLYME_CRYPTO_VECTORS_DIR` to test against a non-default vector
directory. Use `--rerun-tasks` for verification runs so Gradle executes the vector
tests on the current machine instead of returning an up-to-date result.
