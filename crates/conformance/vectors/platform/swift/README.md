<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# ReallyMeCryptoVectorConformance

This Swift package is a conformance harness, not the ReallyMe Swift SDK. It
proves the shared vectors against CryptoKit, Bitcoin Core libsecp256k1 via
the [reallyme/CSecp256k1](https://github.com/reallyme/CSecp256k1) binary
package, and selected ReallyMe C ABI symbols.

The SDK package lives at `packages/swift` and consumes the same C ABI surface
where Apple-native APIs are not the right provider.

## Run

```sh
swift test --package-path crates/conformance/vectors/platform/swift
```

The tests read vectors from the repository-level `vectors/` directory.
