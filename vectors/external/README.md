<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# External Crypto Test Vectors

This directory contains unmodified external test-vector corpora used to
supplement the generated ReallyMe conformance vectors.

## Sources

- `nist-acvp/`: NIST ACVP sample vector files pinned to
  `usnistgov/ACVP-Server` commit
  `15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0`.
- `cctv/`: C2SP CCTV ML-KEM vectors pinned to `C2SP/CCTV` commit
  `1e3d2860d46e94e777e1b17c7a6f2436387e3ecc`.

The `provenance.json` file is the authoritative local index. It records the
source website, immutable upstream commit, retrieval date, license status, and
SHA-256 hash for each vendored file.

Raw source files must stay byte-for-byte identical to upstream. Any normalization
or adapter logic belongs in conformance tests, not beside the raw corpus.

## Execution

The default external-corpus conformance tests validate provenance and raw file
shape. The manual audit runner executes the practical NIST ACVP subset that
matches the current public Rust primitive boundary:

```sh
cargo test -p external-vector-audit --no-default-features --features native
```

The CCTV ML-KEM corpus remains vendored for security review and future adapter
work, but it is not executed by default because the pinned vectors do not match
the final-FIPS RustCrypto `ml-kem` backend currently used by this repository.
