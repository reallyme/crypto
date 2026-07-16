<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# Security Policy

`reallyme-crypto` is cryptographic infrastructure. We take vulnerability
reports seriously and appreciate coordinated disclosure.

## Reporting a Vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through either channel:

- GitHub private vulnerability reporting: use the **"Report a vulnerability"**
  button under this repository's **Security** tab
  (`Security` → `Advisories` → `Report a vulnerability`).
- Email: **security@really.me**. For end-to-end encrypted disclosure, request
  our current PGP key in a first, contentless message; we will reply with it
  before you send details.

Please include, to the extent you can:

- the affected crate, function, and lane (`native` / `wasm` / `swift` /
  `kotlin`);
- the commit or version you tested;
- a minimal reproduction (input bytes, steps, or a failing test);
- your assessment of impact (e.g. key recovery, forgery, panic/DoS,
  side-channel).

## What to Expect

- **Acknowledgement** within 3 business days.
- **Triage and initial assessment** within 10 business days, including a
  severity rating and whether we can reproduce.
- **Coordinated disclosure**: we aim to ship a fix and publish an advisory
  within 90 days of triage, sooner for actively exploited issues. We will
  agree on a disclosure date with you and credit you unless you prefer to
  remain anonymous.

We will keep you updated as the fix progresses and will let you know if we
need more time or information.

## Scope

In scope — vulnerabilities in this repository's code, for example:

- key recovery, signature forgery, or authentication bypass;
- incorrect cryptographic output versus the referenced standard (FIPS 203/204,
  RFC 8032/6979/8785/8439, SEC1, etc.);
- panics, unbounded allocation, or stack exhaustion reachable from untrusted
  input (denial of service);
- timing or other side channels in secret-dependent code paths;
- secret material that is not zeroized, or that leaks through errors, logs,
  or the FFI boundary;
- a platform lane silently substituting a different cryptographic backend
  than the one selected.

Out of scope:

- vulnerabilities in dependencies (report those upstream; tell us so we can
  pin or mitigate);
- issues that require an already-compromised host, a malicious build
  toolchain, or physical access;
- missing hardening that has no concrete exploit (send it as a normal issue
  or pull request).

## Supported Versions

Security fixes are released on the active package line.

| Version | Status |
| --- | --- |
| `0.1.x` | Supported |
| earlier commits | Unsupported |

For source-based consumption, pin a release tag or exact commit and watch
GitHub releases and security advisories.

## Cryptography And Assurance

- We do not implement cryptographic primitives from scratch; we wrap vetted
  implementations (RustCrypto, `ed25519-dalek`, `x25519-dalek`, `ml-kem`,
  `ml-dsa`, BouncyCastle, Bitcoin Core `libsecp256k1` through
  `reallyme/CSecp256k1`) and platform crypto (CryptoKit, JCA/JCE) behind a
  uniform, misuse-resistant API.
- Cross-implementation conformance vectors pin our Rust output against an
  independent oracle (`@noble/*`), including deterministic ML-KEM
  encapsulation, implicit rejection, and deterministic ML-DSA signatures.
- The untrusted-input parsers (multibase, multicodec, multikey, base64url,
  DAG-CBOR, RSA/ECDSA DER) have coverage-guided fuzz harnesses in `fuzz/` that
  assert they never panic or read out of bounds on arbitrary input.
- The HPKE Base composition has a machine-checked Tamarin model in `formal/`
  proving plaintext confidentiality against a network adversary.
- Provider choice is part of the security contract. The generated backend
  matrix in `PROVIDER_POLICY.md` records each Swift, Kotlin/JVM,
  Kotlin/Android, and TypeScript/WASM lane; unsupported lanes must fail with a
  typed unsupported-algorithm result instead of silently choosing another
  backend.

See [`SECURITY_MEMORY_MODEL.md`](SECURITY_MEMORY_MODEL.md) for the
secret-memory model and operational controls this codebase is held to.
