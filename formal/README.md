# Formal verification

Kani checks bounded Rust properties; Tamarin checks symbolic HPKE models.
Neither establishes correctness of the complete library, constant-time machine
code or physical memory erasure. Results apply to the source revision,
lockfile, features and assumptions of the run.

[Formal Verification](../.github/workflows/formal-verification.yml) runs for
every CI candidate. Required CI accepts its source SHA receipt only after all
Tamarin and Kani jobs pass. Package preflight and publication require successful
CI evidence for the exact release commit; proof results cannot carry forward
from an earlier commit.

## Rust implementation proofs

Harnesses live beside the production modules and in [`hpke/`](hpke/). They cover:

- operation admission, algorithm-family selection and restricted providers;
- authenticated plaintext release through Rust, C, JNI and WASM boundaries;
- C pointer-range arithmetic;
- HPKE component IDs, nonce derivation and sequence-state transitions;
- selected ML-KEM encoding/admission, X-Wing transcript, ECDSA scalar,
  X25519/X448 release, AES-KW schedule and Keccak-round properties.

Inspect each harness's symbolic input bounds and stubs before interpreting its
result. Cipher, provider or decoder stubs prove only the modeled handoff or
selection behavior. Ownership proofs do not establish that every physical copy
has been erased. A host proof of WASM routing does not execute a WASM target.

Install Kani 0.68.0 and cache the locked dependencies:

```sh
cargo install --locked kani-verifier@0.68.0
cargo kani setup
cargo fetch --locked
```

Examples from the verification matrix:

```sh
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-proto --features generated
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-core -Z stubbing
CARGO_NET_OFFLINE=true cargo kani -p crypto-ffi --lib -Z stubbing --jobs 2 --output-format terse
CARGO_NET_OFFLINE=true cargo kani -p reallyme-crypto-wasm --lib --jobs 2 --output-format terse
python3 -B formal/hpke/verify.py
```

Use the workflow's exact Cargo profiles and flags for the full matrix. The
locked-package runner requires Python 3.12+, verifies source archives against
`Cargo.lock`, and creates isolated temporary builds. Some categories require
`RUSTFLAGS="--cfg miri"` to select portable arithmetic. The
[reference DER encoder](../tools/external-vector-audit/src/refenc.rs) has a
separate proof job.

## Symbolic HPKE model

[`tamarin/hpke.spthy`](tamarin/hpke.spthy) models single-record Base and PSK
modes. It checks plaintext secrecy, agreement on setup/record inputs and exporter
binding under ideal DH, derivation and authenticated-encryption assumptions.
It does not prove byte encodings, concrete cipher security or Base-mode sender
authentication.

[`tamarin/hpke_pq.spthy`](tamarin/hpke_pq.spthy) models ML-KEM implicit rejection
and X-Wing composition in Base and PSK modes at sequence zero. It assumes an
uncompromised recipient and ideal primitives; it does not prove rejection timing
or the computational security of the combiner.

With Tamarin 1.12.0, Maude 3.5.1 and OpenSSL on `PATH`:

```sh
bash formal/tamarin/verify.sh
```

The runner requires all expected lemmas to be present and verified. A timeout,
skip or incomplete verdict is not a successful proof.

## HPKE record sequences

The locked backend audit checks key-schedule and exporter bytes and record
sequences against the committed RFC 9180 and PQ HPKE corpora. It uses live
sender/receiver contexts, checks rejection followed by a valid retry, and tests
cross-context records.

```sh
python3 -B formal/hpke/check_schedule_vectors.py
cargo test --locked -p external-vector-audit --no-default-features --features native --test rfc9180_hpke --test hpke_pq
```

These vector tests exercise concrete implementations; they are separate from
the symbolic proofs. Source references and corpus reproduction commands are in
[external conformance vectors](../docs/external-conformance-vectors.md).
