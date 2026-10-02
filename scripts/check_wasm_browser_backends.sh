#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ReallyMe LLC
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set -euo pipefail

# These tests execute the primitive crates in a real browser. The TypeScript
# browser suite covers its facade, but cannot establish that each crate's
# backend-specific browser tests were compiled and executed.
wasm-pack test --headless --chrome crates/aes256-gcm --no-default-features --features wasm --test wasm_backend_tests
wasm-pack test --headless --chrome crates/ed25519 --no-default-features --features wasm --test wasm_backend_tests
wasm-pack test --headless --chrome crates/x25519 --no-default-features --features wasm --test wasm_backend_tests
wasm-pack test --headless --chrome crates/secp256k1 --no-default-features --features wasm --test wasm_boundary_tests
