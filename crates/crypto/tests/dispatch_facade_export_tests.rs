// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Public export-parity tests for the root dispatch facade.

#![cfg(feature = "dispatch")]

use crypto_core::Algorithm;
use crypto_dispatch::AlgorithmError;
use zeroize::Zeroizing;

type DeriveKeypairFunction =
    fn(Algorithm, &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AlgorithmError>;

#[test]
fn root_facade_exports_dispatch_keypair_derivation() {
    let root: DeriveKeypairFunction = reallyme_crypto::dispatch::derive_keypair;
    let dispatch: DeriveKeypairFunction = crypto_dispatch::derive_keypair;

    // Function-pointer assignment proves the two public routes have the same
    // typed contract without generating or retaining secret material.
    let _ = (root, dispatch);
}
