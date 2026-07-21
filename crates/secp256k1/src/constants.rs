// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

/// Length in bytes of a secp256k1 secret scalar.
pub const SECP256K1_SECRET_KEY_LEN: usize = 32;
/// Length in bytes of a BIP-340 x-only secp256k1 public key.
pub const BIP340_SCHNORR_PUBLIC_KEY_LEN: usize = 32;
/// Length in bytes of a BIP-340 message digest.
pub const BIP340_SCHNORR_MESSAGE_LEN: usize = 32;
/// Length in bytes of BIP-340 auxiliary signing randomness.
pub const BIP340_SCHNORR_AUX_RAND_LEN: usize = 32;
/// Length in bytes of a BIP-340 Schnorr signature.
pub const BIP340_SCHNORR_SIGNATURE_LEN: usize = 64;
