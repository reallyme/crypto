// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validated prime-order groups with protected supplied-base operations.
//!
//! Elements can represent secret intermediate points. Encoding is therefore an
//! explicit borrow; neither elements nor private scalars implement `Debug` or
//! `Clone`. Protocol identifiers, transcripts and authentication policy belong to
//! callers. Only the built-in, cofactor-one EC and RFC 5114 domains are accepted.

mod dh;
mod domain;
mod ec;
mod element;
mod error;
mod field;
#[cfg(feature = "operation-response")]
mod identity;
mod legacy_curves;
mod map;
mod parameters;
mod scalar;
mod secret;

#[cfg(feature = "operation-response")]
pub mod contract;

use crypto_core::CryptoError;

pub use domain::PrimeGroup;
pub use element::GroupElement;
pub use error::GroupError;
pub use scalar::GroupScalar;
