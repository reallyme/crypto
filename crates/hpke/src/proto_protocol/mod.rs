// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native protocol ownership remains authoritative at every protobuf boundary.
//!
//! Live context state stays non-cloneable, non-serializable and non-shared.
//! These restrictions are checked independently so changing either owner cannot
//! be hidden by the other owner retaining a stricter bound.
//!
//! ```compile_fail
//! fn duplicate(value: &crypto_hpke::HpkeSenderContext) -> crypto_hpke::HpkeSenderContext { value.clone() }
//! ```
//! ```compile_fail
//! fn duplicate(value: &crypto_hpke::HpkeReceiverContext) -> crypto_hpke::HpkeReceiverContext { value.clone() }
//! ```
//! ```compile_fail
//! fn serialize(value: &crypto_hpke::HpkeSenderContext) { let _ = serde_json::to_vec(value); }
//! ```
//! ```compile_fail
//! fn serialize(value: &crypto_hpke::HpkeReceiverContext) { let _ = serde_json::to_vec(value); }
//! ```
//! ```compile_fail
//! fn shared<T: Sync>() {} fn check() { shared::<crypto_hpke::HpkeSenderContext>(); }
//! ```
//! ```compile_fail
//! fn shared<T: Sync>() {} fn check() { shared::<crypto_hpke::HpkeReceiverContext>(); }
//! ```

mod support;
pub use support::{aead_capability, kdf_capability, kem_capability};
#[cfg(feature = "base-p256-aes128gcm")]
mod base_p256;
#[cfg(feature = "base-p256-aes128gcm")]
mod base_p256_recipient;
#[cfg(feature = "backend-native")]
mod content;
#[cfg(feature = "backend-native")]
mod requests;
#[cfg(feature = "backend-native")]
mod setup;

#[cfg(feature = "base-p256-aes128gcm")]
pub use base_p256::{p256_base_capabilities, P256BaseOpenInputs, P256BaseSealInputs};
#[cfg(feature = "base-p256-aes128gcm")]
pub use base_p256_recipient::{
    P256BaseRecipientGenerateInputs, P256BaseRecipientImportInputs, P256BaseRecipientOutput,
};
#[cfg(feature = "backend-native")]
pub use content::{
    sender_seal_public_result, HpkeReceiverOpenInputs, HpkeReceiverOpenRequest,
    HpkeSenderSealInputs, HpkeSenderSealRequest,
};
#[cfg(feature = "backend-native")]
pub use requests::{
    HpkeOpenInputs, HpkePskOpenInputs, HpkePskSealInputs, HpkeReceiverExportInputs, HpkeSealInputs,
    HpkeSenderExportInputs,
};
#[cfg(feature = "backend-native")]
pub use setup::{
    receiver_setup_public_result, HpkePskReceiverSetupInputs, HpkePskSenderSetupInputs,
};
