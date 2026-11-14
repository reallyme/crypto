// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::sensitive::{GuardedOwnedView as BuffaOwnedView, GuardedViewError};
use buffa::view::{ViewLifetimeParametric, ViewReborrow};
use buffa::{bytes::Bytes, DecodeError, DecodeOptions};

use crate::contract_constants::proto_wire::{
    CRYPTO_PROTO_RECURSION_LIMIT, MAX_CRYPTO_PROTO_MESSAGE_BYTES,
};

/// Eagerly validated view with private, clearing backing storage.
///
/// Deliberately does not implement `Clone`: callers must explicitly admit a new
/// owner rather than duplicating access to secret-bearing wire storage.
///
/// ```compile_fail
/// use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::CryptoOperationRequestOwnedView;
/// fn duplicate(view: &CryptoOperationRequestOwnedView) -> CryptoOperationRequestOwnedView {
///     (*view).clone()
/// }
/// ```
///
/// The raw Buffa associated handle is also unavailable for private messages:
///
/// ```compile_fail
/// use reallyme_crypto_proto::generated::proto::reallyme::crypto::v1::CryptoOperationRequest;
/// type Raw = <CryptoOperationRequest as buffa::HasMessageView>::ViewHandle;
/// fn duplicate(view: &Raw) -> Raw { (*view).clone() }
/// ```
pub struct GuardedOwnedView<V> {
    inner: BuffaOwnedView<V>,
}

impl<V: ViewLifetimeParametric> GuardedOwnedView<V> {
    /// Copies caller-owned transport storage into an independently clearing owner.
    pub fn decode(bytes: Bytes) -> Result<Self, DecodeError> {
        Self::decode_with_options(bytes, &admission_options())
    }

    /// Applies caller budgets together with mandatory unknown-field rejection.
    pub fn decode_with_options(bytes: Bytes, options: &DecodeOptions) -> Result<Self, DecodeError> {
        let limit = options
            .max_message_size()
            .min(MAX_CRYPTO_PROTO_MESSAGE_BYTES);
        let options = options
            .clone()
            .with_max_message_size(limit)
            .with_recursion_limit(options.recursion_limit().min(CRYPTO_PROTO_RECURSION_LIMIT))
            .reject_unknown_fields();
        let inner = BuffaOwnedView::decode(&bytes, &options).map_err(decode_error)?;
        Ok(Self { inner })
    }

    /// Encodes directly into reserved clearing storage before admitting a view.
    pub fn from_owned(message: &V::Owned) -> Result<Self, DecodeError> {
        let inner =
            BuffaOwnedView::from_owned(message, &admission_options()).map_err(decode_error)?;
        Ok(Self { inner })
    }
}

fn decode_error(error: GuardedViewError) -> DecodeError {
    match error {
        GuardedViewError::Decode(error) => error,
        GuardedViewError::Allocation => DecodeError::ElementMemoryLimitExceeded,
        // Buffa also checks that the encoder honors its declared length.
        _ => DecodeError::MessageTooLarge,
    }
}

fn admission_options() -> DecodeOptions {
    DecodeOptions::new()
        .with_recursion_limit(CRYPTO_PROTO_RECURSION_LIMIT)
        .with_max_message_size(MAX_CRYPTO_PROTO_MESSAGE_BYTES)
        .reject_unknown_fields()
}

impl<V: ViewReborrow> GuardedOwnedView<V> {
    /// Borrows a view whose lifetime is tied to this clearing owner.
    pub fn view(&self) -> &V::Reborrowed<'_> {
        self.inner.view()
    }

    /// Copies fields into their generated clearing owners without a panic path.
    pub fn to_owned_message(&self) -> Result<V::Owned, DecodeError> {
        self.inner.to_owned_message()
    }

    /// Borrows wire bytes without exposing a clonable reference-counted handle.
    pub fn bytes(&self) -> &[u8] {
        self.inner.bytes()
    }
}

impl<V> core::fmt::Debug for GuardedOwnedView<V> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("GuardedOwnedView(<redacted>)")
    }
}

impl<V: zeroize::ZeroizeOnDrop> zeroize::ZeroizeOnDrop for GuardedOwnedView<V> {}

impl<V> serde::Serialize for GuardedOwnedView<V> {
    fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom(
            crate::error_types::CryptoError::PROVIDER_ACCESS_DENIED,
        ))
    }
}
