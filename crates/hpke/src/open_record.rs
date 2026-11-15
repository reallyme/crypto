// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use hpke::{
    aead::{Aead, AeadCtxR, AeadTag},
    kdf::Kdf,
    Deserializable, Kem,
};
use zeroize::Zeroizing;

use crate::{HpkeError, HPKE_AEAD_TAG_LEN};

pub(crate) fn open_record<A: Aead, D: Kdf, K: Kem>(
    context: &mut AeadCtxR<A, D, K>,
    aad: &[u8],
    record: &[u8],
) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
    crypto_core::authenticate_record::<HPKE_AEAD_TAG_LEN>(record, |output, tag| {
        let tag =
            AeadTag::<A>::from_bytes(tag).map_err(|_| HpkeError::PRIMITIVE_MALFORMED_CIPHERTEXT)?;
        context
            .open_inout_detached(output.into(), aad, &tag)
            .map_err(|_| HpkeError::PRIMITIVE_AUTHENTICATION_FAILED)
    })
}
