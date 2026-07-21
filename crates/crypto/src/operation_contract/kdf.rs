// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! KDF-specific generated request conversion and semantic execution.

#[cfg(any(
    all(feature = "kmac", any(feature = "native", feature = "wasm")),
    all(feature = "hkdf", any(feature = "native", feature = "wasm")),
    all(feature = "argon2id", any(feature = "native", feature = "wasm")),
    all(feature = "pbkdf2", any(feature = "native", feature = "wasm")),
    all(feature = "concat-kdf", any(feature = "native", feature = "wasm"))
))]
use buffa::MessageField;
#[cfg(all(feature = "pbkdf2", any(feature = "native", feature = "wasm")))]
use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoKdfDeriveKeyRequest;
#[cfg(all(
    any(feature = "argon2id", feature = "pbkdf2"),
    any(feature = "native", feature = "wasm")
))]
use crypto_proto::generated::proto::reallyme::crypto::v1::CryptoKdfDeriveKeyResult;
#[cfg(any(
    all(feature = "kmac", any(feature = "native", feature = "wasm")),
    all(feature = "argon2id", any(feature = "native", feature = "wasm")),
    all(feature = "pbkdf2", any(feature = "native", feature = "wasm")),
    all(feature = "concat-kdf", any(feature = "native", feature = "wasm"))
))]
use crypto_proto::generated::proto::reallyme::crypto::v1::KdfAlgorithm as ProtoKdf;
#[cfg(all(feature = "argon2id", any(feature = "native", feature = "wasm")))]
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    Argon2idKdfVersion, CryptoArgon2idDeriveRequest,
};
#[cfg(all(feature = "hkdf", any(feature = "native", feature = "wasm")))]
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoHkdfDeriveRequest, CryptoHkdfDeriveResult,
};
#[cfg(all(feature = "concat-kdf", any(feature = "native", feature = "wasm")))]
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoJwaConcatKdfSha256DeriveRequest, CryptoJwaConcatKdfSha256DeriveResult,
};
#[cfg(all(feature = "kmac", any(feature = "native", feature = "wasm")))]
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    CryptoKmac256DeriveRequest, CryptoKmac256DeriveResult,
};
#[cfg(any(
    all(feature = "kmac", any(feature = "native", feature = "wasm")),
    all(feature = "hkdf", any(feature = "native", feature = "wasm")),
    all(feature = "argon2id", any(feature = "native", feature = "wasm")),
    all(feature = "pbkdf2", any(feature = "native", feature = "wasm")),
    all(feature = "concat-kdf", any(feature = "native", feature = "wasm"))
))]
use crypto_proto::wire::CryptoWireError;

#[cfg(all(feature = "hkdf", any(feature = "native", feature = "wasm")))]
use super::algorithms::hkdf_suite;
#[cfg(any(
    all(feature = "kmac", any(feature = "native", feature = "wasm")),
    all(feature = "hkdf", any(feature = "native", feature = "wasm")),
    all(feature = "argon2id", any(feature = "native", feature = "wasm")),
    all(feature = "pbkdf2", any(feature = "native", feature = "wasm")),
    all(feature = "concat-kdf", any(feature = "native", feature = "wasm"))
))]
use super::algorithms::kdf_identifier;
#[cfg(all(feature = "pbkdf2", any(feature = "native", feature = "wasm")))]
use super::algorithms::pbkdf2_prf;
#[cfg(all(feature = "argon2id", any(feature = "native", feature = "wasm")))]
use super::algorithms::require_argon2id;
#[cfg(all(feature = "concat-kdf", any(feature = "native", feature = "wasm")))]
use super::algorithms::require_jwa_concat_kdf_sha256;
#[cfg(all(feature = "kmac", any(feature = "native", feature = "wasm")))]
use super::algorithms::require_kmac256;
#[cfg(any(
    all(feature = "kmac", any(feature = "native", feature = "wasm")),
    all(feature = "hkdf", any(feature = "native", feature = "wasm")),
    all(feature = "argon2id", any(feature = "native", feature = "wasm")),
    all(feature = "pbkdf2", any(feature = "native", feature = "wasm")),
    all(feature = "concat-kdf", any(feature = "native", feature = "wasm"))
))]
use super::operation_error::map_operation_error;
#[cfg(any(
    all(feature = "kmac", any(feature = "native", feature = "wasm")),
    all(feature = "hkdf", any(feature = "native", feature = "wasm")),
    all(feature = "argon2id", any(feature = "native", feature = "wasm")),
    all(feature = "pbkdf2", any(feature = "native", feature = "wasm")),
    all(feature = "concat-kdf", any(feature = "native", feature = "wasm"))
))]
use super::wire_error::invalid_parameter;

#[cfg(all(feature = "kmac", any(feature = "native", feature = "wasm")))]
pub(super) fn process_kmac256_derive(
    request: CryptoKmac256DeriveRequest,
) -> Result<CryptoKmac256DeriveResult, CryptoWireError> {
    require_kmac256(&request.algorithm)?;
    let output_length = usize::try_from(request.output_length).map_err(|_| invalid_parameter())?;
    let key = crate::kmac::Kmac256Key::from_slice(&request.key).map_err(CryptoWireError::from)?;
    let derived = crate::operations::kdf::derive_kmac256(
        &key,
        &request.context,
        &request.customization,
        output_length,
    )
    .map_err(map_operation_error)?;
    Ok(CryptoKmac256DeriveResult {
        algorithm: MessageField::some(kdf_identifier(ProtoKdf::KDF_ALGORITHM_KMAC_256)),
        derived_key: derived.as_bytes().to_vec(),
        __buffa_unknown_fields: Default::default(),
    })
}

#[cfg(all(feature = "hkdf", any(feature = "native", feature = "wasm")))]
pub(super) fn process_hkdf_derive(
    request: CryptoHkdfDeriveRequest,
) -> Result<CryptoHkdfDeriveResult, CryptoWireError> {
    let (suite, proto_suite) = hkdf_suite(&request.algorithm)?;
    let ikm = crate::hkdf::HkdfInputKeyMaterial::from_slice(&request.input_key_material);
    let salt = if request.salt.is_empty() {
        None
    } else {
        Some(crate::hkdf::HkdfSalt::from_slice(&request.salt))
    };
    let info = crate::hkdf::HkdfInfo::from_slice(&request.info);
    let derive_request = crate::hkdf::DeriveRequest {
        suite,
        ikm: &ikm,
        salt: salt.as_ref(),
        info: &info,
    };
    let output = derive_hkdf_to_vec(&derive_request, request.output_length)?;
    Ok(CryptoHkdfDeriveResult {
        algorithm: MessageField::some(kdf_identifier(proto_suite)),
        output_key_material: output,
        __buffa_unknown_fields: Default::default(),
    })
}

#[cfg(all(feature = "argon2id", any(feature = "native", feature = "wasm")))]
pub(super) fn process_argon2id_derive(
    request: CryptoArgon2idDeriveRequest,
) -> Result<CryptoKdfDeriveKeyResult, CryptoWireError> {
    require_argon2id(&request.algorithm)?;
    let kdf_version = match request.kdf_version.as_known() {
        Some(Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V1) => 1,
        Some(Argon2idKdfVersion::ARGON2ID_KDF_VERSION_V2) => 2,
        Some(Argon2idKdfVersion::ARGON2ID_KDF_VERSION_UNSPECIFIED) | None => {
            return Err(invalid_parameter());
        }
    };
    let derived = crate::operations::kdf::derive_argon2id_for_version(
        kdf_version,
        &request.secret,
        &request.salt,
    )
    .map_err(map_operation_error)?;
    Ok(CryptoKdfDeriveKeyResult {
        algorithm: MessageField::some(kdf_identifier(ProtoKdf::KDF_ALGORITHM_ARGON2ID)),
        derived_key: derived.as_bytes().to_vec(),
        __buffa_unknown_fields: Default::default(),
    })
}

#[cfg(all(feature = "pbkdf2", any(feature = "native", feature = "wasm")))]
pub(super) fn process_kdf_derive_key(
    request: CryptoKdfDeriveKeyRequest,
) -> Result<CryptoKdfDeriveKeyResult, CryptoWireError> {
    let prf = pbkdf2_prf(&request.algorithm)?;
    let output_length = usize::try_from(request.output_length).map_err(|_| invalid_parameter())?;
    let derived = crate::operations::kdf::derive_pbkdf2_from_raw(
        prf,
        &request.password,
        &request.salt,
        request.iterations,
        output_length,
    )
    .map_err(map_operation_error)?;
    Ok(CryptoKdfDeriveKeyResult {
        algorithm: MessageField::some(kdf_identifier(match prf {
            crypto_pbkdf2::Pbkdf2Prf::HmacSha256 => ProtoKdf::KDF_ALGORITHM_PBKDF2_HMAC_SHA256,
            crypto_pbkdf2::Pbkdf2Prf::HmacSha512 => ProtoKdf::KDF_ALGORITHM_PBKDF2_HMAC_SHA512,
        })),
        derived_key: derived.as_bytes().to_vec(),
        __buffa_unknown_fields: Default::default(),
    })
}

#[cfg(all(feature = "concat-kdf", any(feature = "native", feature = "wasm")))]
pub(super) fn process_jwa_concat_kdf_sha256_derive(
    request: CryptoJwaConcatKdfSha256DeriveRequest,
) -> Result<CryptoJwaConcatKdfSha256DeriveResult, CryptoWireError> {
    require_jwa_concat_kdf_sha256(&request.algorithm)?;
    let shared_secret = crate::concat_kdf::JwaSharedSecret::from_slice(&request.shared_secret)
        .map_err(CryptoWireError::from)?;
    let algorithm_id = crate::concat_kdf::JwaAlgorithmId::from_slice(&request.algorithm_id)
        .map_err(CryptoWireError::from)?;
    let party_u_info = crate::concat_kdf::JwaPartyInfo::from_slice(&request.party_u_info)
        .map_err(CryptoWireError::from)?;
    let party_v_info = crate::concat_kdf::JwaPartyInfo::from_slice(&request.party_v_info)
        .map_err(CryptoWireError::from)?;
    let derive_request = crate::concat_kdf::JwaConcatKdfRequest {
        shared_secret: &shared_secret,
        algorithm_id: &algorithm_id,
        party_u_info: &party_u_info,
        party_v_info: &party_v_info,
    };
    let derived = derive_jwa_concat_kdf_to_vec(&derive_request, request.output_length)?;
    Ok(CryptoJwaConcatKdfSha256DeriveResult {
        algorithm: MessageField::some(kdf_identifier(
            ProtoKdf::KDF_ALGORITHM_JWA_CONCAT_KDF_SHA256,
        )),
        derived_key: derived,
        __buffa_unknown_fields: Default::default(),
    })
}

#[cfg(all(feature = "hkdf", any(feature = "native", feature = "wasm")))]
fn derive_hkdf_to_vec(
    request: &crate::hkdf::DeriveRequest<'_>,
    output_length: u32,
) -> Result<Vec<u8>, CryptoWireError> {
    match output_length {
        16 => crate::operations::kdf::derive_hkdf::<16>(request)
            .map(|output| output.as_bytes().to_vec()),
        24 => crate::operations::kdf::derive_hkdf::<24>(request)
            .map(|output| output.as_bytes().to_vec()),
        32 => crate::operations::kdf::derive_hkdf::<32>(request)
            .map(|output| output.as_bytes().to_vec()),
        48 => crate::operations::kdf::derive_hkdf::<48>(request)
            .map(|output| output.as_bytes().to_vec()),
        64 => crate::operations::kdf::derive_hkdf::<64>(request)
            .map(|output| output.as_bytes().to_vec()),
        _ => return Err(invalid_parameter()),
    }
    .map_err(map_operation_error)
}

#[cfg(all(feature = "concat-kdf", any(feature = "native", feature = "wasm")))]
fn derive_jwa_concat_kdf_to_vec(
    request: &crate::concat_kdf::JwaConcatKdfRequest<'_>,
    output_length: u32,
) -> Result<Vec<u8>, CryptoWireError> {
    match output_length {
        16 => crate::operations::kdf::derive_jwa_concat_kdf_sha256::<16>(request)
            .map(|output| output.as_bytes().to_vec()),
        24 => crate::operations::kdf::derive_jwa_concat_kdf_sha256::<24>(request)
            .map(|output| output.as_bytes().to_vec()),
        32 => crate::operations::kdf::derive_jwa_concat_kdf_sha256::<32>(request)
            .map(|output| output.as_bytes().to_vec()),
        48 => crate::operations::kdf::derive_jwa_concat_kdf_sha256::<48>(request)
            .map(|output| output.as_bytes().to_vec()),
        64 => crate::operations::kdf::derive_jwa_concat_kdf_sha256::<64>(request)
            .map(|output| output.as_bytes().to_vec()),
        _ => return Err(invalid_parameter()),
    }
    .map_err(map_operation_error)
}
