// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Protected protobuf adapters for the existing public-only JWK model.

use crate::{AkpJwk, EcJwk, Jwk, JwkOptions, Jwks, OkpJwk};
use buffa::EnumValue;
use crypto_core::CryptoError;
use crypto_proto::generated::proto::reallyme::crypto::v1::{
    __buffa::oneof::public_jwk::Key, CryptoJwkOptions, KeyAlgorithm, PublicAkpJwk, PublicEcJwk,
    PublicJwk, PublicJwks, PublicOkpJwk,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Owns copied option metadata and clears its legacy KID string on every exit.
pub struct ProtectedJwkOptions {
    options: JwkOptions,
}
impl ProtectedJwkOptions {
    /// Borrows the unchanged legacy options API.
    pub fn as_options(&self) -> &JwkOptions {
        &self.options
    }
}
impl Zeroize for ProtectedJwkOptions {
    fn zeroize(&mut self) {
        self.options.kid.zeroize();
    }
}
impl Drop for ProtectedJwkOptions {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for ProtectedJwkOptions {}
impl TryFrom<&CryptoJwkOptions> for ProtectedJwkOptions {
    type Error = CryptoError;
    fn try_from(value: &CryptoJwkOptions) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        let kid = read_optional_text(value.kid.as_deref())?;
        let mut owner = Self {
            options: JwkOptions {
                alg: value.alg,
                use_sig: value.use_sig,
                use_enc: value.use_enc,
                kid: None,
            },
        };
        copy_optional_string(&mut owner.options.kid, kid)?;
        Ok(owner)
    }
}
impl TryFrom<&JwkOptions> for CryptoJwkOptions {
    type Error = CryptoError;
    // Establish each clearing output owner before copying correlating fields.
    #[allow(clippy::field_reassign_with_default)]
    fn try_from(value: &JwkOptions) -> Result<Self, Self::Error> {
        if let Some(kid) = &value.kid {
            check_length(kid.as_bytes())?;
        }
        let mut output = Self::default();
        output.alg = value.alg;
        output.use_sig = value.use_sig;
        output.use_enc = value.use_enc;
        copy_optional_bytes(&mut output.kid, value.kid.as_deref())?;
        Ok(output)
    }
}

/// Owns a converted legacy public JWK and clears every owned string on drop.
/// No `Debug`, `Clone` or extraction API exposes an unmanaged copied KID.
pub struct ProtectedJwk {
    jwk: Jwk,
}
impl ProtectedJwk {
    /// Borrows the unchanged native public-key model.
    pub fn as_jwk(&self) -> &Jwk {
        &self.jwk
    }
    /// Replaces KID through this owner without changing key identity or encoding.
    /// Failure drops the consumed owner and clears every owned field.
    pub fn with_key_id(mut self, kid: Option<&str>) -> Result<Self, CryptoError> {
        let target = match &mut self.jwk {
            Jwk::Ec(value) => &mut value.kid,
            Jwk::Okp(value) => &mut value.kid,
            Jwk::Akp(value) => &mut value.kid,
        };
        target.zeroize();
        *target = None;
        copy_optional_string(target, kid)?;
        Ok(self)
    }

    fn take_jwk(&mut self) -> Jwk {
        // Used only after the destination set has reserved its full capacity.
        core::mem::replace(&mut self.jwk, empty_jwk())
    }
}
impl TryFrom<Jwk> for ProtectedJwk {
    type Error = CryptoError;
    fn try_from(jwk: Jwk) -> Result<Self, Self::Error> {
        let owner = Self { jwk };
        let _public_key = Zeroizing::new(owner.jwk.public_key_bytes()?);
        Ok(owner)
    }
}

impl Zeroize for ProtectedJwk {
    fn zeroize(&mut self) {
        clear_jwk(&mut self.jwk);
    }
}
impl Drop for ProtectedJwk {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for ProtectedJwk {}
impl TryFrom<&PublicJwk> for ProtectedJwk {
    type Error = CryptoError;
    fn try_from(value: &PublicJwk) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        let mut owner = Self { jwk: empty_jwk() };
        match &value.key {
            Some(Key::Ec(value)) => {
                require_known(value.__buffa_unknown_fields.is_empty())?;
                let metadata = metadata(value.key_algorithm, Shape::Ec)?;
                let alg = read_optional_text(value.alg.as_deref())?;
                let usage = read_optional_text(value.usage.as_deref())?;
                let x = read_text(&value.x_base64url)?;
                let y = read_text(&value.y_base64url)?;
                let kid = read_optional_text(value.kid.as_deref())?;
                owner.jwk = Jwk::Ec(EcJwk {
                    kty: String::new(),
                    crv: String::new(),
                    x: String::new(),
                    y: String::new(),
                    alg: None,
                    use_: None,
                    kid: None,
                });
                if let Jwk::Ec(native) = &mut owner.jwk {
                    copy_string(&mut native.kty, metadata.kty)?;
                    copy_string(&mut native.crv, metadata.curve)?;
                    copy_string(&mut native.x, x)?;
                    copy_string(&mut native.y, y)?;
                    copy_optional_string(&mut native.alg, alg)?;
                    copy_optional_string(&mut native.use_, usage)?;
                    copy_optional_string(&mut native.kid, kid)?;
                } else {
                    return Err(CryptoError::BACKEND_INTERNAL);
                }
            }
            Some(Key::Okp(value)) => {
                require_known(value.__buffa_unknown_fields.is_empty())?;
                let metadata = metadata(value.key_algorithm, Shape::Okp)?;
                let alg = read_optional_text(value.alg.as_deref())?;
                let usage = read_optional_text(value.usage.as_deref())?;
                let x = read_text(&value.x_base64url)?;
                let kid = read_optional_text(value.kid.as_deref())?;
                owner.jwk = empty_jwk();
                if let Jwk::Okp(native) = &mut owner.jwk {
                    copy_string(&mut native.kty, metadata.kty)?;
                    copy_string(&mut native.crv, metadata.curve)?;
                    copy_string(&mut native.x, x)?;
                    copy_optional_string(&mut native.alg, alg)?;
                    copy_optional_string(&mut native.use_, usage)?;
                    copy_optional_string(&mut native.kid, kid)?;
                } else {
                    return Err(CryptoError::BACKEND_INTERNAL);
                }
            }
            Some(Key::Akp(value)) => {
                require_known(value.__buffa_unknown_fields.is_empty())?;
                let metadata = metadata(value.key_algorithm, Shape::Akp)?;
                let usage = read_optional_text(value.usage.as_deref())?;
                let public_key = read_text(&value.public_key_base64url)?;
                let kid = read_optional_text(value.kid.as_deref())?;
                owner.jwk = Jwk::Akp(AkpJwk {
                    kty: String::new(),
                    alg: String::new(),
                    public_key: String::new(),
                    use_: None,
                    kid: None,
                });
                if let Jwk::Akp(native) = &mut owner.jwk {
                    copy_string(&mut native.kty, metadata.kty)?;
                    copy_string(&mut native.alg, metadata.algorithm)?;
                    copy_string(&mut native.public_key, public_key)?;
                    copy_optional_string(&mut native.use_, usage)?;
                    copy_optional_string(&mut native.kid, kid)?;
                } else {
                    return Err(CryptoError::BACKEND_INTERNAL);
                }
            }
            None => return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER),
        }
        // Existing native validation remains authoritative for key identity,
        // metadata and backend availability. Protect its returned copy at once.
        let _public_key = Zeroizing::new(owner.jwk.public_key_bytes()?);
        Ok(owner)
    }
}
impl TryFrom<&Jwk> for PublicJwk {
    type Error = CryptoError;
    // Establish each clearing output owner before copying correlating fields.
    #[allow(clippy::field_reassign_with_default)]
    fn try_from(value: &Jwk) -> Result<Self, Self::Error> {
        let _public_key = Zeroizing::new(value.public_key_bytes()?);
        let key = match value {
            Jwk::Ec(value) => {
                let identity = match value.crv.as_str() {
                    "P-256" => KeyAlgorithm::KEY_ALGORITHM_P256,
                    "secp256k1" => KeyAlgorithm::KEY_ALGORITHM_SECP256K1,
                    _ => return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
                };
                check_length(value.x.as_bytes())?;
                check_length(value.y.as_bytes())?;
                check_optional_text(&value.kid)?;
                let mut output = PublicEcJwk::default();
                output.key_algorithm = identity.into();
                copy_into(&mut output.x_base64url, value.x.as_bytes())?;
                copy_into(&mut output.y_base64url, value.y.as_bytes())?;
                copy_optional_bytes(&mut output.alg, value.alg.as_deref())?;
                copy_optional_bytes(&mut output.usage, value.use_.as_deref())?;
                copy_optional_bytes(&mut output.kid, value.kid.as_deref())?;
                Key::Ec(Box::new(output))
            }
            Jwk::Okp(value) => {
                let identity = match value.crv.as_str() {
                    "Ed25519" => KeyAlgorithm::KEY_ALGORITHM_ED25519,
                    "X25519" => KeyAlgorithm::KEY_ALGORITHM_X25519,
                    _ => return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
                };
                check_length(value.x.as_bytes())?;
                check_optional_text(&value.kid)?;
                let mut output = PublicOkpJwk::default();
                output.key_algorithm = identity.into();
                copy_into(&mut output.x_base64url, value.x.as_bytes())?;
                copy_optional_bytes(&mut output.alg, value.alg.as_deref())?;
                copy_optional_bytes(&mut output.usage, value.use_.as_deref())?;
                copy_optional_bytes(&mut output.kid, value.kid.as_deref())?;
                Key::Okp(Box::new(output))
            }
            Jwk::Akp(value) => {
                let identity = akp_identity(&value.alg)?;
                check_length(value.public_key.as_bytes())?;
                check_optional_text(&value.kid)?;
                let mut output = PublicAkpJwk::default();
                output.key_algorithm = identity.into();
                copy_into(
                    &mut output.public_key_base64url,
                    value.public_key.as_bytes(),
                )?;
                copy_optional_bytes(&mut output.usage, value.use_.as_deref())?;
                copy_optional_bytes(&mut output.kid, value.kid.as_deref())?;
                Key::Akp(Box::new(output))
            }
        };
        Ok(Self {
            key: Some(key),
            __buffa_unknown_fields: Default::default(),
        })
    }
}

/// Owns a converted native JWKS and clears all nested fields on failure/drop.
pub struct ProtectedJwks {
    jwks: Jwks,
}
impl ProtectedJwks {
    /// Borrows the unchanged native set API.
    pub fn as_jwks(&self) -> &Jwks {
        &self.jwks
    }
}
impl Zeroize for ProtectedJwks {
    fn zeroize(&mut self) {
        for key in &mut self.jwks.keys {
            clear_jwk(key);
        }
    }
}
impl Drop for ProtectedJwks {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for ProtectedJwks {}
impl TryFrom<&PublicJwks> for ProtectedJwks {
    type Error = CryptoError;
    fn try_from(value: &PublicJwks) -> Result<Self, Self::Error> {
        require_known(value.__buffa_unknown_fields.is_empty())?;
        check_count(value.keys.len())?;
        let mut owner = Self {
            jwks: Jwks::new(Vec::new()),
        };
        owner
            .jwks
            .keys
            .try_reserve_exact(value.keys.len())
            .map_err(|_| CryptoError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED)?;
        for key in &value.keys {
            let mut key = ProtectedJwk::try_from(key)?;
            owner.jwks.keys.push(key.take_jwk());
        }
        Ok(owner)
    }
}
impl TryFrom<&Jwks> for PublicJwks {
    type Error = CryptoError;
    fn try_from(value: &Jwks) -> Result<Self, Self::Error> {
        check_count(value.keys.len())?;
        let mut output = Self::default();
        output
            .keys
            .try_reserve_exact(value.keys.len())
            .map_err(|_| CryptoError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED)?;
        for key in &value.keys {
            output.keys.push(PublicJwk::try_from(key)?);
        }
        Ok(output)
    }
}

#[derive(PartialEq, Eq)]
enum Shape {
    Ec,
    Okp,
    Akp,
}
struct Metadata {
    kty: &'static str,
    curve: &'static str,
    algorithm: &'static str,
}
fn metadata(value: EnumValue<KeyAlgorithm>, shape: Shape) -> Result<Metadata, CryptoError> {
    let (expected_shape, kty, curve, algorithm) = match value.as_known() {
        Some(KeyAlgorithm::KEY_ALGORITHM_P256) => (Shape::Ec, "EC", "P-256", "ES256"),
        Some(KeyAlgorithm::KEY_ALGORITHM_SECP256K1) => (Shape::Ec, "EC", "secp256k1", "ES256K"),
        Some(KeyAlgorithm::KEY_ALGORITHM_ED25519) => (Shape::Okp, "OKP", "Ed25519", "EdDSA"),
        Some(KeyAlgorithm::KEY_ALGORITHM_X25519) => (Shape::Okp, "OKP", "X25519", "ECDH-ES"),
        Some(KeyAlgorithm::KEY_ALGORITHM_ML_DSA_44) => (Shape::Akp, "AKP", "", "ML-DSA-44"),
        Some(KeyAlgorithm::KEY_ALGORITHM_ML_DSA_65) => (Shape::Akp, "AKP", "", "ML-DSA-65"),
        Some(KeyAlgorithm::KEY_ALGORITHM_ML_DSA_87) => (Shape::Akp, "AKP", "", "ML-DSA-87"),
        Some(KeyAlgorithm::KEY_ALGORITHM_ML_KEM_512) => (Shape::Akp, "AKP", "", "ML-KEM-512"),
        Some(KeyAlgorithm::KEY_ALGORITHM_ML_KEM_768) => (Shape::Akp, "AKP", "", "ML-KEM-768"),
        Some(KeyAlgorithm::KEY_ALGORITHM_ML_KEM_1024) => (Shape::Akp, "AKP", "", "ML-KEM-1024"),
        Some(KeyAlgorithm::KEY_ALGORITHM_SLH_DSA_SHA2_128S) => {
            (Shape::Akp, "AKP", "", "SLH-DSA-SHA2-128s")
        }
        Some(KeyAlgorithm::KEY_ALGORITHM_X_WING_768) => (Shape::Akp, "AKP", "", "X-Wing-768"),
        _ => return Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    };
    if expected_shape != shape {
        return Err(CryptoError::PRIMITIVE_INVALID_PARAMETER);
    }
    Ok(Metadata {
        kty,
        curve,
        algorithm,
    })
}
fn akp_identity(value: &str) -> Result<KeyAlgorithm, CryptoError> {
    match value {
        "ML-DSA-44" => Ok(KeyAlgorithm::KEY_ALGORITHM_ML_DSA_44),
        "ML-DSA-65" => Ok(KeyAlgorithm::KEY_ALGORITHM_ML_DSA_65),
        "ML-DSA-87" => Ok(KeyAlgorithm::KEY_ALGORITHM_ML_DSA_87),
        "ML-KEM-512" => Ok(KeyAlgorithm::KEY_ALGORITHM_ML_KEM_512),
        "ML-KEM-768" => Ok(KeyAlgorithm::KEY_ALGORITHM_ML_KEM_768),
        "ML-KEM-1024" => Ok(KeyAlgorithm::KEY_ALGORITHM_ML_KEM_1024),
        "SLH-DSA-SHA2-128s" => Ok(KeyAlgorithm::KEY_ALGORITHM_SLH_DSA_SHA2_128S),
        "X-Wing-768" => Ok(KeyAlgorithm::KEY_ALGORITHM_X_WING_768),
        _ => Err(CryptoError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}
fn empty_jwk() -> Jwk {
    Jwk::Okp(OkpJwk {
        kty: String::new(),
        crv: String::new(),
        x: String::new(),
        alg: None,
        use_: None,
        kid: None,
    })
}
fn clear_jwk(value: &mut Jwk) {
    match value {
        Jwk::Ec(value) => {
            value.kty.zeroize();
            value.crv.zeroize();
            value.x.zeroize();
            value.y.zeroize();
            value.alg.zeroize();
            value.use_.zeroize();
            value.kid.zeroize();
        }
        Jwk::Okp(value) => {
            value.kty.zeroize();
            value.crv.zeroize();
            value.x.zeroize();
            value.alg.zeroize();
            value.use_.zeroize();
            value.kid.zeroize();
        }
        Jwk::Akp(value) => {
            value.kty.zeroize();
            value.alg.zeroize();
            value.public_key.zeroize();
            value.use_.zeroize();
            value.kid.zeroize();
        }
    }
}
fn check_count(length: usize) -> Result<(), CryptoError> {
    u32::try_from(length)
        .map(|_| ())
        .map_err(|_| CryptoError::PRIMITIVE_INVALID_LENGTH)
}
fn check_length(value: &[u8]) -> Result<(), CryptoError> {
    check_count(value.len())
}
fn check_optional_text(value: &Option<String>) -> Result<(), CryptoError> {
    if let Some(value) = value {
        check_length(value.as_bytes())?;
    }
    Ok(())
}
fn read_text(value: &[u8]) -> Result<&str, CryptoError> {
    check_length(value)?;
    core::str::from_utf8(value).map_err(|_| CryptoError::PRIMITIVE_INVALID_ENCODING)
}
fn read_optional_text(value: Option<&[u8]>) -> Result<Option<&str>, CryptoError> {
    value.map(read_text).transpose()
}
fn require_known(known: bool) -> Result<(), CryptoError> {
    if known {
        Ok(())
    } else {
        Err(CryptoError::PRIMITIVE_INVALID_PARAMETER)
    }
}

// All copies are installed in their final clearing owner before allocation.
fn copy_into(output: &mut Vec<u8>, value: &[u8]) -> Result<(), CryptoError> {
    check_length(value)?;
    if !output.is_empty() {
        return Err(CryptoError::BACKEND_INVALID_STATE);
    }
    output
        .try_reserve_exact(value.len())
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    output.extend_from_slice(value);
    Ok(())
}
fn copy_optional_bytes(
    output: &mut Option<Vec<u8>>,
    value: Option<&str>,
) -> Result<(), CryptoError> {
    if output.is_some() {
        return Err(CryptoError::BACKEND_INVALID_STATE);
    }
    if let Some(value) = value {
        let field = output.get_or_insert_with(Vec::new);
        copy_into(field, value.as_bytes())?;
    }
    Ok(())
}
fn copy_string(output: &mut String, value: &str) -> Result<(), CryptoError> {
    check_length(value.as_bytes())?;
    if !output.is_empty() {
        return Err(CryptoError::BACKEND_INVALID_STATE);
    }
    output
        .try_reserve_exact(value.len())
        .map_err(|_| CryptoError::BACKEND_INTERNAL)?;
    output.push_str(value);
    Ok(())
}
fn copy_optional_string(
    output: &mut Option<String>,
    value: Option<&str>,
) -> Result<(), CryptoError> {
    if output.is_some() {
        return Err(CryptoError::BACKEND_INVALID_STATE);
    }
    if let Some(value) = value {
        let field = output.get_or_insert_with(String::new);
        copy_string(field, value)?;
    }
    Ok(())
}
