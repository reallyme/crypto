// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

// Each integration test compiles this support module as a separate crate-local
// module, so a helper used by one CCTV file can be intentionally unused in
// another.
#![allow(dead_code)]

use external_vector_audit::support::{hex_array, hex_bytes, load_gzip_text, load_text, AuditError};

const ML_KEM_SEED_LEN: usize = 64;
const ML_KEM_RANDOMNESS_LEN: usize = 32;
const SHARED_SECRET_LEN: usize = 32;

pub(crate) const ALL_PARAMETER_SETS: [MlKemParameterSet; 3] = [
    MlKemParameterSet::MlKem512,
    MlKemParameterSet::MlKem768,
    MlKemParameterSet::MlKem1024,
];

#[derive(Clone, Copy)]
pub(crate) enum MlKemParameterSet {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl MlKemParameterSet {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
        }
    }

    pub(crate) fn intermediate_path(self) -> String {
        self.path("intermediate", "txt")
    }

    pub(crate) fn modulus_path(self) -> String {
        self.path("modulus", "txt.gz")
    }

    pub(crate) fn strcmp_path(self) -> String {
        self.path("strcmp", "txt")
    }

    pub(crate) fn unlucky_path(self) -> String {
        self.path("unluckysample", "txt")
    }

    fn path(self, family: &str, extension: &str) -> String {
        format!("cctv/ml-kem/{family}/{}.{}", self.label(), extension)
    }
}

pub(crate) struct UnluckyVector {
    pub(crate) seed: [u8; ML_KEM_SEED_LEN],
    pub(crate) ek: Vec<u8>,
    pub(crate) m: [u8; ML_KEM_RANDOMNESS_LEN],
    pub(crate) c: Vec<u8>,
    pub(crate) k: [u8; SHARED_SECRET_LEN],
}

pub(crate) struct StrcmpVectorShape {
    pub(crate) decapsulation_key_len: usize,
    pub(crate) ciphertext_len: usize,
    pub(crate) shared_secret_len: usize,
}

pub(crate) fn load_unlucky_vector(
    parameter_set: MlKemParameterSet,
) -> Result<UnluckyVector, AuditError> {
    let text = load_text(&parameter_set.unlucky_path())?;
    let seed = ml_kem_seed(field(&text, "d")?, field(&text, "z")?)?;
    let ek = hex_bytes(field(&text, "ek")?)?;
    let m = hex_array::<ML_KEM_RANDOMNESS_LEN>(field(&text, "m")?)?;
    let c = hex_bytes(field(&text, "c")?)?;
    let k = hex_array::<SHARED_SECRET_LEN>(field(&text, "K")?)?;

    Ok(UnluckyVector { seed, ek, m, c, k })
}

pub(crate) fn load_modulus_public_keys(
    parameter_set: MlKemParameterSet,
    limit: usize,
) -> Result<Vec<Vec<u8>>, AuditError> {
    let text = load_gzip_text(&parameter_set.modulus_path())?;
    let mut public_keys = Vec::new();

    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        public_keys.push(hex_bytes(line)?);
        if public_keys.len() >= limit {
            return Ok(public_keys);
        }
    }

    if public_keys.is_empty() {
        Err(AuditError::NoExecutableVectors)
    } else {
        Ok(public_keys)
    }
}

pub(crate) fn load_strcmp_vector_shape(
    parameter_set: MlKemParameterSet,
) -> Result<StrcmpVectorShape, AuditError> {
    let text = load_text(&parameter_set.strcmp_path())?;
    let decapsulation_key_len = hex_bytes(field(&text, "dk")?)?.len();
    let ciphertext_len = hex_bytes(field(&text, "c")?)?.len();
    let shared_secret_len = hex_bytes(field(&text, "K")?)?.len();

    Ok(StrcmpVectorShape {
        decapsulation_key_len,
        ciphertext_len,
        shared_secret_len,
    })
}

pub(crate) fn intermediate_text_has_internal_markers(
    parameter_set: MlKemParameterSet,
) -> Result<bool, AuditError> {
    let text = load_text(&parameter_set.intermediate_path())?;
    Ok(text.contains("A = ") && text.contains("s = ") && text.contains("KBar = "))
}

fn ml_kem_seed(d: &str, z: &str) -> Result<[u8; ML_KEM_SEED_LEN], AuditError> {
    let d = hex_array::<ML_KEM_RANDOMNESS_LEN>(d)?;
    let z = hex_array::<ML_KEM_RANDOMNESS_LEN>(z)?;
    let mut seed = [0u8; ML_KEM_SEED_LEN];
    seed[..ML_KEM_RANDOMNESS_LEN].copy_from_slice(&d);
    seed[ML_KEM_RANDOMNESS_LEN..].copy_from_slice(&z);
    Ok(seed)
}

fn field<'a>(text: &'a str, name: &str) -> Result<&'a str, AuditError> {
    for line in text.lines() {
        let (candidate, value) = line.split_once(" = ").ok_or(AuditError::Shape)?;
        if candidate == name {
            return Ok(value);
        }
    }
    Err(AuditError::Shape)
}
