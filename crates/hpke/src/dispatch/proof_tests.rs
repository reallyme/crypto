// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::HpkeError;
use crate::identifiers::{HpkeAeadId, HpkeComponentSupport, HpkeKdfId, HpkeKemId};
use crate::identifiers::{HPKE_REGISTERED_AEADS, HPKE_REGISTERED_KDFS, HPKE_REGISTERED_KEMS};

// The production macros choose the same generic types for every callback.
// Reading their IDs verifies the route without invoking a primitive or RNG.
fn kem_id<Kem: hpke::Kem>() -> Result<u16, HpkeError> {
    Ok(Kem::KEM_ID)
}

fn kdf_id<_Kem, Kdf: hpke::kdf::Kdf>() -> Result<u16, HpkeError> {
    Ok(Kdf::KDF_ID)
}

fn aead_id<Aead: hpke::aead::Aead, _Kdf, _Kem>() -> Result<u16, HpkeError> {
    Ok(Aead::AEAD_ID)
}

fn expected_route(id: u16, available: bool) -> Result<u16, HpkeError> {
    if available {
        Ok(id)
    } else {
        Err(HpkeError::PROVIDER_UNSUPPORTED_ALGORITHM)
    }
}

#[kani::proof]
#[kani::unwind(18)]
fn kem_dispatch_agrees_with_the_registry_and_build_policy() {
    let requested: u16 = kani::any();
    let registered = HPKE_REGISTERED_KEMS
        .iter()
        .any(|id| *id as u16 == requested);
    match HpkeKemId::try_from(requested) {
        Ok(kem) => {
            assert!(registered);
            assert_eq!(kem as u16, requested);
            let executable = kem.support() == HpkeComponentSupport::Executable;
            assert_eq!(
                dispatch_kem!(kem, kem_id),
                expected_route(requested, executable)
            );
        }
        Err(error) => {
            assert!(!registered);
            assert_eq!(error, HpkeError::PROVIDER_UNSUPPORTED_ALGORITHM);
        }
    }
}

#[kani::proof]
#[kani::unwind(8)]
fn kdf_dispatch_agrees_with_the_registry_and_build_policy() {
    let requested: u16 = kani::any();
    let registered = HPKE_REGISTERED_KDFS
        .iter()
        .any(|id| *id as u16 == requested);
    match HpkeKdfId::try_from(requested) {
        Ok(kdf) => {
            assert!(registered);
            assert_eq!(kdf as u16, requested);
            let executable = kdf.support() == HpkeComponentSupport::Executable;
            assert_eq!(
                dispatch_kdf!(kdf, kdf_id, ()),
                expected_route(requested, executable)
            );
        }
        Err(error) => {
            assert!(!registered);
            assert_eq!(error, HpkeError::PROVIDER_UNSUPPORTED_ALGORITHM);
        }
    }
}

#[kani::proof]
#[kani::unwind(5)]
fn aead_dispatch_agrees_with_the_registry_and_operation() {
    let requested: u16 = kani::any();
    let registered = HPKE_REGISTERED_AEADS
        .iter()
        .any(|id| *id as u16 == requested);
    match HpkeAeadId::try_from(requested) {
        Ok(aead) => {
            assert!(registered);
            assert_eq!(aead as u16, requested);
            let executable = aead.support() == HpkeComponentSupport::Executable;
            assert_eq!(
                dispatch_export_aead!(aead, aead_id, (), ()),
                expected_route(requested, executable),
            );
            assert_eq!(
                dispatch_sealing_aead!(aead, aead_id, (), ()),
                expected_route(requested, executable && aead != HpkeAeadId::ExportOnly),
            );
        }
        Err(error) => {
            assert!(!registered);
            assert_eq!(error, HpkeError::PROVIDER_UNSUPPORTED_ALGORITHM);
        }
    }
}
