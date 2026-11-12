// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_crypto::{
    ecdsa_explicit::{self, EcdsaCurve, EcdsaEncoding, EcdsaHash, EcdsaInput, EcdsaKey},
    ed448::{self, Ed448Key},
    key_identifier,
};

const CURVES: [EcdsaCurve; 7] = [
    EcdsaCurve::P256,
    EcdsaCurve::P384,
    EcdsaCurve::P521,
    EcdsaCurve::BrainpoolP256r1,
    EcdsaCurve::BrainpoolP320r1,
    EcdsaCurve::BrainpoolP384r1,
    EcdsaCurve::BrainpoolP512r1,
];
const WIDTHS: [usize; 7] = [32, 48, 66, 32, 40, 48, 64];
const HASHES: [EcdsaHash; 3] = [EcdsaHash::Sha256, EcdsaHash::Sha384, EcdsaHash::Sha512];

fn take<'a>(data: &mut &'a [u8], length: usize) -> Option<&'a [u8]> {
    let (value, remainder) = data.split_at_checked(length)?;
    *data = remainder;
    Some(value)
}

fn exercise(mut data: &[u8]) -> Option<()> {
    let header = take(&mut data, 4)?;
    let index = usize::from(header[0]) % CURVES.len();
    let curve = *CURVES.get(index)?;
    let width = *WIDTHS.get(index)?;
    let hash = *HASHES.get(usize::from(header[1]) % HASHES.len())?;
    let encoding = if header[2] & 1 == 0 {
        EcdsaEncoding::Der
    } else {
        EcdsaEncoding::FixedWidth
    };
    let private = take(&mut data, width)?;
    let public = take(&mut data, width.checked_mul(2)?.checked_add(1)?)?;
    let signature = take(&mut data, usize::from(header[3]))?;
    let input = EcdsaInput::Message { hash, bytes: data };
    let _ = ecdsa_explicit::verify(curve, public, input, signature, encoding);
    let _ = ecdsa_explicit::der_to_fixed(curve, signature);
    let _ = ecdsa_explicit::fixed_to_der(curve, signature);
    if let Ok(key) = EcdsaKey::import(curve, private) {
        let _ = key.agree(public);
        let _ = key.sign(input, encoding);
    }
    let _ = key_identifier::subject_key_identifier_sha1(data);
    let mut ed448_data = data;
    if let (Some(public), Some(signature)) = (
        take(&mut ed448_data, ed448::PUBLIC_KEY_LEN),
        take(&mut ed448_data, ed448::SIGNATURE_LEN),
    ) {
        let _ = ed448::verify(public, ed448_data, signature);
    }
    if let Some(seed) = data.get(..ed448::SEED_LEN) {
        if let Ok(key) = Ed448Key::import(seed) {
            let _ = key.sign(data);
        }
    }
    Some(())
}

fuzz_target!(|data: &[u8]| {
    let _ = exercise(data);
});
