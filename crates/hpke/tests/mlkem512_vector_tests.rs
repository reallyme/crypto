// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! ML-KEM-512 checks against draft-ietf-hpke-pq-04 Appendix A.1.

#![allow(missing_docs)]
#![allow(clippy::expect_used)]
#![cfg(feature = "native")]

use crypto_hpke::{derive_keypair, HPKE_MLKEM512_HKDF_SHA256_AES128GCM};

#[test]
fn mlkem512_derive_keypair_matches_ietf_vector() {
    let input_key_material = hex::decode(concat!(
        "53c72362cd4c0d3c04fb963bb2d8fa3b61be2a83befb53883892f68d1e6af3ee",
        "2ab07a445a87cd505fe27f3434e35c8ad26e6452b51f24e5c9d3d174b326fb0e"
    ))
    .expect("IETF IKM is valid hexadecimal");
    let expected_private_key = hex::decode(concat!(
        "0466a81fc187205d5925aaa518e98d6cbde2a1aa63d756da4a62f873f6a0b1f1",
        "418d0eec2620055b8537aca724d18ad436e47972f85f4c5c5d2cfb1c62b100bd"
    ))
    .expect("IETF private key is valid hexadecimal");
    let expected_public_key = hex::decode(concat!(
        "3e774db858732c35a408388fceb66cc61777d361c85a72b1e844422cca0effcb",
        "5778cc5de43acab0ec682b0b318fa4122bac224d10c193b5933758320587196f",
        "d50cf76c94a1222b2a330a9fdb32b0ec8a42931c531bb025095e49fc0df8a52",
        "05b32149e7354d63232c8199dd9e6654ec0bef0937484b0904950b05b29297db",
        "b410be008ad441ebce23052c8cda593bb1bf4b5e0e520ac4a53e9a1bc38591c",
        "3f723e66c177a6715d3a365b0c156a5f72aa439ccb42944b8f47a32b446ab6d",
        "8ce58096a778a2322b3b467f2c5a17875fcd6a69ee74ea297093798765f6851e",
        "6402b77c723b335c5c8857d94090d41fa2b5e54ce5b7194d29175f141718c36",
        "959e6142402b2e816a856d914b1f2b3fc62329cccc7e23fb9d14828e44941997",
        "b323bcc90c497579d49462d79671809a38d79c3137cc4258563134d466287226",
        "0cc13b5c990215959721082c827bab0cb9a2559b16eb704cdea7cfe60b24224b",
        "13d055b382ea9e0920adb3592689b3635239ccf8db631f585957a37c57fa8d92",
        "fc7907d0266dca9b55fa5b68d308d8d6cbdcd8b583fa804c03ac620003911b50",
        "6396709bea2ad1a7a83f697c9ec741cf650464bac0093a0efd462207620c13b86",
        "cc0dc10dc9442870250390384c5e2b8f5294f9c88b26b09c8d504c286d16109a",
        "56838830caa35b231811bda3a1677d3087ce216ed9c8ce5cc4020d290efcc60d",
        "ed511bb990795d00674a12641e885ceda249e387ce470716188cd359c66f4e619",
        "08e12757b97c3095168fb8714681a96c54c1cd401231a5500896a8eabaa521da6",
        "80e759222d9765746624ab6c79a754b10477a0ae12ba2175f6f701569bb15d2e",
        "bc4e6e9b8e6f1c021b31edccb152ea23365db5ef396c893a9ba12cca8a3847e9",
        "9f6c732523e55844a17ba34cbd6042d1b7ffdc47d6031a7587162ada1a283267",
        "eaaa31da17cc611038fff51446e0384c7397450b05084859cb8f79e6a1775710",
        "a19f8e9896e83861debc6ffe1ba8ebb1cdee95da61c30f6c99091e31b4f3c59",
        "3352a1253910261c187c60a420e1445951cd797b74a4a7b53b50b0c1370e69e6",
        "5fcd29aa553682cc42f6802ac4b8a3bd7b1c482ff85523aa2848b95ee9654b55",
        "af"
    ))
    .expect("IETF public key is valid hexadecimal");

    let keypair = derive_keypair(HPKE_MLKEM512_HKDF_SHA256_AES128GCM, &input_key_material)
        .expect("IETF ML-KEM-512 derivation succeeds");

    assert_eq!(keypair.private_key(), expected_private_key);
    assert_eq!(keypair.public_key, expected_public_key);
}
