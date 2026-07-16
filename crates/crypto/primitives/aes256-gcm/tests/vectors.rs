// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]
pub struct Aes256GcmVector {
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub aad: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub ciphertext_and_tag: Vec<u8>,
}

pub struct Aes128GcmVector {
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub aad: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub ciphertext_and_tag: Vec<u8>,
}

pub struct Aes192GcmVector {
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub aad: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub ciphertext_and_tag: Vec<u8>,
}

pub fn all_regression_vectors() -> Vec<Aes256GcmVector> {
    vec![
        nist_vector_case_13(),
        regression_vector_case_alpha(),
        regression_vector_case_beta_empty_plaintext(),
    ]
}

pub fn all_aes128_regression_vectors() -> Vec<Aes128GcmVector> {
    vec![
        aes128_empty_plaintext_zero_key_vector(),
        aes128_single_block_zero_key_vector(),
    ]
}

pub fn all_aes192_regression_vectors() -> Vec<Aes192GcmVector> {
    vec![
        aes192_empty_plaintext_zero_key_vector(),
        aes192_single_block_zero_key_vector(),
    ]
}

pub fn aes128_empty_plaintext_zero_key_vector() -> Aes128GcmVector {
    // NIST SP 800-38D AES-128-GCM example: empty plaintext/AAD with zero key
    // and zero 96-bit IV. The ciphertext is empty and the output is the tag.
    Aes128GcmVector {
        key: hex::decode("00000000000000000000000000000000").expect("vector key hex must be valid"),
        nonce: hex::decode("000000000000000000000000").expect("vector nonce hex must be valid"),
        aad: Vec::new(),
        plaintext: Vec::new(),
        ciphertext_and_tag: hex::decode("58e2fccefa7e3061367f1d57a4e7455a")
            .expect("vector tag hex must be valid"),
    }
}

pub fn aes128_single_block_zero_key_vector() -> Aes128GcmVector {
    // NIST SP 800-38D AES-128-GCM example with one zero plaintext block.
    let mut ciphertext_and_tag = hex::decode("0388dace60b6a392f328c2b971b2fe78")
        .expect("vector ciphertext hex must be valid");
    ciphertext_and_tag.extend_from_slice(
        &hex::decode("ab6e47d42cec13bdf53a67b21257bddf").expect("vector tag hex must be valid"),
    );

    Aes128GcmVector {
        key: hex::decode("00000000000000000000000000000000").expect("vector key hex must be valid"),
        nonce: hex::decode("000000000000000000000000").expect("vector nonce hex must be valid"),
        aad: Vec::new(),
        plaintext: hex::decode("00000000000000000000000000000000")
            .expect("vector plaintext hex must be valid"),
        ciphertext_and_tag,
    }
}

pub fn aes192_empty_plaintext_zero_key_vector() -> Aes192GcmVector {
    // NIST SP 800-38D AES-192-GCM example: empty plaintext/AAD with zero key
    // and zero 96-bit IV. The ciphertext is empty and the output is the tag.
    Aes192GcmVector {
        key: hex::decode("000000000000000000000000000000000000000000000000")
            .expect("vector key hex must be valid"),
        nonce: hex::decode("000000000000000000000000").expect("vector nonce hex must be valid"),
        aad: Vec::new(),
        plaintext: Vec::new(),
        ciphertext_and_tag: hex::decode("cd33b28ac773f74ba00ed1f312572435")
            .expect("vector tag hex must be valid"),
    }
}

pub fn aes192_single_block_zero_key_vector() -> Aes192GcmVector {
    // NIST SP 800-38D AES-192-GCM example with one zero plaintext block.
    let mut ciphertext_and_tag = hex::decode("98e7247c07f0fe411c267e4384b0f600")
        .expect("vector ciphertext hex must be valid");
    ciphertext_and_tag.extend_from_slice(
        &hex::decode("2ff58d80033927ab8ef4d4587514f0fb").expect("vector tag hex must be valid"),
    );

    Aes192GcmVector {
        key: hex::decode("000000000000000000000000000000000000000000000000")
            .expect("vector key hex must be valid"),
        nonce: hex::decode("000000000000000000000000").expect("vector nonce hex must be valid"),
        aad: Vec::new(),
        plaintext: hex::decode("00000000000000000000000000000000")
            .expect("vector plaintext hex must be valid"),
        ciphertext_and_tag,
    }
}

pub fn nist_vector_case_13() -> Aes256GcmVector {
    // NIST SP 800-38D, GCM-AES-256 test vector (case with AAD).
    let key = hex::decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
        .expect("vector key hex must be valid");

    let nonce = hex::decode("cafebabefacedbaddecaf888").expect("vector nonce hex must be valid");

    let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        .expect("vector aad hex must be valid");

    let plaintext = hex::decode(
        "d9313225f88406e5a55909c5aff5269a\
         86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525\
         b16aedf5aa0de657ba637b39",
    )
    .expect("vector plaintext hex must be valid");

    let ciphertext = hex::decode(
        "522dc1f099567d07f47f37a32a84427d\
         643a8cdcbfe5c0c97598a2bd2555d1aa\
         8cb08e48590dbb3da7b08b1056828838\
         c5f61e6393ba7a0abcc9f662",
    )
    .expect("vector ciphertext hex must be valid");

    let tag =
        hex::decode("76fc6ece0f4e1768cddf8853bb2d551b").expect("vector tag hex must be valid");

    let mut ciphertext_and_tag = ciphertext;
    ciphertext_and_tag.extend_from_slice(&tag);

    Aes256GcmVector {
        key,
        nonce,
        aad,
        plaintext,
        ciphertext_and_tag,
    }
}

pub fn regression_vector_case_alpha() -> Aes256GcmVector {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .expect("vector key hex must be valid");
    let nonce = hex::decode("1af38c2dc2b96ffdd8669409").expect("vector nonce hex must be valid");
    let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        .expect("vector aad hex must be valid");
    let plaintext = hex::decode(
        "41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365",
    )
    .expect("vector plaintext hex must be valid");
    let ciphertext = hex::decode(
        "e350fda4478983335c52877b20d06795e873a81098f41a02d6e91a3067a30e902b50168b74a6c94192b95dc5d3ee30c1e6aaa04ba81bd2d1ea5303b08760b1bfb92a354cf9d7f749c7d251cd0bee0be651873f329ddd216493a6cd469776655d4b8d89f43520d4fabeba28235c0cc8ffd2e98c56cfb8a834aa453df707baaf88",
    )
    .expect("vector ciphertext hex must be valid");
    let tag =
        hex::decode("f586dd6898d35f51b5c39744a0e95191").expect("vector tag hex must be valid");

    let mut ciphertext_and_tag = ciphertext;
    ciphertext_and_tag.extend_from_slice(&tag);

    Aes256GcmVector {
        key,
        nonce,
        aad,
        plaintext,
        ciphertext_and_tag,
    }
}

pub fn regression_vector_case_beta_empty_plaintext() -> Aes256GcmVector {
    let key = hex::decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
        .expect("vector key hex must be valid");
    let nonce = hex::decode("cafebabefacedbaddecaf888").expect("vector nonce hex must be valid");
    let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        .expect("vector aad hex must be valid");
    let plaintext = Vec::new();
    let tag =
        hex::decode("9f6be07603c0b0bd1272854063e9c9ba").expect("vector tag hex must be valid");

    Aes256GcmVector {
        key,
        nonce,
        aad,
        plaintext,
        ciphertext_and_tag: tag,
    }
}
