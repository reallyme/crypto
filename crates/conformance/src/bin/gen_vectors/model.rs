// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#[derive(Serialize)]
struct Manifest {
    vectors: Vec<&'static str>,
    negative_vectors: Vec<&'static str>,
    lifecycle_vectors: Vec<&'static str>,
    runtime_lanes: Vec<RuntimeLane>,
    post_quantum_oracle: PostQuantumOracle,
}

#[derive(Serialize)]
struct RuntimeLane {
    name: &'static str,
    harness: &'static str,
    status: &'static str,
    algorithms: Vec<&'static str>,
    notes: Vec<&'static str>,
}

#[derive(Serialize)]
struct PostQuantumOracle {
    package: &'static str,
    version: &'static str,
    algorithms: Vec<&'static str>,
}

#[derive(Serialize)]
struct OperationResponseVectors {
    schema_version: u32,
    request_protobuf: String,
    request_json: String,
    operation_response: String,
    malformed_protobuf: String,
    malformed_protobuf_response: String,
    malformed_json: String,
    malformed_json_response: String,
}

#[derive(Serialize)]
struct P256Vector {
    alg: &'static str,
    curve: &'static str,
    secret_key: String,
    public_key_compressed: String,
    public_key_uncompressed: String,
    // ECDSA (ES256) signing material. The Rust and Kotlin package lanes use
    // deterministic ECDSA and must reproduce these exact bytes; platform
    // native lanes may verify this vector without claiming deterministic emit.
    ecdsa_message: String,
    ecdsa_signature_der: String,
    peer_secret_key: String,
    peer_public_key_compressed: String,
    peer_public_key_uncompressed: String,
    shared_secret: String,
}

#[derive(Serialize)]
struct Sec1EcdsaVector {
    alg: &'static str,
    curve: &'static str,
    secret_key: String,
    public_key_compressed: String,
    public_key_uncompressed: String,
    message: String,
    signature_der: String,
    peer_secret_key: String,
    peer_public_key_compressed: String,
    peer_public_key_uncompressed: String,
    shared_secret: String,
}

#[derive(Serialize)]
struct Ed25519Vector {
    alg: &'static str,
    curve: &'static str,
    secret_key: String,
    public_key: String,
    message: String,
    signature: String,
}

#[derive(Serialize)]
struct Secp256k1Vector {
    alg: &'static str,
    curve: &'static str,
    secret_key: String,
    public_key_compressed: String,
    // ECDSA (ES256K) signing material. The signature is deterministic
    // (RFC 6979), SHA-256 prehashed, and 64-byte compact low-S (BIP 0062);
    // every lane must reproduce these exact bytes.
    ecdsa_message: String,
    ecdsa_signature_compact: String,
}

#[derive(Serialize)]
struct Bip340SchnorrVector {
    alg: &'static str,
    scheme: &'static str,
    curve: &'static str,
    public_key_format: &'static str,
    secret_key: String,
    public_key_xonly: String,
    message: String,
    aux_rand: String,
    signature: String,
}

#[derive(Serialize)]
struct RsaVector {
    alg: &'static str,
    key_format: &'static str,
    public_key_der: String,
    message: String,
    pkcs1v15_sha1_signature: String,
    pkcs1v15_sha256_signature: String,
    pkcs1v15_sha384_signature: String,
    pkcs1v15_sha512_signature: String,
    pss_sha256_mgf1_sha256_salt_len: usize,
    pss_sha256_mgf1_sha256_signature: String,
    pss_sha1_mgf1_sha1_salt_len: usize,
    pss_sha1_mgf1_sha1_signature: String,
    pss_sha384_mgf1_sha384_salt_len: usize,
    pss_sha384_mgf1_sha384_signature: String,
    pss_sha512_mgf1_sha512_salt_len: usize,
    pss_sha512_mgf1_sha512_signature: String,
}

#[derive(Serialize)]
struct X25519Vector {
    alg: &'static str,
    curve: &'static str,
    secret_key: String,
    public_key: String,
    peer_secret_key: String,
    peer_public_key: String,
    shared_secret: String,
}

#[derive(Serialize)]
struct MlDsaVector {
    alg: &'static str,
    scheme: &'static str,
    secret_key_format: &'static str,
    secret_key: String,
    public_key: String,
    public_key_length: usize,
    /// Message signed by `signature`, so every lane signs identical bytes.
    message: String,
    /// Deterministic ML-DSA-87 signature (FIPS 204 deterministic variant,
    /// empty context). Every implementation must reproduce it exactly.
    signature: String,
}

#[derive(Serialize)]
struct SlhDsaVector {
    alg: &'static str,
    scheme: &'static str,
    hash: &'static str,
    parameter_set: &'static str,
    secret_key_format: &'static str,
    keygen_sk_seed: String,
    keygen_sk_prf: String,
    keygen_pk_seed: String,
    secret_key: String,
    public_key: String,
    public_key_length: usize,
    secret_key_length: usize,
    message: String,
    signature: String,
    signature_length: usize,
}

#[derive(Serialize)]
struct MlKemVector {
    alg: &'static str,
    scheme: &'static str,
    secret_key_format: &'static str,
    secret_key: String,
    public_key: String,
    public_key_length: usize,
    /// 32-byte encapsulation randomness (`m`) driving deterministic
    /// encapsulation, committed so the ciphertext is reproducible.
    encaps_randomness: String,
    /// Ciphertext produced by deterministic encapsulation to `public_key`.
    ciphertext: String,
    /// Shared secret from encapsulating (equals the decapsulation result).
    shared_secret: String,
    /// `ciphertext` with one byte flipped; must trigger FIPS 203 implicit
    /// rejection rather than an error.
    tampered_ciphertext: String,
    /// Pseudorandom shared secret implicit rejection yields for
    /// `tampered_ciphertext`. Deterministic given the secret key, so every
    /// implementation must agree — and it must differ from `shared_secret`.
    tampered_shared_secret: String,
}

/// Deterministic ML-KEM known-answer data for one variant.
struct MlKemKat {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
    tampered_ciphertext: Vec<u8>,
    tampered_shared_secret: Vec<u8>,
}

#[derive(Serialize)]
struct XWingVectors {
    x_wing_768: XWingVector,
}

#[derive(Serialize)]
struct XWingVector {
    alg: &'static str,
    scheme: &'static str,
    secret_key_format: &'static str,
    secret_key: String,
    public_key: String,
    public_key_length: usize,
    encaps_seed: String,
    ciphertext: String,
    ciphertext_length: usize,
    shared_secret: String,
}

#[derive(Serialize)]
struct HpkeVectors {
    p256_sha256_aes256gcm: HpkeVector,
    x25519_sha256_chacha20poly1305: HpkeVector,
}

#[derive(Serialize)]
struct HpkeVector {
    alg: &'static str,
    mode: &'static str,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    recipient_secret_key: String,
    recipient_public_key: String,
    encaps_seed: String,
    info: String,
    aad: String,
    plaintext: String,
    encapsulated_key: String,
    ciphertext: String,
    tampered_ciphertext: String,
}

#[derive(Serialize)]
struct AesGcmVector {
    alg: &'static str,
    key: String,
    nonce: String,
    aad: String,
    plaintext: String,
    ciphertext_with_tag: String,
}

#[derive(Serialize)]
struct ConcatKdfVector {
    alg: &'static str,
    profile: &'static str,
    shared_secret: String,
    algorithm_id: String,
    party_u_info: String,
    party_v_info: String,
    output_len: usize,
    derived_key: String,
}

#[derive(Serialize)]
struct AesGcmSivVector {
    alg: &'static str,
    key: String,
    nonce: String,
    aad: String,
    plaintext: String,
    ciphertext_with_tag: String,
}

#[derive(Serialize)]
struct Argon2idVector {
    alg: &'static str,
    kdf_version: u32,
    memory_cost_kib: u32,
    time_cost: u32,
    parallelism: u32,
    secret: String,
    salt: String,
    derived_key: String,
}

#[derive(Serialize)]
struct AesKwVector {
    alg: &'static str,
    kek: String,
    key_data: String,
    wrapped_key: String,
}

#[derive(Serialize)]
struct KmacVector {
    alg: &'static str,
    key: String,
    context: String,
    customization: String,
    output_length: usize,
    derived_key: String,
}

#[derive(Serialize)]
struct ChaCha20Poly1305Vectors {
    chacha20_poly1305: ChaCha20Poly1305Vector,
    xchacha20_poly1305: ChaCha20Poly1305Vector,
}

#[derive(Serialize)]
struct ChaCha20Poly1305Vector {
    alg: &'static str,
    key: String,
    nonce: String,
    aad: String,
    plaintext: String,
    ciphertext_with_tag: String,
}

#[derive(Serialize)]
struct HmacVectors {
    hmac_sha256: HmacVector,
    hmac_sha384: HmacVector,
    hmac_sha512: HmacVector,
}

#[derive(Serialize)]
struct HmacVector {
    alg: &'static str,
    key: String,
    message: String,
    tag: String,
}

#[derive(Serialize)]
struct HkdfVector {
    alg: &'static str,
    hash: &'static str,
    ikm: String,
    salt: String,
    info: String,
    output_len: usize,
    okm: String,
}

#[derive(Serialize)]
struct Pbkdf2Vectors {
    pbkdf2_hmac_sha256: Pbkdf2Vector,
    pbkdf2_hmac_sha512: Pbkdf2Vector,
}

#[derive(Serialize)]
struct Pbkdf2Vector {
    alg: &'static str,
    password: String,
    salt: String,
    iterations: u32,
    output_len: usize,
    derived_key: String,
}

#[derive(Serialize)]
struct HashVector {
    message: String,
    sha2_256: String,
    sha2_384: String,
    sha2_512: String,
    sha3_224: String,
    sha3_256: String,
    sha3_384: String,
    sha3_512: String,
}

#[derive(Serialize)]
struct JwkVectors {
    vectors: Vec<JwkVector>,
}

#[derive(Serialize)]
struct JwkVector {
    alg: &'static str,
    public_key: String,
    public_key_length: usize,
    kty: &'static str,
    crv: &'static str,
    jwk_jcs: String,
    multikey: Option<String>,
    multikey_status: &'static str,
}

struct GeneratedKeys {
    p256_public: Vec<u8>,
    p256_secret: Vec<u8>,
    p256_peer_public: Vec<u8>,
    p256_peer_secret: Vec<u8>,
    p384_public: Vec<u8>,
    p384_secret: Vec<u8>,
    p384_peer_public: Vec<u8>,
    p384_peer_secret: Vec<u8>,
    p521_public: Vec<u8>,
    p521_secret: Vec<u8>,
    p521_peer_public: Vec<u8>,
    p521_peer_secret: Vec<u8>,
    ed25519_public: Vec<u8>,
    ed25519_secret: Vec<u8>,
    secp256k1_public: Vec<u8>,
    secp256k1_secret: Vec<u8>,
    x25519_public: Vec<u8>,
    x25519_secret: Vec<u8>,
    x25519_peer_public: Vec<u8>,
    x25519_peer_secret: Vec<u8>,
    ml_dsa_44_public: Vec<u8>,
    ml_dsa_44_secret: Vec<u8>,
    ml_dsa_65_public: Vec<u8>,
    ml_dsa_65_secret: Vec<u8>,
    ml_dsa_87_public: Vec<u8>,
    ml_dsa_87_secret: Vec<u8>,
    slh_dsa_sha2_128s_public: Vec<u8>,
    slh_dsa_sha2_128s_secret: Vec<u8>,
    mlkem512_public: Vec<u8>,
    mlkem512_secret: Vec<u8>,
    mlkem768_public: Vec<u8>,
    mlkem768_secret: Vec<u8>,
    mlkem1024_public: Vec<u8>,
    mlkem1024_secret: Vec<u8>,
}
