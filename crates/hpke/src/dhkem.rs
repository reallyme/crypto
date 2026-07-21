// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Shared RFC 9180 DHKEM adapter machinery for locally integrated groups.

use core::marker::PhantomData;

use hpke::hybrid_array::ArraySize;
use hpke::kdf::Kdf;
use hpke::kem::SharedSecret;
use hpke::rand_core::CryptoRng;
use hpke::{Deserializable, Kem, Serializable};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DhKemBufferError {
    LengthOverflow,
    AllocationFailure,
}

pub(crate) trait DhGroup: 'static {
    type PrivateKey: Clone + ZeroizeOnDrop;
    type PublicKey: Clone + PartialEq + Eq;
    type RawSharedSecret: ZeroizeOnDrop;
    type PublicKeySize: ArraySize;
    type PrivateKeySize: ArraySize;
    type SecretSize: ArraySize;
    type KemKdf: Kdf;

    const KEM_ID: u16;
    const PUBLIC_KEY_LEN: usize;
    const PRIVATE_KEY_LEN: usize;

    fn derive_private_key(input_key_material: &[u8]) -> Self::PrivateKey;
    fn private_key_from_bytes(encoded: &[u8]) -> Result<Self::PrivateKey, hpke::HpkeError>;
    fn write_private_key(private_key: &Self::PrivateKey, output: &mut [u8]);
    fn public_key_from_bytes(encoded: &[u8]) -> Result<Self::PublicKey, hpke::HpkeError>;
    fn write_public_key(public_key: &Self::PublicKey, output: &mut [u8]);
    fn public_key_from_private(private_key: &Self::PrivateKey) -> Self::PublicKey;
    fn private_keys_equal(left: &Self::PrivateKey, right: &Self::PrivateKey) -> Choice;
    fn diffie_hellman(
        private_key: &Self::PrivateKey,
        public_key: &Self::PublicKey,
    ) -> Result<Self::RawSharedSecret, hpke::HpkeError>;
    fn shared_secret_bytes(secret: &Self::RawSharedSecret) -> &[u8];
}

pub(crate) struct DhPrivateKey<Group: DhGroup>(Group::PrivateKey);

impl<Group: DhGroup> Clone for DhPrivateKey<Group> {
    fn clone(&self) -> Self {
        // `Kem` requires cloneable private keys. Every clone is an independent
        // owner whose inner key zeroizes when that owner is dropped.
        Self(self.0.clone())
    }
}

impl<Group: DhGroup> ConstantTimeEq for DhPrivateKey<Group> {
    fn ct_eq(&self, other: &Self) -> Choice {
        Group::private_keys_equal(&self.0, &other.0)
    }
}

impl<Group: DhGroup> ZeroizeOnDrop for DhPrivateKey<Group> {}

impl<Group: DhGroup> Serializable for DhPrivateKey<Group> {
    type OutputSize = Group::PrivateKeySize;

    fn write_exact(&self, output: &mut [u8]) {
        if output.len() == Group::PRIVATE_KEY_LEN {
            Group::write_private_key(&self.0, output);
        }
    }
}

impl<Group: DhGroup> Deserializable for DhPrivateKey<Group> {
    fn from_bytes(encoded: &[u8]) -> Result<Self, hpke::HpkeError> {
        if encoded.len() != Group::PRIVATE_KEY_LEN {
            return Err(hpke::HpkeError::IncorrectInputLength(
                Group::PRIVATE_KEY_LEN,
                encoded.len(),
            ));
        }
        Group::private_key_from_bytes(encoded).map(Self)
    }
}

pub(crate) struct DhPublicKey<Group: DhGroup>(Group::PublicKey);

impl<Group: DhGroup> Clone for DhPublicKey<Group> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<Group: DhGroup> PartialEq for DhPublicKey<Group> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<Group: DhGroup> Eq for DhPublicKey<Group> {}

impl<Group: DhGroup> core::fmt::Debug for DhPublicKey<Group> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DhPublicKey(<redacted>)")
    }
}

impl<Group: DhGroup> Serializable for DhPublicKey<Group> {
    type OutputSize = Group::PublicKeySize;

    fn write_exact(&self, output: &mut [u8]) {
        if output.len() == Group::PUBLIC_KEY_LEN {
            Group::write_public_key(&self.0, output);
        }
    }
}

impl<Group: DhGroup> Deserializable for DhPublicKey<Group> {
    fn from_bytes(encoded: &[u8]) -> Result<Self, hpke::HpkeError> {
        if encoded.len() != Group::PUBLIC_KEY_LEN {
            return Err(hpke::HpkeError::IncorrectInputLength(
                Group::PUBLIC_KEY_LEN,
                encoded.len(),
            ));
        }
        Group::public_key_from_bytes(encoded).map(Self)
    }
}

pub(crate) struct DhKem<Group: DhGroup>(PhantomData<Group>);

impl<Group: DhGroup> Kem for DhKem<Group> {
    type PublicKey = DhPublicKey<Group>;
    type PrivateKey = DhPrivateKey<Group>;
    type EncappedKey = DhPublicKey<Group>;
    type NSecret = Group::SecretSize;

    const KEM_ID: u16 = Group::KEM_ID;

    fn sk_to_pk(secret_key: &Self::PrivateKey) -> Self::PublicKey {
        DhPublicKey(Group::public_key_from_private(&secret_key.0))
    }

    fn derive_keypair(input_key_material: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        let private_key = DhPrivateKey(Group::derive_private_key(input_key_material));
        let public_key = Self::sk_to_pk(&private_key);
        (private_key, public_key)
    }

    fn decap(
        recipient_secret_key: &Self::PrivateKey,
        sender_public_key: Option<&Self::PublicKey>,
        encapsulated_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, hpke::HpkeError> {
        let recipient_public_key = Self::sk_to_pk(recipient_secret_key);
        let first_secret = Group::diffie_hellman(&recipient_secret_key.0, &encapsulated_key.0)
            .map_err(|_| hpke::HpkeError::DecapError)?;

        let mut dh = allocate_secret_buffer(
            Group::shared_secret_bytes(&first_secret).len(),
            sender_public_key.is_some(),
        )
        .map_err(|_| hpke::HpkeError::DecapError)?;
        append_piece(&mut dh, Group::shared_secret_bytes(&first_secret))
            .map_err(|_| hpke::HpkeError::DecapError)?;
        if let Some(sender_public_key) = sender_public_key {
            let sender_secret =
                Group::diffie_hellman(&recipient_secret_key.0, &sender_public_key.0)
                    .map_err(|_| hpke::HpkeError::DecapError)?;
            append_piece(&mut dh, Group::shared_secret_bytes(&sender_secret))
                .map_err(|_| hpke::HpkeError::DecapError)?;
        }

        let mut context = Vec::new();
        append_serialized(&mut context, encapsulated_key)
            .map_err(|_| hpke::HpkeError::DecapError)?;
        append_serialized(&mut context, &recipient_public_key)
            .map_err(|_| hpke::HpkeError::DecapError)?;
        if let Some(sender_public_key) = sender_public_key {
            append_serialized(&mut context, sender_public_key)
                .map_err(|_| hpke::HpkeError::DecapError)?;
        }
        extract_and_expand::<Group>(&dh, &context).map_err(|_| hpke::HpkeError::DecapError)
    }

    fn encap_with_rng(
        recipient_public_key: &Self::PublicKey,
        sender_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut impl CryptoRng,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), hpke::HpkeError> {
        let (ephemeral_private_key, encapsulated_key) = Self::gen_keypair_with_rng(csprng);
        let first_secret = Group::diffie_hellman(&ephemeral_private_key.0, &recipient_public_key.0)
            .map_err(|_| hpke::HpkeError::EncapError)?;

        let mut dh = allocate_secret_buffer(
            Group::shared_secret_bytes(&first_secret).len(),
            sender_keypair.is_some(),
        )
        .map_err(|_| hpke::HpkeError::EncapError)?;
        append_piece(&mut dh, Group::shared_secret_bytes(&first_secret))
            .map_err(|_| hpke::HpkeError::EncapError)?;
        if let Some((sender_private_key, _)) = sender_keypair {
            let sender_secret =
                Group::diffie_hellman(&sender_private_key.0, &recipient_public_key.0)
                    .map_err(|_| hpke::HpkeError::EncapError)?;
            append_piece(&mut dh, Group::shared_secret_bytes(&sender_secret))
                .map_err(|_| hpke::HpkeError::EncapError)?;
        }

        let mut context = Vec::new();
        append_serialized(&mut context, &encapsulated_key)
            .map_err(|_| hpke::HpkeError::EncapError)?;
        append_serialized(&mut context, recipient_public_key)
            .map_err(|_| hpke::HpkeError::EncapError)?;
        if let Some((_, sender_public_key)) = sender_keypair {
            append_serialized(&mut context, sender_public_key)
                .map_err(|_| hpke::HpkeError::EncapError)?;
        }
        let shared_secret =
            extract_and_expand::<Group>(&dh, &context).map_err(|_| hpke::HpkeError::EncapError)?;
        Ok((shared_secret, encapsulated_key))
    }
}

fn append_piece(output: &mut Vec<u8>, piece: &[u8]) -> Result<(), DhKemBufferError> {
    let required = output
        .len()
        .checked_add(piece.len())
        .ok_or(DhKemBufferError::LengthOverflow)?;
    if required > output.capacity() {
        let additional = required
            .checked_sub(output.len())
            .ok_or(DhKemBufferError::LengthOverflow)?;
        output
            .try_reserve_exact(additional)
            .map_err(|_| DhKemBufferError::AllocationFailure)?;
    }
    output.extend_from_slice(piece);
    Ok(())
}

fn allocate_secret_buffer(
    piece_length: usize,
    has_second_piece: bool,
) -> Result<Zeroizing<Vec<u8>>, DhKemBufferError> {
    let piece_count = 1usize
        .checked_add(usize::from(has_second_piece))
        .ok_or(DhKemBufferError::LengthOverflow)?;
    let required = piece_length
        .checked_mul(piece_count)
        .ok_or(DhKemBufferError::LengthOverflow)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(required)
        .map_err(|_| DhKemBufferError::AllocationFailure)?;
    Ok(Zeroizing::new(output))
}

fn append_serialized<Value: Serializable>(
    output: &mut Vec<u8>,
    value: &Value,
) -> Result<(), DhKemBufferError> {
    append_piece(output, value.to_bytes().as_slice())
}

fn extract_and_expand<Group: DhGroup>(
    dh: &[u8],
    context: &[u8],
) -> Result<SharedSecret<DhKem<Group>>, hpke::HpkeError> {
    let suite_id = [
        b'K',
        b'E',
        b'M',
        Group::KEM_ID.to_be_bytes()[0],
        Group::KEM_ID.to_be_bytes()[1],
    ];
    let mut shared_secret = SharedSecret::<DhKem<Group>>::default();
    Group::KemKdf::extract_and_expand(dh, &suite_id, context, &mut shared_secret.0)?;
    Ok(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::{allocate_secret_buffer, append_piece, DhKemBufferError};

    #[test]
    fn authenticated_mode_secret_buffer_never_reallocates_between_dh_outputs(
    ) -> Result<(), DhKemBufferError> {
        let mut output = allocate_secret_buffer(32, true)?;
        append_piece(&mut output, &[0x11; 32])?;
        let allocation = output.as_ptr();
        append_piece(&mut output, &[0x22; 32])?;

        assert_eq!(output.len(), 64);
        assert_eq!(output.as_ptr(), allocation);
        Ok(())
    }
}
