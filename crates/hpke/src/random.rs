// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use core::convert::Infallible;

use hpke::rand_core::{utils::next_word_via_fill, TryCryptoRng, TryRng};

pub(crate) struct FixedRandomness<'a> {
    remaining: &'a [u8],
    exhausted: bool,
}

impl<'a> FixedRandomness<'a> {
    pub(crate) fn new(randomness: &'a [u8]) -> Self {
        Self {
            remaining: randomness,
            exhausted: false,
        }
    }

    pub(crate) fn was_consumed_exactly(&self) -> bool {
        !self.exhausted && self.remaining.is_empty()
    }
}

impl TryRng for FixedRandomness<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        if dest.len() > self.remaining.len() {
            self.exhausted = true;
            // A nonzero deterministic fallback lets scalar-generation loops
            // terminate before the caller maps exhaustion to a typed error.
            dest.fill(1);
            return Ok(());
        }

        let (taken, rest) = self.remaining.split_at(dest.len());
        dest.copy_from_slice(taken);
        self.remaining = rest;
        Ok(())
    }
}

impl TryCryptoRng for FixedRandomness<'_> {}
