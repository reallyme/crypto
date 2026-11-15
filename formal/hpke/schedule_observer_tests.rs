// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Included only in the temporary, checksummed backend used for the vector audit.

use core::cell::Cell;

pub struct Schedule<'a> {
    pub shared_secret: &'a [u8],
    pub context: Option<&'a [u8]>,
    pub secret: Option<&'a [u8]>,
    pub key: &'a [u8],
    pub base_nonce: Option<&'a [u8]>,
    pub exporter_secret: &'a [u8],
}

std::thread_local! {
    static EXPECTED: Cell<Option<&'static Schedule<'static>>> = const { Cell::new(None) };
    static EXPECTED_NONCE: Cell<Option<&'static [u8]>> = const { Cell::new(None) };
}

pub fn verify<T>(expected: &'static Schedule<'static>, setup: impl FnOnce() -> T) -> T {
    EXPECTED.with(|slot| {
        assert!(slot.replace(Some(expected)).is_none());
        let output = setup();
        assert!(
            slot.take().is_none(),
            "setup bypassed the audited key schedule"
        );
        output
    })
}

pub(crate) fn observe(actual: Schedule<'_>) {
    EXPECTED.with(|slot| {
        let expected = slot.take().expect("unexpected key schedule invocation");
        assert!(
            actual.shared_secret == expected.shared_secret,
            "KEM shared_secret"
        );
        if let Some(context) = expected.context {
            assert!(actual.context == Some(context), "key_schedule_context");
        }
        if let Some(secret) = expected.secret {
            assert!(actual.secret == Some(secret), "secret");
        }
        assert!(actual.key == expected.key, "traffic key");
        if let Some(nonce) = expected.base_nonce {
            assert!(actual.base_nonce == Some(nonce), "base_nonce");
        }
        assert!(
            actual.exporter_secret == expected.exporter_secret,
            "exporter_secret"
        );
    });
}

pub fn verify_nonce<T>(expected: &'static [u8], record: impl FnOnce() -> T) -> T {
    EXPECTED_NONCE.with(|slot| {
        assert!(slot.replace(Some(expected)).is_none());
        let output = record();
        assert!(slot.take().is_none(), "record bypassed nonce derivation");
        output
    })
}

pub(crate) fn observe_nonce(actual: &[u8]) {
    EXPECTED_NONCE.with(|slot| {
        let expected = slot.take().expect("unexpected record nonce derivation");
        assert!(actual == expected, "record nonce differs from the vector");
    });
}
