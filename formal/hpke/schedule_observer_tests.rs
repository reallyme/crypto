// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Included only in the temporary, checksummed backend used for the vector audit.

use core::cell::Cell;

pub struct Schedule<'a> {
    pub shared_secret: &'a [u8],
    pub context: &'a [u8],
    pub secret: &'a [u8],
    pub key: &'a [u8],
    pub base_nonce: Option<&'a [u8]>,
    pub exporter_secret: &'a [u8],
}

std::thread_local! {
    static EXPECTED: Cell<Option<&'static Schedule<'static>>> = const { Cell::new(None) };
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
            "DHKEM shared_secret"
        );
        assert!(actual.context == expected.context, "key_schedule_context");
        assert!(actual.secret == expected.secret, "secret");
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
