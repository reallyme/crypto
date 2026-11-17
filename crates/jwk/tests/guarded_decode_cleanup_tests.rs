// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Observe live initialized allocations before their allocator releases them.

#![cfg(not(target_arch = "wasm32"))]
#![allow(unsafe_code, clippy::unwrap_used, missing_docs)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

const MARKER: &str = "private-cleanup-regression-83bd5f";
const NUMERIC_MARKER: &str = "773495662153840927";
const KEY_MARKER: &[u8] = b"identifying-public-key-43ab";
static OBSERVE: AtomicBool = AtomicBool::new(false);
static UNWIPED: AtomicUsize = AtomicUsize::new(0);
struct ObserveRelease;
#[global_allocator]
static ALLOCATOR: ObserveRelease = ObserveRelease;

// SAFETY: Requests use System with their unchanged layout and ownership.
// Every byte is initialized on allocation, including padding. Inspection occurs
// only while the allocation is live and exclusively owned for deallocation.
unsafe impl GlobalAlloc for ObserveRelease {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: Forward the caller's valid allocation layout unchanged.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            // SAFETY: System returned this writable allocation of layout.size().
            unsafe { pointer.write_bytes(0, layout.size()) };
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if OBSERVE.load(Relaxed) {
            // SAFETY: This allocation is live, initialized, and exclusively
            // owned for deallocation; no bytes are inspected after release.
            let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
            if bytes
                .windows(MARKER.len())
                .any(|window| window == MARKER.as_bytes())
                || bytes
                    .windows(NUMERIC_MARKER.len())
                    .any(|window| window == NUMERIC_MARKER.as_bytes())
                || bytes
                    .windows(KEY_MARKER.len())
                    .any(|window| window == KEY_MARKER)
            {
                UNWIPED.fetch_add(1, Relaxed);
            }
        }
        // SAFETY: The original pointer/layout pair belongs to System.
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let Ok(next) = Layout::from_size_align(size, layout.align()) else {
            return std::ptr::null_mut();
        };
        // SAFETY: The new layout is validated above, and alloc initializes it.
        let replacement = unsafe { self.alloc(next) };
        if !replacement.is_null() {
            // SAFETY: Distinct live allocations do not overlap. Copy length
            // is bounded by both layouts; the old allocation remains owned.
            unsafe { std::ptr::copy_nonoverlapping(pointer, replacement, size.min(layout.size())) };
            // SAFETY: Retire the original allocation with its original layout.
            unsafe { self.dealloc(pointer, layout) };
        }
        replacement
    }
}

fn releases(operation: impl FnOnce()) -> usize {
    UNWIPED.store(0, Relaxed);
    OBSERVE.store(true, Relaxed);
    operation();
    OBSERVE.store(false, Relaxed);
    UNWIPED.load(Relaxed)
}

#[test]
fn guarded_jwk_admission_clears_partial_fields_and_extensions() {
    use envelopes_jwk::{AkpJwk, EcJwk, Jwk, OkpJwk};
    assert!(releases(|| drop(std::hint::black_box(MARKER.to_owned()))) > 0);
    let inputs = [
        format!(r#"{{"kid":{NUMERIC_MARKER},"kty":"EC"}}"#),
        format!("\"{MARKER}\""),
        format!(r#"{{"kid":"{MARKER}","kty":"invalid"}}"#),
        format!(r#"{{"kid":"{MARKER}","kty":"EC","crv":"P-256","x":"AA"}}"#),
        format!(r#"{{"kid":"{MARKER}","kty":"OKP","crv":"Ed25519","x":false}}"#),
        format!(r#"{{"kid":"{MARKER}","kty":"AKP","alg":"ML-DSA-44"}}"#),
        format!(r#"{{"kid":"{MARKER}","kty":"EC","d":null}}"#),
        format!(r#"{{"kid":"{MARKER}","kid":"duplicate","kty":"EC"}}"#),
        format!(r#"{{"x-extension":{{"claim":["{MARKER}"]}},"kty":"unsupported"}}"#),
        format!(
            r#"{{"x-extension":{{"claim":["{MARKER}"]}},"kty":"EC","broken":"{MARKER}","x":false}}"#
        ),
        format!(r#"{{"kid":"{MARKER}","x-extension":["{MARKER}",{{"nested":"{MARKER}","bad":]}}"#),
        format!(r#"{{"kid":"{MARKER}","kty":false}}"#),
    ];
    for input in &inputs {
        assert_eq!(
            releases(|| {
                assert!(serde_json::from_str::<Jwk>(input).is_err());
            }),
            0
        );
        assert_eq!(
            releases(|| {
                assert!(serde_json::from_str::<EcJwk>(input).is_err());
            }),
            0
        );
        assert_eq!(
            releases(|| {
                assert!(serde_json::from_str::<OkpJwk>(input).is_err());
            }),
            0
        );
        assert_eq!(
            releases(|| {
                assert!(serde_json::from_str::<AkpJwk>(input).is_err());
            }),
            0
        );
    }
    for tail in [
        r#"{"kty":"unsupported"}"#,
        r#"{"kid":"later","kty":"EC","x":false}"#,
    ] {
        let input = format!(
            r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"AA","kid":"{MARKER}"}},{tail}]}}"#
        );
        assert_eq!(
            releases(|| {
                assert!(serde_json::from_str::<envelopes_jwk::Jwks>(&input).is_err());
            }),
            0
        );
    }
    let duplicate_keys = format!(
        r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"AA","kid":"{MARKER}"}}],"keys":[]}}"#
    );
    assert_eq!(
        releases(|| {
            assert!(serde_json::from_str::<envelopes_jwk::Jwks>(&duplicate_keys).is_err());
        }),
        0
    );
    for input in [format!("\"{MARKER}\""), format!(r#"{{"keys":"{MARKER}"}}"#)] {
        assert_eq!(
            releases(|| {
                assert!(serde_json::from_str::<envelopes_jwk::Jwks>(&input).is_err());
            }),
            0
        );
    }
    #[cfg(feature = "proto")]
    {
        use envelopes_jwk::proto_options::ProtectedJwk;
        let mut bytes = [0_u8; 32];
        bytes[..KEY_MARKER.len()].copy_from_slice(KEY_MARKER);
        let x = codec_base64url::bytes_to_base64url(&bytes);
        let valid_length_y = codec_base64url::bytes_to_base64url(&[0_u8; 32]);
        for y in ["!", valid_length_y.as_str()] {
            let input = format!(r#"{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}"}}"#);
            assert_eq!(
                releases(|| {
                    assert!(serde_json::from_str::<ProtectedJwk>(&input).is_err());
                }),
                0
            );
        }
    }
    // A completed legacy result transfers to its protected public owner before
    // fallible key validation; admission copies have already been cleared.
    #[cfg(feature = "proto")]
    {
        use envelopes_jwk::proto_options::ProtectedJwk;
        let input = format!(
            r#"{{"kty":"EC","crv":"P-256","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","kid":"{MARKER}"}}"#
        );
        for suffix in ["", " trailing"] {
            let token = format!("{input}{suffix}");
            let set = format!(r#"{{"keys":[{input}]}}{suffix}"#);
            assert_eq!(
                releases(|| {
                    let result = serde_json::from_str::<ProtectedJwk>(&token);
                    assert_eq!(result.is_ok(), suffix.is_empty());
                }),
                0
            );
            assert_eq!(
                releases(|| {
                    let result =
                        serde_json::from_str::<envelopes_jwk::proto_options::ProtectedJwks>(&set);
                    assert_eq!(result.is_ok(), suffix.is_empty());
                }),
                0
            );
        }
        assert_eq!(
            releases(|| {
                let jwk = serde_json::from_str::<Jwk>(&input).unwrap();
                let protected = ProtectedJwk::try_from(jwk).unwrap();
                assert!(
                    matches!(protected.as_jwk(), Jwk::Ec(key) if key.kid.as_deref() == Some(MARKER))
                );
            }),
            0
        );
    }
}
