# ReallyMe Buffa integration

The migration targets the published ReallyMe Buffa 0.1.0 family, following its
[release contract](https://github.com/reallyme/buffa/blob/reallyme-v0.1.0/FORK.md)
and [guarded-field guide](https://github.com/reallyme/buffa/blob/reallyme-v0.1.0/docs/guarded-fields.md).
Existing protobuf package names, field numbers and wire meanings remain the
authority. This inventory precedes implementation changes and binds the
previous integration to source commit `293cf032dc74a62ed6973b5bdda4cafc088f6886`.

## Existing integration

- The workspace aliases `buffa` to upstream 0.9.2. Nineteen workspace packages
  consume it: conformance vectors, FFI, the umbrella library, Argon2id,
  Concat KDF, constant-time helpers, core, CSPRNG, dispatch, HKDF, HPKE, JWK,
  JWK multikey, PBKDF2, Poseidon2, protobuf, RSA, secp256k1 and SHA-3.
  The resolved all-feature graph has one Buffa runtime and no external
  package requiring it. No current workspace manifest uses `buffa-build`,
  `buffa-types`, descriptor, codegen, proto-options or remote-derive directly.
- `crates/proto` owns all runtime-generated Rust bindings. Its optional
  `generated` feature enables JSON and views; minimal error and immutable
  contract authorities remain independent of the message runtime. Normal and
  fuzz lockfiles contain the resolved integration.
- `buf.gen.yaml` uses the two upstream local Rust plugins. Protobuf CI installs
  them with `BUFFA_VERSION: 0.9.2`. `scripts/check_release_readiness.mjs` and
  its shared policy module guard versions and reproducible generation.
  No protobuf generation runs from `build.rs`; the two existing vector-audit
  build scripts have separate responsibilities. No generated RPC service or
  runtime transport dependency is present.
- The main schema declares 226 messages, 270 byte fields, 15 optional byte
  fields, eleven oneofs, an authentication-prompt string and a repeated public
  provider-name string. Five supplemental runtime schemas contain numeric
  policy/identity records. The separate `contract/v1` schemas define immutable
  maintenance metadata and custom descriptor options; they are excluded from
  runtime message generation. No runtime WKT import, map field, numeric repeated
  field, chrono/jiff adapter or reflection generation is currently present.
- TypeScript uses the ES generator and its own runtime. Swift and Java/Kotlin
  use their platform generators. Their independent diagnostic and buffer
  protections must survive the Rust runtime migration.

## Security behavior and replacement map

| Existing implementation | Native configuration or retained responsibility | Required regression |
| --- | --- | --- |
| Rust Debug rewrites for direct and transitive sensitive owners, views and scalar metadata | Native complete-family cleanup redaction | No secret, oneof case, selector or nested value in Debug; include empty views. |
| Injected `Drop` and `ZeroizeOnDrop`; hand-written clear paths | Native `zeroize` profile for complete runtime families, including referenced numeric records | Clear/drop, scalar and enum reset, nested cleanup, independent clones and error exits. |
| `merge_sensitive` replacement of singular/optional bytes and prompt strings | Wipe-owning custom bytes/string types and their native bounded decode hooks | Short duplicate, empty duplicate, oneof replacement, growth and fragmented invalid UTF-8. |
| Hand-written temporary JSON `Wire` structs and byte visitors | Native early cleanup owners and explicit `ProtoBytesJson`/`ProtoStringJson` policies; retain audited base64 acceptance and fixed diagnostics | Earlier-field failure cleanup, optional absent/empty, both alphabets, padding/trailing bits and malformed suffixes. |
| Retained unknown-field wrapper and recursive unknown-group decoder | Disable storage for cleanup messages and explicitly reject unknown fields at every untrusted admission decoder | Unknown fields/groups/closed enums, nested rejection and resource accounting; descriptor-option decoding remains separate. |
| Generated oneof JSON unknown-field rewrites | Native `deny_unknown_json_fields` with guarded visitors | Unknown and duplicate JSON fields, aliases, oneofs and fixed diagnostic boundaries. |
| Secret keypair JSON serializer rejection | A distinct selected custom byte policy on the keypair's secret field | Owned and view export refusal, import behavior and permitted public-field encoding. |
| Injected keypair constant-time equality | Constant-time byte-owner equality with secret-first native comparison; preserve schema numbers and canonical encoding | Equal/different secrets and metadata, secret comparison order, unchanged wire goldens. |
| Secret-bearing eager/owned view JSON rewrites | Native `deny_view_json` over the sensitive-owner closure | Denial before output, including empty values and containing messages; permitted numeric metadata remains explicit. |
| Removing Clone from secret-bearing generated owned-view wrappers | A handwritten non-Clone owner boundary, keeping raw generated owned wrappers private | Compile-fail Clone restriction, redacted diagnostics, safe reborrows and clearing backing ownership. |
| Ordinary repeated message/string storage | Native guarded collection selection and wipe-owning elements | Repeated growth, replacement and failure cleanup; fixture coverage for numeric lists/maps. |
| Supplemental numeric-message hardening and private unknown storage | Native recursive cleanup and explicit admission rejection | Scalar cleanup and malformed/unknown input; preserve permitted metadata projection. |
| Rewriting untrusted enum diagnostics | Fixed domain-error mapping at public wire boundaries; audit generator diagnostics rather than reflecting parser text | No caller-controlled diagnostics from public adapters. |
| Swift debugDescription and Java toString post-processing | Retained SDK-only redaction driver; Buffa cannot configure another generator | Direct/nested secret redaction in matching platform tests. |
| Generated whitespace normalization | Retained deterministic formatting responsibility | Repeat generation without content drift or gratuitous timestamp changes. |
| Shared canonical error-enum authority and native constants generation | Retained schema-contract generation; unrelated to secret hardening | Minimal-feature authority, generated/native parity and freshness. |
| Canonical protobuf validation, size/depth limits, JSON operation admission and raw transport owners | Retain application wire/domain boundaries | Noncanonical wire, unknowns, oversized/deep input, secret-bearing JSON rejection and exact context bytes. |

## Boundary considerations

The native cleanup profile requires unknown storage to be disabled. A typed
message cannot recover unknown fields discarded by an earlier permissive
decoder. Untrusted bytes therefore enter through explicitly rejecting bounded
decoders before domain conversion; bare runtime default decoding is not a
substitute for this admission contract. This applies to standalone adapters as
well as operation envelopes. Descriptor decoding that consumes custom options
must retain its distinct extension-aware policy.

Secret-bearing owned views use `GuardedOwnedView`, which eagerly validates
the entire tree, owns clearing wire storage and does not implement `Clone`.
Borrowed views and their lifetime bounds remain native. Input, parser, output
and managed runtime copies retain their existing ownership boundaries.

The product schema imports no WKTs and enables no generated reflection. The
separate guarded fixture exercises the five sensitive WKTs (`Timestamp`,
`Duration`, `Value`, `Struct`, and `ListValue`), numeric collections and
borrowed inspection. Its descriptor and WKT dependencies are dev dependencies.

## Rust callers

These changes target unpublished 0.4.0. Published 0.3 packages keep their
existing APIs. When migrating a source consumer, use the generated builders or
convert owned byte vectors with `.into()`. Borrow message fields instead of
moving them out of an owner that implements `Drop`. `wire::encode_protobuf` and
guarded view conversion return typed results. Use `view()` to borrow fields from
a guarded owned view; `bytes()` returns a slice and cannot share the allocation.

## Remaining Buffa 0.1.0 limitations

- `HasMessageView::ViewHandle` exposes the generated clonable owned wrapper
  even when its module is private. Its required `From<OwnedView<_>>` and
  `AsRef<OwnedView<_>>` also expose ordinary shared wire storage. A precise
  generator option to omit the owned handle and trait implementation for
  selected messages, while keeping borrowed views, would remove the remaining
  Rust source edit in `restrict_buffa_view_handles.mjs`.
- Concrete generated enum JSON errors can include the offending value.
  Crypto selects schema-derived enum types with fixed diagnostics through
  `extern_path`. The runtime `EnumValue` can also echo invalid input; public
  operation decoders discard this diagnostic and report a typed reason. Native
  fixed diagnostics for both paths would eliminate the enum policy adapter.
- The raw runtime merge method decodes a duplicate field before replacing
  its previous value. If decoding fails, that value can remain in the live
  destination. `wire::merge_protobuf` clears the destination on any admission
  error. Fresh decode drops the partial message on failure.
- The guarded repeated list has no fallible reserve or append API. JWK set
  construction reserves a vector of guarded elements before inserting them,
  then transfers that allocation to the guarded list without copying bytes.

The allocator regression observes initialized memory just before deallocation
on growth, successful replacement, failed merge, clone drop, oneof switch and
owned view drop. The generated message tests cover redaction, private key JSON,
optional presence and binary goldens. The guarded fixture tests cover nested
WKT cleanup, repeated and map fields, and eager versus lazy admission. These
checks supplement the earlier schema contract provenance record, which remains
bound to its original checkpoint.
