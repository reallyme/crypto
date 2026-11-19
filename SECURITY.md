# Security Policy

## Reporting a vulnerability

Report vulnerabilities privately through this repository's **Security →
Advisories → Report a vulnerability** page or email **security@really.me**.
Do not put vulnerability details in a public issue.

Include the affected package and version or commit, platform/provider, a minimal
reproduction and the observed impact. Use test keys and synthetic input;
do not send production keys, credentials or personal data.

Reports may cover incorrect cryptographic results, authentication bypass,
secret disclosure, side channels, untrusted-input crashes or denial of service,
and undeclared provider substitution. Report dependency vulnerabilities upstream
and notify this repository when its packages are affected.

Reports are acknowledged within three business days and initially triaged within
ten. The coordinated-disclosure target is 90 days from triage; agree the date
and attribution with the maintainers.

## Using the packages safely

Pin a published release or exact commit and monitor releases and security
advisories. Security fixes are released on the active package line.

Select a supported provider from [provider_manifest.json](provider_manifest.json)
and follow the SDK's setup instructions.
Algorithm availability differs by SDK and build features. An unavailable
provider returns a typed error; it does not select a substitute.

The library supplies primitives, not application trust policy. Applications
must authenticate public keys, bind protocol context, enforce nonce and replay
rules, and protect caller-owned secret copies. AEAD callers must supply their
protocol's AAD; the primitive does not add protocol context.

Rust secret owners clear their retained storage on drop. Caller-owned copies
and exported bytes require separate cleanup. Swift, Kotlin and JavaScript
buffers cannot guarantee erasure of runtime, provider or compiler copies.
Keep secrets in byte buffers, clear them promptly, and use binary protobuf
for secret-bearing requests rather than JSON strings.

## Portable Brainpool

Portable Brainpool ECDH uses `primefield` 0.14.0, which leaves an unguarded
coordinate-serialization buffer. The returned secret owner clears its retained
bytes but cannot clear that intermediate copy. Do not choose this path when
your deployment requires every library-owned secret buffer to be wiped.

For local verification commands, see [conformance](docs/conformance.md).
Formal verification covers bounded properties under the assumptions documented
in [formal/README.md](formal/README.md); it is not a proof of the entire SDK.
