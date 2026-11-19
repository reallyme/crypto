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

Select a supported provider from [PROVIDER_POLICY.md](PROVIDER_POLICY.md).
Algorithm availability differs by SDK and build features. An unavailable
provider returns a typed error; it does not select a substitute.

The library supplies primitives, not application trust policy. Applications
must authenticate public keys, bind protocol context, enforce nonce and replay
rules, and protect caller-owned secret copies. Read the
[memory limitations](SECURITY_MEMORY_MODEL.md), including the known portable
Brainpool serialization limitation, before choosing a deployment profile.

For local verification commands, see [conformance](docs/conformance.md).
Formal verification covers bounded properties under the assumptions documented
in [formal/README.md](formal/README.md); it is not a proof of the entire SDK.
