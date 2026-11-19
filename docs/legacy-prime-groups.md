# Legacy prime-group domains

Enable `prime-groups` for these legacy interoperability domains. Applications
must decide whether their protocol and strength policy permit them.

| `PrimeGroup` variant | Protobuf value | Field/scalar bytes | Uncompressed point bytes |
| --- | --- | --- | --- |
| `NistP192` | `PRIME_GROUP_NIST_P192 = 130` | 24 | 49 |
| `BrainpoolP192r1` | `PRIME_GROUP_BRAINPOOL_P192R1 = 240` | 24 | 49 |
| `BrainpoolP224r1` | `PRIME_GROUP_BRAINPOOL_P224R1 = 250` | 28 | 57 |

Parameters come from [SEC 2 §2.2.2](https://www.secg.org/sec2-v2.pdf#page=10)
and [RFC 5639 §§3.2–3.3](https://www.rfc-editor.org/rfc/rfc5639.html#section-3.2).
ReallyMe enum values are not a protocol's domain-parameter identifiers.

The API provides `generator`, `scalar`, `random_scalar`, supplied-base
`multiply`, `linear_combination`, `reduce_to_field`, `encode_field` and
agreement operations. Add `operation-response` for standalone schema adapters.
These domains are separate from the seven-curve ECDSA interface.

Outputs preserve fixed widths and leading zeros. Scalar and point inputs must
use the selected domain's canonical encoding. See the
[portable Brainpool memory limitation](../SECURITY_MEMORY_MODEL.md#known-portable-brainpool-limitation).
