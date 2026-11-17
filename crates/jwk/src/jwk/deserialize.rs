// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 7517 syntax over schema-owned, clearing admission storage.

use std::{collections::BTreeSet, fmt};

use buffa::json_helpers::ProtoStringJson;
use crypto_proto::{
    generated::proto::reallyme::crypto::v1::{PublicJwkJsonFields, PublicJwksJsonFields},
    SecretString,
};
use serde::{
    de::{Error as SerdeError, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};

use super::{AkpJwk, EcJwk, Jwk, Jwks, OkpJwk};
use crate::JwtError;

const MAX_JWK_MEMBER_COUNT: usize = 16;

// This is a parser adapter, not another wire record. Its value is immediately
// moved into a generated field or the bounded duplicate-member set.
struct Text(SecretString);
impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        SecretString::deserialize_json(deserializer).map(Self)
    }
}

// Reject wrong root/collection types without Serde formatting their received
// values into heap-backed diagnostics. Owned strings still need a wiping owner.
macro_rules! reject_scalar_values {
    () => {
        fn visit_str<E: SerdeError>(self, _: &str) -> Result<Self::Value, E> {
            Err(E::custom(JwtError::PRIMITIVE_MALFORMED_JSON))
        }
        fn visit_string<E: SerdeError>(self, value: String) -> Result<Self::Value, E> {
            let _value = zeroize::Zeroizing::new(value);
            Err(E::custom(JwtError::PRIMITIVE_MALFORMED_JSON))
        }
        fn visit_bool<E: SerdeError>(self, value: bool) -> Result<Self::Value, E> {
            let _value = zeroize::Zeroizing::new(value);
            Err(E::custom(JwtError::PRIMITIVE_MALFORMED_JSON))
        }
        fn visit_i64<E: SerdeError>(self, value: i64) -> Result<Self::Value, E> {
            let _value = zeroize::Zeroizing::new(value);
            Err(E::custom(JwtError::PRIMITIVE_MALFORMED_JSON))
        }
        fn visit_u64<E: SerdeError>(self, value: u64) -> Result<Self::Value, E> {
            let _value = zeroize::Zeroizing::new(value);
            Err(E::custom(JwtError::PRIMITIVE_MALFORMED_JSON))
        }
        fn visit_f64<E: SerdeError>(self, value: f64) -> Result<Self::Value, E> {
            let _value = zeroize::Zeroizing::new(value);
            Err(E::custom(JwtError::PRIMITIVE_MALFORMED_JSON))
        }
        fn visit_unit<E: SerdeError>(self) -> Result<Self::Value, E> {
            Err(E::custom(JwtError::PRIMITIVE_MALFORMED_JSON))
        }
    };
}

struct JwkVisitor {
    expected: Option<&'static str>,
}
impl<'de> Visitor<'de> for JwkVisitor {
    type Value = PublicJwkJsonFields;
    reject_scalar_values!();
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a public JWK object")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<PublicJwkJsonFields, M::Error> {
        let mut fields = PublicJwkJsonFields::default();
        let mut seen = BTreeSet::new();
        while let Some(Text(name)) = map.next_key::<Text>()? {
            if seen.len() >= MAX_JWK_MEMBER_COUNT {
                return Err(M::Error::custom(
                    JwtError::PRIMITIVE_RESOURCE_LIMIT_EXCEEDED,
                ));
            }
            if is_private_member(&name) {
                // Reject before visiting even null or syntactically invalid
                // values. Private material must never enter an admission tree.
                return Err(M::Error::custom(JwtError::PRIMITIVE_INVALID_PARAMETER));
            }
            if !seen.insert(name.clone()) {
                return Err(M::Error::custom(JwtError::PRIMITIVE_MALFORMED_JSON));
            }
            let target = match name.as_str() {
                "kty" => Some((&mut fields.kty, false)),
                "crv" => Some((&mut fields.crv, false)),
                "x" => Some((&mut fields.x, false)),
                "y" => Some((&mut fields.y, false)),
                "pub" => Some((&mut fields.public_key, false)),
                "alg" => Some((&mut fields.alg, true)),
                "use" => Some((&mut fields.usage, true)),
                "kid" => Some((&mut fields.kid, true)),
                _ => None,
            };
            if let Some((slot, optional)) = target {
                *slot = if optional {
                    map.next_value::<Option<Text>>()
                        .map_err(|_| M::Error::custom(JwtError::PRIMITIVE_MALFORMED_JSON))?
                        .map(|value| value.0)
                } else {
                    Some(
                        map.next_value::<Text>()
                            .map_err(|_| M::Error::custom(JwtError::PRIMITIVE_MALFORMED_JSON))?
                            .0,
                    )
                };
            } else {
                // Generated guarded WKT storage preserves JSON admission (also
                // rejecting nonfinite numbers), without an unprotected DOM or
                // partially retained extension strings on parse failure.
                let _value = map
                    .next_value::<buffa_types::sensitive::Value>()
                    .map_err(|_| M::Error::custom(JwtError::PRIMITIVE_MALFORMED_JSON))?;
            }
        }
        validate(&fields, &seen, self.expected).map_err(M::Error::custom)?;
        Ok(fields)
    }
}

fn is_private_member(name: &str) -> bool {
    matches!(
        name,
        "d" | "p" | "q" | "dp" | "dq" | "qi" | "oth" | "k" | "priv" | "privateKey" | "secretKey"
    )
}

fn required(value: &Option<SecretString>) -> Result<&str, JwtError> {
    value
        .as_ref()
        .map(SecretString::as_str)
        .ok_or(JwtError::PRIMITIVE_MALFORMED_JSON)
}
// Borrowed validated shape, not a serializable record. Holding references
// prevents an ordinary JWK allocation until the entire outer JSON succeeds.
enum ValidatedJwk<'a> {
    Ec {
        crv: &'a str,
        x: &'a str,
        y: &'a str,
        fields: &'a PublicJwkJsonFields,
    },
    Okp {
        crv: &'a str,
        x: &'a str,
        fields: &'a PublicJwkJsonFields,
    },
    Akp {
        alg: &'a str,
        public_key: &'a str,
        fields: &'a PublicJwkJsonFields,
    },
}
impl ValidatedJwk<'_> {
    fn into_native(self) -> Jwk {
        fn optional(value: &Option<SecretString>) -> Option<String> {
            value.as_ref().map(|value| value.as_str().to_owned())
        }
        match self {
            Self::Ec { crv, x, y, fields } => Jwk::Ec(EcJwk {
                kty: "EC".to_owned(),
                crv: crv.to_owned(),
                x: x.to_owned(),
                y: y.to_owned(),
                alg: optional(&fields.alg),
                use_: optional(&fields.usage),
                kid: optional(&fields.kid),
            }),
            Self::Okp { crv, x, fields } => Jwk::Okp(OkpJwk {
                kty: "OKP".to_owned(),
                crv: crv.to_owned(),
                x: x.to_owned(),
                alg: optional(&fields.alg),
                use_: optional(&fields.usage),
                kid: optional(&fields.kid),
            }),
            Self::Akp {
                alg,
                public_key,
                fields,
            } => Jwk::Akp(AkpJwk {
                kty: "AKP".to_owned(),
                alg: alg.to_owned(),
                public_key: public_key.to_owned(),
                use_: optional(&fields.usage),
                kid: optional(&fields.kid),
            }),
        }
    }
}
fn validate<'a>(
    fields: &'a PublicJwkJsonFields,
    names: &BTreeSet<SecretString>,
    expected: Option<&str>,
) -> Result<ValidatedJwk<'a>, JwtError> {
    let kty = required(&fields.kty)?;
    if expected.is_some_and(|expected| expected != kty) {
        return Err(JwtError::PRIMITIVE_INVALID_PARAMETER);
    }
    let allowed: &[&str] = match kty {
        "EC" => &["kty", "crv", "x", "y", "alg", "use", "kid"],
        "OKP" => &["kty", "crv", "x", "alg", "use", "kid"],
        "AKP" => &["kty", "alg", "pub", "use", "kid"],
        _ => return Err(JwtError::PROVIDER_UNSUPPORTED_ALGORITHM),
    };
    if names
        .iter()
        .any(|name| !allowed.contains(&name.as_str()) && !name.starts_with("x-"))
    {
        return Err(JwtError::PRIMITIVE_MALFORMED_JSON);
    }
    project(fields)
}
fn project(fields: &PublicJwkJsonFields) -> Result<ValidatedJwk<'_>, JwtError> {
    match required(&fields.kty)? {
        "EC" => Ok(ValidatedJwk::Ec {
            crv: required(&fields.crv)?,
            x: required(&fields.x)?,
            y: required(&fields.y)?,
            fields,
        }),
        "OKP" => Ok(ValidatedJwk::Okp {
            crv: required(&fields.crv)?,
            x: required(&fields.x)?,
            fields,
        }),
        "AKP" => Ok(ValidatedJwk::Akp {
            alg: required(&fields.alg)?,
            public_key: required(&fields.public_key)?,
            fields,
        }),
        _ => Err(JwtError::PROVIDER_UNSUPPORTED_ALGORITHM),
    }
}

struct Fields(PublicJwkJsonFields);
impl<'de> Deserialize<'de> for Fields {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_map(JwkVisitor { expected: None })
            .map(Self)
    }
}
struct Keys(PublicJwksJsonFields);
impl<'de> Deserialize<'de> for Keys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KeyVisitor;
        impl<'de> Visitor<'de> for KeyVisitor {
            type Value = PublicJwksJsonFields;
            reject_scalar_values!();
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an array of public JWKs")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut fields = PublicJwksJsonFields::default();
                while let Some(Fields(value)) = sequence.next_element::<Fields>()? {
                    fields.keys.push(value);
                }
                Ok(fields)
            }
        }
        deserializer.deserialize_any(KeyVisitor).map(Self)
    }
}
impl<'de> Deserialize<'de> for Jwks {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SetVisitor;
        impl<'de> Visitor<'de> for SetVisitor {
            type Value = PublicJwksJsonFields;
            reject_scalar_values!();
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a public JWKS object")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut set = None;
                while let Some(Text(name)) = map.next_key::<Text>()? {
                    if name.as_str() == "keys" {
                        if set.is_some() {
                            return Err(M::Error::custom(JwtError::PRIMITIVE_MALFORMED_JSON));
                        }
                        set = Some(map.next_value::<Keys>()?.0);
                    } else {
                        let _value = map.next_value::<buffa_types::sensitive::Value>()?;
                    }
                }
                set.ok_or_else(|| M::Error::custom(JwtError::PRIMITIVE_MALFORMED_JSON))
            }
        }
        let fields = deserializer.deserialize_any(SetVisitor)?;
        let validated = fields
            .keys
            .iter()
            .map(project)
            .collect::<Result<Vec<_>, _>>()
            .map_err(D::Error::custom)?;
        Ok(Jwks {
            keys: validated
                .into_iter()
                .map(ValidatedJwk::into_native)
                .collect(),
        })
    }
}

impl<'de> Deserialize<'de> for Jwk {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let fields = deserializer.deserialize_any(JwkVisitor { expected: None })?;
        project(&fields)
            .map(ValidatedJwk::into_native)
            .map_err(D::Error::custom)
    }
}
impl<'de> Deserialize<'de> for EcJwk {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let fields = deserializer.deserialize_any(JwkVisitor {
            expected: Some("EC"),
        })?;
        match project(&fields).map_err(D::Error::custom)?.into_native() {
            Jwk::Ec(value) => Ok(value),
            _ => Err(D::Error::custom(JwtError::PRIMITIVE_INVALID_PARAMETER)),
        }
    }
}
impl<'de> Deserialize<'de> for OkpJwk {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let fields = deserializer.deserialize_any(JwkVisitor {
            expected: Some("OKP"),
        })?;
        match project(&fields).map_err(D::Error::custom)?.into_native() {
            Jwk::Okp(value) => Ok(value),
            _ => Err(D::Error::custom(JwtError::PRIMITIVE_INVALID_PARAMETER)),
        }
    }
}
impl<'de> Deserialize<'de> for AkpJwk {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let fields = deserializer.deserialize_any(JwkVisitor {
            expected: Some("AKP"),
        })?;
        match project(&fields).map_err(D::Error::custom)?.into_native() {
            Jwk::Akp(value) => Ok(value),
            _ => Err(D::Error::custom(JwtError::PRIMITIVE_INVALID_PARAMETER)),
        }
    }
}
