// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fail-closed JWK deserialization with explicit key-type dispatch.

use std::{collections::BTreeMap, fmt};

use serde::{
    de::{Error as SerdeError, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::Value;

use super::{AkpJwk, EcJwk, Jwk, OkpJwk};
use crate::JwtError;

const MAX_JWK_MEMBER_COUNT: usize = 16;

// Option treats an explicit null as absence. Public-only parsing must reject
// the member name regardless of its value, including through concrete JWK types.
#[derive(Default)]
struct PrivateMemberPresence(bool);

impl<'de> Deserialize<'de> for PrivateMemberPresence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        serde::de::IgnoredAny::deserialize(deserializer)?;
        Ok(Self(true))
    }
}

fn is_private_member(name: &str) -> bool {
    matches!(
        name,
        "d" | "p" | "q" | "dp" | "dq" | "qi" | "oth" | "k" | "priv" | "privateKey" | "secretKey"
    )
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct PrivateJwkMembers {
    d: PrivateMemberPresence,
    p: PrivateMemberPresence,
    q: PrivateMemberPresence,
    dp: PrivateMemberPresence,
    dq: PrivateMemberPresence,
    qi: PrivateMemberPresence,
    oth: PrivateMemberPresence,
    k: PrivateMemberPresence,
    r#priv: PrivateMemberPresence,
    #[serde(rename = "privateKey")]
    private_key: PrivateMemberPresence,
    #[serde(rename = "secretKey")]
    secret_key: PrivateMemberPresence,
}

impl PrivateJwkMembers {
    fn is_present(&self) -> bool {
        self.d.0
            || self.p.0
            || self.q.0
            || self.dp.0
            || self.dq.0
            || self.qi.0
            || self.oth.0
            || self.k.0
            || self.r#priv.0
            || self.private_key.0
            || self.secret_key.0
    }
}

#[derive(Deserialize)]
struct EcJwkWire {
    kty: String,
    crv: String,
    x: String,
    y: String,
    alg: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    kid: Option<String>,
    #[serde(flatten)]
    private: PrivateJwkMembers,
    #[serde(flatten)]
    extra: BTreeMap<String, serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
struct OkpJwkWire {
    kty: String,
    crv: String,
    x: String,
    alg: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    kid: Option<String>,
    #[serde(flatten)]
    private: PrivateJwkMembers,
    #[serde(flatten)]
    extra: BTreeMap<String, serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
struct AkpJwkWire {
    kty: String,
    alg: String,
    #[serde(rename = "pub")]
    public_key: String,
    #[serde(rename = "use")]
    use_: Option<String>,
    kid: Option<String>,
    #[serde(flatten)]
    private: PrivateJwkMembers,
    #[serde(flatten)]
    extra: BTreeMap<String, serde::de::IgnoredAny>,
}

struct JwkVisitor;

impl<'de> Visitor<'de> for JwkVisitor {
    type Value = Jwk;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a public JWK object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut members = serde_json::Map::new();
        let mut member_count = 0_usize;
        while let Some(name) = map.next_key::<String>()? {
            member_count = member_count
                .checked_add(1)
                .ok_or_else(|| M::Error::custom(JwtError::InvalidEnvelope))?;
            if member_count > MAX_JWK_MEMBER_COUNT {
                return Err(M::Error::custom(JwtError::InvalidEnvelope));
            }
            // Reject before reading the value: private-key JSON must not be
            // materialized as an unzeroized serde_json::Value merely to discard it.
            if is_private_member(&name) {
                return Err(M::Error::custom(JwtError::PrivateKeyMaterial));
            }
            if members.contains_key(&name) {
                return Err(M::Error::custom(JwtError::DuplicateMember));
            }
            let value = map.next_value::<Value>()?;
            members.insert(name, value);
        }

        deserialize_by_key_type(Value::Object(members)).map_err(M::Error::custom)
    }
}

fn deserialize_by_key_type(value: Value) -> Result<Jwk, JwtError> {
    let key_type = value
        .get("kty")
        .and_then(Value::as_str)
        .ok_or(JwtError::InvalidEnvelope)?;
    match key_type {
        "EC" => serde_json::from_value(value)
            .map(Jwk::Ec)
            .map_err(|_| JwtError::InvalidEnvelope),
        "OKP" => serde_json::from_value(value)
            .map(Jwk::Okp)
            .map_err(|_| JwtError::InvalidEnvelope),
        "AKP" => serde_json::from_value(value)
            .map(Jwk::Akp)
            .map_err(|_| JwtError::InvalidEnvelope),
        _ => Err(JwtError::UnsupportedKeyFormat),
    }
}

impl<'de> Deserialize<'de> for Jwk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(JwkVisitor)
    }
}

impl<'de> Deserialize<'de> for EcJwk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = EcJwkWire::deserialize(deserializer)?;
        validate_wire_members(&wire.kty, "EC", &wire.private, &wire.extra)
            .map_err(D::Error::custom)?;
        Ok(Self {
            kty: wire.kty,
            crv: wire.crv,
            x: wire.x,
            y: wire.y,
            alg: wire.alg,
            use_: wire.use_,
            kid: wire.kid,
        })
    }
}

impl<'de> Deserialize<'de> for OkpJwk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = OkpJwkWire::deserialize(deserializer)?;
        validate_wire_members(&wire.kty, "OKP", &wire.private, &wire.extra)
            .map_err(D::Error::custom)?;
        Ok(Self {
            kty: wire.kty,
            crv: wire.crv,
            x: wire.x,
            alg: wire.alg,
            use_: wire.use_,
            kid: wire.kid,
        })
    }
}

impl<'de> Deserialize<'de> for AkpJwk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AkpJwkWire::deserialize(deserializer)?;
        validate_wire_members(&wire.kty, "AKP", &wire.private, &wire.extra)
            .map_err(D::Error::custom)?;
        Ok(Self {
            kty: wire.kty,
            alg: wire.alg,
            public_key: wire.public_key,
            use_: wire.use_,
            kid: wire.kid,
        })
    }
}

fn validate_wire_members(
    actual_key_type: &str,
    expected_key_type: &str,
    private: &PrivateJwkMembers,
    extra: &BTreeMap<String, serde::de::IgnoredAny>,
) -> Result<(), JwtError> {
    if private.is_present() {
        return Err(JwtError::PrivateKeyMaterial);
    }
    if extra.keys().any(|name| !name.starts_with("x-")) {
        return Err(JwtError::UnknownMember);
    }
    if actual_key_type != expected_key_type {
        return Err(JwtError::UnsupportedKeyFormat);
    }
    Ok(())
}
