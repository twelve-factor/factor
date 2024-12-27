/*
 * Copyright 2024 The Twelve-Factor Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, prelude::*};
use biscuit::jwk::{AlgorithmParameters, CommonParameters, JWKSet, RSAKeyParameters, JWK};
use factor_error::{prelude::*, ConfigSource, FactorResult};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::{rngs::StdRng, SeedableRng};
use rsa::{
    pkcs1::EncodeRsaPrivateKey, pkcs8::LineEnding, traits::PublicKeyParts, RsaPrivateKey,
    RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    env,
    identity::{IdentityProvider, ProviderConfig},
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub iss: String,
    pub secret: String,
    pub sub: Option<String>,
}

#[derive(Clone)]
pub struct Provider {
    config: Config,
    key: EncodingKey,
    kid: String,
    jwks: JWKSet<CommonParameters>,
}

/// # Errors
///
/// If `secret` is not valid base64, returns a [`base64::DecodeError`]
///
/// There are two additional low-level errors that can occur, but they are
/// extremely unlikely to occur with a 2048-bit key:
///
/// - Cannot find suitable prime numbers
/// - Generated key doesn't meet cryptographic requirements
///
/// TODO: Unwrap these error cases
fn generate_rsa_key_from_secret(secret: &str) -> FactorResult<RsaPrivateKey> {
    let decoded_secret = BASE64_STANDARD.decode(secret).context(Base64Snafu)?;

    let mut hasher = Sha256::new();
    hasher.update(decoded_secret);
    let seed = hasher.finalize();

    let mut rng = StdRng::from_seed(seed.into());

    Ok(RsaPrivateKey::new(&mut rng, 2048).context(RsaSnafu)?)
}

/// Generate a JWKS from a public key
fn generate_jwks(public_key: &RsaPublicKey, kid: &str) -> JWKSet<CommonParameters> {
    let jwk = public_key_to_jwk(public_key, kid);
    JWKSet { keys: vec![jwk] }
}

fn public_key_to_jwk(public_key: &RsaPublicKey, kid: &str) -> JWK<CommonParameters> {
    let n = num_bigint::BigUint::from_bytes_be(&public_key.n().to_bytes_be());
    let e = num_bigint::BigUint::from_bytes_be(&public_key.e().to_bytes_be());

    JWK {
        common: CommonParameters {
            public_key_use: Some(biscuit::jwk::PublicKeyUse::Signature),
            algorithm: Some(biscuit::jwa::Algorithm::Signature(
                biscuit::jwa::SignatureAlgorithm::RS256,
            )),
            key_id: Some(kid.to_string()),
            ..Default::default()
        },
        algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
            n,
            e,
            ..Default::default()
        }),
        additional: CommonParameters::default(),
    }
}

fn generate_kid(public_key: &RsaPublicKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key.n().to_bytes_be());
    hasher.update(public_key.e().to_bytes_be());
    let hash = hasher.finalize();
    URL_SAFE_NO_PAD.encode(hash)
}

impl Provider {
    /// # Errors
    ///
    /// Common errors:
    /// - `config.secret` is not valid base64
    ///
    /// Rare errors:
    /// - RSA key generation fails (see `generate_rsa_key_from_secret`)
    /// - The generated key cannot be encoded in PKCS#1 PEM format (extremely unlikely,
    ///   would indicate internal key corruption)
    /// - The PEM-encoded key cannot be converted to JWT format
    pub fn new(config: Config) -> FactorResult<Self> {
        let private_key = generate_rsa_key_from_secret(&config.secret)?;
        let private_key_pem = private_key
            .to_pkcs1_pem(LineEnding::CR)
            .context(CryptoSnafu)?
            .to_string();
        let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).context(JwtSnafu)?;
        let public_key = private_key.to_public_key();
        let kid = generate_kid(&public_key);
        let jwks = generate_jwks(&public_key, &kid);

        Ok(Self {
            config: Config { ..config },
            kid,
            jwks,
            key,
        })
    }
}

#[derive(Debug, Serialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
}

#[async_trait]
impl IdentityProvider for Provider {
    async fn get_iss_and_jwks(&self) -> FactorResult<Option<(String, String)>> {
        // if iss is still an env var, expand it now
        let iss = crate::env::expand(&self.config.iss)?;
        let json = serde_json::to_string_pretty(&self.jwks).context(JsonSnafu)?;
        Ok(Some((iss, json)))
    }

    async fn configure_app_identity(&self, name: &str) -> FactorResult<ProviderConfig> {
        let mut config = self.config.clone();
        // subject is just the name of the app for local
        config.sub = Some(name.to_string());
        Ok(ProviderConfig::local(config))
    }

    async fn get_token(&self, audience: &str) -> FactorResult<String> {
        let sub = self.config.sub.as_ref().context(MissingConfigSnafu {
            config: ConfigSource::provider("local"),
            at: "sub",
        })?;

        // if iss is still an env var, expand it now
        let iss = env::expand(&self.config.iss)?;

        let claims: Claims = Claims {
            iss,
            sub: sub.to_string(),
            aud: audience.to_string(),
            exp: (SystemTime::now() + std::time::Duration::from_secs(1800)) // Expiration time (30 minutes from now)
                .duration_since(UNIX_EPOCH)
                .expect("SystemTime before UNIX EPOCH is impossible")
                .as_secs(),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());

        let token = encode(&header, &claims, &self.key).context(JwtSnafu)?;

        Ok(token)
    }
}
