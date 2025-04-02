use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, prelude::*};
use biscuit::jwk::{AlgorithmParameters, CommonParameters, JWKSet, RSAKeyParameters, JWK};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rand::{rngs::StdRng, SeedableRng};
use rsa::{
    pkcs1::EncodeRsaPrivateKey, pkcs8::LineEnding, traits::PublicKeyParts, RsaPrivateKey,
    RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    dirs,
    identity::{IdentityProvider, ProviderConfig},
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
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
fn generate_rsa_key_from_secret(secret: &str) -> Result<RsaPrivateKey> {
    let decoded_secret = BASE64_STANDARD.decode(secret)?;

    let mut hasher = Sha256::new();
    hasher.update(decoded_secret);
    let seed = hasher.finalize();

    let mut rng = StdRng::from_seed(seed.into());

    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;

    Ok(private_key)
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
    pub fn new(config: Config) -> Result<Self> {
        let private_key = generate_rsa_key_from_secret(&config.secret)
            .map_err(|e| anyhow!("Invalid secret: {}", e))?;
        let private_key_pem = private_key.to_pkcs1_pem(LineEnding::CR)?.to_string();
        let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())?;
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
    iat: u64,
    exp: u64,
}

#[async_trait]
impl IdentityProvider for Provider {
    async fn get_iss(&self) -> Result<String> {
        dirs::get_stored_url()
    }
    async fn get_jwks(&self) -> Result<Option<String>> {
        let json = serde_json::to_string_pretty(&self.jwks)?;
        Ok(Some(json))
    }

    async fn configure_app_identity(&self, name: &str) -> Result<ProviderConfig> {
        let mut config = self.config.clone();
        // subject is just the name of the app for local
        config.sub = Some(name.to_string());
        Ok(ProviderConfig::local(config))
    }

    async fn ensure_audience(&self, _audience: &str) -> Result<()> {
        // No audience management needed for local JWT generation
        Ok(())
    }

    async fn get_token(&self, audience: &str) -> Result<String> {
        let sub = self.config.sub.as_ref().context("Sub not configured")?;

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let claims = Claims {
            iss: self.get_iss().await?,
            sub: sub.to_string(),
            aud: audience.to_string(),
            iat: now,
            exp: now + 1800, // Expiration time (30 minutes from now)
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());

        let token = encode(&header, &claims, &self.key)?;

        Ok(token)
    }

    async fn get_sub(&self) -> Result<String> {
        self.config
            .sub
            .clone()
            .ok_or_else(|| anyhow!("Subject not configured"))
    }
}
