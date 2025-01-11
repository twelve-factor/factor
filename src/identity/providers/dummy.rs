use anyhow::Result;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::identity::{IdentityProvider, ProviderConfig};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub app_name: Option<String>,
}

#[derive(Debug, Serialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
}

#[derive(Clone)]
pub struct Provider {
    config: Config,
}

impl Provider {
    /// # Errors
    ///
    /// The dummy provider is infallible, but `Provider::new` returns a Result for
    /// compatibility with the `identity_providers!` macro
    pub fn new(config: Config) -> Result<Self> {
        Ok(Self { config })
    }
}

#[async_trait]
impl IdentityProvider for Provider {
    async fn get_iss(&self) -> Result<String> {
        Ok("dummy-issuer".to_string())
    }
    async fn configure_app_identity(&self, name: &str) -> Result<ProviderConfig> {
        let mut config = self.config.clone();
        config.app_name = Some(name.to_string());
        Ok(ProviderConfig::dummy(config))
    }

    async fn ensure_audience(&self, _audience: &str) -> Result<()> {
        Ok(())
    }

    async fn get_token(&self, audience: &str) -> Result<String> {
        let now = Utc::now();
        let claims = Claims {
            iss: "dummy-issuer".to_string(),
            sub: self
                .config
                .app_name
                .clone()
                .unwrap_or("dummy-subject".to_string()),
            aud: audience.to_string(),
            iat: now.timestamp(),
            exp: (now + Duration::minutes(30)).timestamp(),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"dummy-secret"),
        )?;

        Ok(token)
    }

    async fn get_sub(&self) -> Result<String> {
        Ok(self
            .config
            .app_name
            .clone()
            .unwrap_or_else(|| "dummy-subject".to_string()))
    }
}
