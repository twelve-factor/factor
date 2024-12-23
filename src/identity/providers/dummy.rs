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
use crate::identity::{IdentityProvider, ProviderConfig};
use anyhow::Result;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

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
    pub fn new(config: Config) -> Result<Self> {
        Ok(Self { config })
    }
}

#[async_trait]
impl IdentityProvider for Provider {
    async fn get_iss_and_jwks(&self) -> Result<Option<(String, String)>> {
        // No jwks management
        Ok(None)
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
}