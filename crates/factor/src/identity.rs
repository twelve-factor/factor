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

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use factor_core::identity::IdentityProvider;
use log::{error, info, trace, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::{sync::watch, time::interval};

use super::{env, server::Service};

pub struct IdentitySyncService {
    pub key: String,
    path: PathBuf,
    audience: String,
    provider: Arc<dyn IdentityProvider + Send + Sync>,
}

impl IdentitySyncService {
    /// # Errors
    ///
    /// - Returns [`anyhow::Error`] if:
    ///     - `path` is the root or parent directory doesn't exist
    ///     - permission issues
    ///
    /// See [`env::set_var_file`] for more error conditions
    pub fn new(
        path: &str,
        target_id: &str,
        audience: &str,
        provider: Arc<dyn IdentityProvider + Send + Sync>,
    ) -> anyhow::Result<Self> {
        let safe_regex = Regex::new(r"[^a-zA-Z0-9_-]")?;
        let target_id_safe = safe_regex
            .replace_all(target_id, "_")
            .to_string()
            .to_uppercase();
        let key = format!("{}_{}", target_id_safe, "IDENTITY");
        let filename = format!("{target_id}.token");
        let path = PathBuf::from(path).join(filename);
        // make sure that we empty any existing old identity
        env::set_var_file(&key, "", &path)?;
        let service = IdentitySyncService {
            key: key.clone(),
            path,
            audience: audience.to_string(),
            provider,
        };
        // set up env vars
        Ok(service)
    }
}

#[async_trait]
impl Service for IdentitySyncService {
    async fn start(&mut self, mut shutdown: watch::Receiver<bool>) {
        if let Err(e) = self.provider.ensure_audience(&self.audience).await {
            warn!(
                "Failed to create or verify API for audience {}: {}",
                self.audience, e
            );
        }

        let mut period = interval(Duration::from_secs(15 * 60));
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    // shutdown
                    break;
                }
                _ = period.tick() => {
                    match self.provider.get_token(&self.audience).await {
                        Ok(token) => {
                            match env::set_var_file(&self.key, &token, &self.path) {
                                Ok(()) => {
                                    trace!("Successfully wrote token for audience {} to file", self.audience);
                                    match get_claims(&token) {
                                        Ok(claims) => {
                                            match serde_json::to_string_pretty(&claims) {
                                                Ok(json_output) => trace!("{json_output}"),
                                                Err(e) => error!("Failed to convert to JSON: {e}"),
                                            }
                                        }
                                        Err(e) => {
                                            error!("Failed to get claims for token: {e}");
                                            info!("Token prefix: {}", &token[..6]);
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to write token to file for audience {}: {}", self.audience, e);
                                }
                            }
                        }
                        Err(e) => error!("Failed to get token for audience {}: {}", self.audience, e),
                    }
                }
            }
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: serde_json::Value,
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

/// Parse the [`Claims`] from a JWT token:
///
/// The JWT token is expected to be Base64-encoded JSON in the following format:
///
/// ```json
/// {
///     "iss": "<issuer>",
///     "sub": "<subject>",
///     "aud": "<audience>",
///     "...": "arbitrary key-value pairs"
/// }
/// ```
///
/// The token **must**:
///
/// - contain the `iss`, `sub` and `aud` fields
/// - be a valid Base64-encoded JSON
/// - not contain padding
///
/// # Errors
///
/// Returns `anyhow::Error` if:
///
/// - The JWT token doesn't have 3 parts (separated by `.`)
/// - The JWT token contains characters that are not base64 (without padding)
/// - The JWT token payload cannot be decoded as [`Claims`]
pub fn get_claims(jwt: &str) -> Result<Claims> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid JWT token format"));
    }

    let payload = URL_SAFE_NO_PAD.decode(parts[1])?;
    let claims: Claims = serde_json::from_slice(&payload)?;

    Ok(claims)
}
