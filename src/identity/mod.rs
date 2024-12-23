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
mod providers;

use super::env;
use super::server::Service;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use regex::Regex;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::interval;

pub use providers::*;

use serde::{Deserialize, Serialize};

macro_rules! identity_providers {
    ($($variant:ident),*) => {
        #[derive(Debug, Deserialize, Serialize, Clone, PartialEq, strum_macros::Display)]
        #[strum(serialize_all = "lowercase")]
        #[serde(rename_all = "lowercase")]
        #[allow(non_camel_case_types)]
        pub enum IdProvider {
            $($variant),*
        }

        impl IdProvider {
            pub fn variants() -> &'static [&'static str] {
                &[$(stringify!($variant)),*]
            }
        }

        #[derive(Debug, Clone, Deserialize, Serialize)]
        #[serde(tag = "provider", rename_all = "lowercase")]
        #[allow(non_camel_case_types)]
        pub enum ProviderConfig {
            $(
                #[serde(rename_all = "lowercase")]
                $variant(providers::$variant::Config),
            )*
        }

        pub fn create_provider(config: &ProviderConfig) -> Result<Arc<dyn IdentityProvider>> {
            match config {
                $(
                    ProviderConfig::$variant(config) => {
                        let provider = providers::$variant::Provider::new(config.clone())?;
                        Ok(Arc::new(provider))
                    },
                )*
            }
        }
    }
}

identity_providers!(dummy, auth0, k8s, local);

#[async_trait]
pub trait IdentityProvider: Send + Sync {
    async fn configure_app_identity(&self, name: &str) -> Result<ProviderConfig>;
    async fn ensure_audience(&self, audience: &str) -> Result<()>;
    async fn get_token(&self, audience: &str) -> Result<String>;
    async fn get_iss_and_jwks(&self) -> Result<Option<(String, String)>>;
}

pub struct IdentitySyncService {
    pub key: String,
    path: PathBuf,
    audience: String,
    provider: Arc<dyn IdentityProvider + Send + Sync>,
}

impl IdentitySyncService {
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
            path: path,
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
            println!(
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
                                Ok(_) => {
                                    println!("Successfully wrote token for audience {} to file", self.audience);
                                    match get_claims(&token) {
                                        Ok(claims) => {
                                            match serde_json::to_string_pretty(&claims) {
                                                Ok(json_output) => println!("{json_output}"),
                                                Err(e) => eprintln!("Failed to convert to JSON: {e}"),
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("Failed to get claims for token: {e}");
                                            println!("Token prefix: {}", &token[..6]);
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Failed to write token to file for audience {}: {}", self.audience, e);
                                }
                            }
                        }
                        Err(e) => eprintln!("Failed to get token for audience {}: {}", self.audience, e),
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

pub fn get_claims(jwt: &str) -> Result<Claims> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid JWT token format"));
    }

    let payload = URL_SAFE_NO_PAD.decode(parts[1])?;
    let claims: Claims = serde_json::from_slice(&payload)?;

    Ok(claims)
}
