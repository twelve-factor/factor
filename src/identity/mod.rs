mod providers;

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use log::{error, info, trace, warn};
pub use providers::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::{fs::File, io::AsyncWriteExt, sync::watch, time::interval};

use super::{dirs, env, server::Service};

const ISSUER_FILENAME: &str = "issuer";

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
            #[must_use] pub fn variants() -> &'static [&'static str] {
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

        /// # Errors
        ///
        /// This method returns the same errors as [`providers::$variant::Provider::new`]
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
    async fn get_sub(&self) -> Result<String>;
    async fn get_token(&self, audience: &str) -> Result<String>;
    async fn get_iss(&self) -> Result<String>;
    async fn get_jwks(&self) -> Result<Option<String>> {
        Ok(None)
    }
}

pub struct IdentitySyncService {
    pub key: String,
    path: PathBuf,
    audience: String,
    provider: Arc<dyn IdentityProvider + Send + Sync>,
    issuer_path: PathBuf,
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
        let issuer_path = dirs::get_data_dir()?.join(ISSUER_FILENAME);

        // make sure that we empty any existing old identity
        env::set_var_file(&key, "", &path)?;
        let service = IdentitySyncService {
            key: key.clone(),
            path,
            audience: audience.to_string(),
            provider,
            issuer_path,
        };
        Ok(service)
    }

    async fn write_issuer(&self) -> Result<()> {
        let issuer = self.provider.get_iss().await?;
        let mut file = File::create(&self.issuer_path).await?;
        file.write_all(issuer.as_bytes()).await?;
        Ok(())
    }
}

#[async_trait]
impl Service for IdentitySyncService {
    async fn start(&mut self, mut shutdown: watch::Receiver<bool>) {
        // Write issuer at startup
        if let Err(e) = self.write_issuer().await {
            warn!("Failed to write issuer: {}", e);
        }

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
                    // Clean up issuer file on shutdown
                    if let Err(e) = std::fs::remove_file(&self.issuer_path) {
                        warn!("Failed to remove issuer file: {}", e);
                    }
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

/// Get the stored issuer from the data directory
///
/// # Errors
///
/// Returns an error if:
/// - Cannot access data directory
/// - Issuer file doesn't exist or can't be read
pub fn get_stored_issuer() -> Result<String> {
    let issuer_path = dirs::get_data_dir()?.join(ISSUER_FILENAME);
    std::fs::read_to_string(&issuer_path).map_err(|e| anyhow!("Failed to read issuer file: {}", e))
}
