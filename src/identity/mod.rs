mod providers;

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use log::{error, info, trace, warn};
pub use providers::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::{sync::watch, time::interval};

use super::{dirs, server::Service};

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

#[derive(Debug, Serialize)]
struct TokenCredentials {
    #[serde(rename = "type")]
    cred_type: String,
    data: TokenData,
}

#[derive(Debug, Serialize)]
struct TokenData {
    token: String,
}

impl TokenCredentials {
    fn new(token_path: impl AsRef<std::path::Path>) -> Self {
        Self {
            cred_type: "oidc".to_string(),
            data: TokenData {
                token: format!("file://{}", token_path.as_ref().display()),
            },
        }
    }
}

/// Write a value to a file idempotently using a temporary file
///
/// # Errors
///
/// Returns an error if:
/// - The parent directory doesn't exist
/// - Cannot create a temporary file
/// - Cannot write to the temporary file
/// - Cannot rename the temporary file
fn write_file_idempotent(path: impl AsRef<std::path::Path>, contents: &str) -> Result<()> {
    let path = path.as_ref();

    // Ensure parent directory exists and get canonical path
    let canonicalized_parent = path
        .parent()
        .ok_or_else(|| anyhow!("Path has no parent directory"))?
        .canonicalize()
        .map_err(|e| anyhow!("Failed to get canonical parent path: {}", e))?;

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("Path has no filename"))?;

    let canonical_path = canonicalized_parent.join(file_name);

    // Create temporary file in same directory
    let temp_file = tempfile::NamedTempFile::new_in(&canonicalized_parent)
        .map_err(|e| anyhow!("Failed to create temporary file: {}", e))?;

    // Write contents to temporary file
    std::fs::write(temp_file.path(), contents)
        .map_err(|e| anyhow!("Failed to write to temporary file: {}", e))?;

    // Atomically rename temporary file to target
    temp_file
        .persist(&canonical_path)
        .map_err(|e| anyhow!("Failed to rename temporary file: {}", e))?;

    Ok(())
}

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
    ///     - cannot create or write to temporary files
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
        let key = format!("{}_{}", target_id_safe, "CREDS");
        let filename = format!("{target_id}.token");
        let path = PathBuf::from(path).join(filename);

        // Write initial empty token file
        write_file_idempotent(&path, "")?;

        // Set credentials environment variable
        let creds = TokenCredentials::new(&path);
        std::env::set_var(&key, serde_json::to_string(&creds)?);

        let service = IdentitySyncService {
            key: key.clone(),
            path,
            audience: audience.to_string(),
            provider,
        };
        Ok(service)
    }

    async fn write_issuer(&self) -> Result<()> {
        let issuer = self.provider.get_iss().await?;
        dirs::write_iss(issuer).await
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
                    if let Err(e) = dirs::delete_iss().await {
                        error!("Failed to delete issuer file: {}", e);
                    }
                    break;
                }
                _ = period.tick() => {
                    match self.provider.get_token(&self.audience).await {
                        Ok(token) => {
                            match write_file_idempotent(&self.path, &token) {
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
