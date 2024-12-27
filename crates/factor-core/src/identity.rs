use std::sync::Arc;

use async_trait::async_trait;
use factor_error::FactorResult;
use serde::{Deserialize, Serialize};
use strum::Display;

#[async_trait]
pub trait IdentityProvider: Send + Sync {
    async fn configure_app_identity(&self, name: &str) -> FactorResult<ProviderConfig>;
    async fn get_token(&self, audience: &str) -> FactorResult<String>;

    async fn get_iss_and_jwks(&self) -> FactorResult<Option<(String, String)>> {
        Ok(None)
    }

    async fn ensure_audience(&self, _audience: &str) -> FactorResult<()> {
        Ok(())
    }
}

macro_rules! identity_providers {
    ($($variant:ident),*) => {
        #[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Display)]
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
                $variant(crate::providers::$variant::Config),
            )*
        }

        /// # Errors
        ///
        /// This method returns the same errors as [`providers::$variant::Provider::new`]
        pub fn create_provider(config: &ProviderConfig) -> FactorResult<Arc<dyn IdentityProvider>> {
            match config {
                $(
                    ProviderConfig::$variant(config) => {
                        let provider = crate::providers::$variant::Provider::new(config.clone())?;
                        Ok(Arc::new(provider))
                    },
                )*
            }
        }
    }
}

identity_providers!(dummy, auth0, k8s, local);
