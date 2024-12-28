use std::sync::Arc;

use async_trait::async_trait;
use factor_error::{sources::ConfigLocation, FactorResult};
use serde::{Deserialize, Serialize};
use strum::Display;

pub trait ProviderDebug: IdentityProvider {
    fn get_config_location(&self) -> ConfigLocation;
}

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

        preinterpret::preinterpret! {
            #[derive(Debug, Clone, Deserialize, Serialize)]
            #[serde(tag = "provider", rename_all = "lowercase")]
            #[allow(non_camel_case_types)]
            pub enum ProviderConfig {
                $(
                    #[serde(rename_all = "lowercase")]
                    [!ident_camel! $variant](crate::providers::$variant::[!ident_camel! $variant Config]),
                )*
            }

            impl ProviderConfig {
                $(
                    pub fn $variant(config: &(impl std::ops::Deref<Target = crate::providers::$variant::[!ident_camel! $variant Config]> + Clone)) -> ProviderConfig {
                        ProviderConfig::[!ident_camel! $variant](config.deref().clone())
                    }
                )*
            }

            /// # Errors
            ///
            /// This method returns the same errors as [`providers::$variant::Provider::new`]
            pub fn create_provider(config: &ProviderConfig, location: impl Into<ConfigLocation>) -> FactorResult<Arc<dyn IdentityProvider>> {
                match config {
                    $(
                        ProviderConfig::[!ident_camel! $variant](config) => {
                            let config: crate::Config<crate::providers::$variant::[!ident_camel! $variant Config]> = crate::Config::new(config.clone(), location.into());
                            let provider = crate::providers::$variant::Provider::new(config)?;
                            Ok(Arc::new(provider))
                        },
                    )*
                }
            }
        }
    }
}

identity_providers!(dummy, auth0, k8s, local);
