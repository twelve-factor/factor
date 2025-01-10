use anyhow::{Context, Result};
use async_trait::async_trait;
use http::uri::Uri;
use k8s_openapi::api::{
    authentication::v1::{TokenRequest, TokenRequestSpec},
    core::v1::ServiceAccount,
};
use kube::{
    api::{Api, PostParams},
    config::KubeConfigOptions,
    Client,
};
use log::trace;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use tokio::sync::OnceCell;

use crate::identity::{IdentityProvider, ProviderConfig};

#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub cluster_url: Option<Uri>,
    pub namespace: Option<String>,
    pub service_account_name: Option<String>,
    pub kubeconfig_path: Option<String>,
}

#[derive(Clone)]
pub struct Provider {
    config: Config,
    client: OnceCell<Client>,
}

impl Provider {
    /// # Errors
    ///
    /// The k8s provider is infallible, but `Provider::new` returns a Result for
    /// compatibility with the `identity_providers!` macro
    pub fn new(config: Config) -> Result<Self> {
        Ok(Self {
            config,
            client: OnceCell::new(),
        })
    }

    /// # Errors
    ///
    /// This method returns an [`anyhow::Error`] if:
    ///
    /// - Configuration error in `self.config.kubeconfig_path`:
    ///     - the config file does not exist
    ///     - the config file is not valid YAML
    ///     - the config file is missing a context
    ///     - see [`kube::config::Kubeconfig::read_from`]
    ///     - see [`kube::config::Config::from_custom_kubeconfig`]
    ///
    /// - Client creation error:
    ///     - TLS is required but not enabled
    ///     - Invalid TLS configuration (certificates, etc.)
    ///     - Invalid authentication configuration
    ///     - Invalid proxy configuration
    ///
    /// - See [`kube::Client::try_default`]
    pub async fn get_client(&self) -> Result<&Client> {
        self.client
            .get_or_try_init(|| async {
                Ok(if let Some(path) = &self.config.kubeconfig_path {
                    // Load kubeconfig and convert to client config
                    let kube_config = kube::config::Kubeconfig::read_from(path)
                        .context("Failed to read kubeconfig from path")?;
                    let client_config = kube::config::Config::from_custom_kubeconfig(
                        kube_config,
                        &KubeConfigOptions::default(),
                    )
                    .await
                    .context("Failed to create config from kubeconfig")?;
                    Client::try_from(client_config)
                        .context("Failed to create client from config")?
                } else {
                    // Use the default client loading
                    Client::try_default()
                        .await
                        .context("Failed to create default Kubernetes client")?
                })
            })
            .await
    }
}

#[async_trait]
impl IdentityProvider for Provider {
    async fn get_iss_and_jwks(&self) -> Result<Option<(String, String)>> {
        // No jwks management
        Ok(None)
    }

    async fn configure_app_identity(&self, name: &str) -> Result<ProviderConfig> {
        let client = self.get_client().await?;
        let sa_name = format!("{name}-sa");

        // Create the service account object
        let sa = ServiceAccount {
            metadata: kube::api::ObjectMeta {
                name: Some(sa_name.clone()),
                ..Default::default()
            },
            ..Default::default()
        };

        let api: Api<ServiceAccount> = Api::default_namespaced(client.clone());

        // Create the service account
        api.create(&PostParams::default(), &sa)
            .await
            .context("Failed to create service account")?;

        trace!("Created service account: {}", sa_name);

        // Create new config with service account name
        let mut config = self.config.clone();
        config.service_account_name = Some(sa_name);

        Ok(ProviderConfig::k8s(config))
    }

    async fn ensure_audience(&self, _audience: &str) -> Result<()> {
        // audience in k8s can be specified on token creation
        Ok(())
    }

    async fn get_token(&self, audience: &str) -> Result<String> {
        let client = self.get_client().await?;
        let sa_name = self
            .config
            .service_account_name
            .as_ref()
            .context("Service account name not configured")?;

        let api: Api<ServiceAccount> = Api::default_namespaced(client.clone());

        // Create a TokenRequest object
        let token_request = TokenRequest {
            spec: TokenRequestSpec {
                audiences: vec![audience.to_string()],
                expiration_seconds: Some(1800), // 30 minutes in seconds
                ..Default::default()
            },
            ..Default::default()
        };

        // Request a token for the service account
        let token_response = api
            .create_token_request(sa_name, &PostParams::default(), &token_request)
            .await
            .context("Failed to create token request")?;

        token_response
            .status
            .ok_or_else(|| anyhow::Error::msg("Token response status was empty"))
            .map(|status| status.token)
            .context("Failed to extract token from response")
    }

    async fn get_sub(&self) -> Result<String> {
        let sa_name = self
            .config
            .service_account_name
            .as_ref()
            .context("Service account name not configured")?;
        let namespace = self
            .config
            .namespace
            .as_ref()
            .context("Namespace not configured")?;
        Ok(format!("system:serviceaccount:{namespace}:{sa_name}"))
    }
}
