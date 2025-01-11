use std::sync::Arc;

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
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use tokio::sync::{OnceCell, RwLock};

use crate::identity::{IdentityProvider, ProviderConfig};

#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub default_namespace: Option<String>,
    pub service_account_name: Option<String>,
    pub kubeconfig_path: Option<String>,
}

#[derive(Clone)]
pub struct Provider {
    config: Config,
    issuer: Arc<RwLock<Option<String>>>,
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
            issuer: Arc::new(RwLock::new(None)),
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
    /// - The cluster URL cannot be inferred from the Kubernetes configuration.
    ///
    /// - See [`kube::Config::infer`]
    pub async fn get_cluster_url(&self) -> Result<Uri> {
        if let Some(path) = &self.config.kubeconfig_path {
            let kube_config = kube::config::Kubeconfig::read_from(path)
                .context("Failed to read kubeconfig from path")?;
            let client_config = kube::config::Config::from_custom_kubeconfig(
                kube_config,
                &KubeConfigOptions::default(),
            )
            .await
            .context("Failed to create config from kubeconfig")?;
            Ok(client_config.cluster_url)
        } else {
            let config = kube::Config::infer()
                .await
                .context("Failed to infer Kubernetes config")?;
            Ok(config.cluster_url)
        }
    }
}

#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    issuer: String,
    // Add other fields if needed
}

#[async_trait]
impl IdentityProvider for Provider {
    async fn get_iss(&self) -> Result<String> {
        if let Some(issuer) = &*self.issuer.read().await {
            return Ok(issuer.clone());
        }

        let cluster_url = self.get_cluster_url().await?;

        // Convert http::Uri to url::Url
        let cluster_url =
            Url::parse(&cluster_url.to_string()).context("Failed to parse cluster URL")?;

        let discovery_url = cluster_url.join(".well-known/openid-configuration")?;
        let response = reqwest::get(discovery_url).await?;
        let oidc_discovery: OidcDiscovery = response.json().await?;

        *self.issuer.write().await = Some(oidc_discovery.issuer.clone());

        // Return the issuer URL
        Ok(oidc_discovery.issuer)
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
        config.default_namespace = Some(client.default_namespace().to_string());
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
            .default_namespace
            .as_ref()
            .context("Namespace not configured")?;
        Ok(format!("system:serviceaccount:{namespace}:{sa_name}"))
    }
}
