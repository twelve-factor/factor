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
use async_trait::async_trait;
use factor_error::{prelude::*, ConfigSource};
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
    pub fn new(config: Config) -> FactorResult<Self> {
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
    pub async fn get_client(&self) -> FactorResult<&Client> {
        self.client
            .get_or_try_init(|| async {
                Ok(if let Some(path) = &self.config.kubeconfig_path {
                    // Load kubeconfig and convert to client config
                    let kube_config =
                        kube::config::Kubeconfig::read_from(path).context(KubeConfigSnafu)?;
                    let client_config = kube::config::Config::from_custom_kubeconfig(
                        kube_config,
                        &KubeConfigOptions::default(),
                    )
                    .await
                    .context(KubeConfigSnafu)?;
                    Client::try_from(client_config).context(KubeClientSnafu)?
                } else {
                    // Use the default client loading
                    Client::try_default().await.context(KubeClientSnafu)?
                })
            })
            .await
    }
}

#[async_trait]
impl IdentityProvider for Provider {
    async fn get_iss_and_jwks(&self) -> FactorResult<Option<(String, String)>> {
        // No jwks management
        Ok(None)
    }

    async fn configure_app_identity(&self, name: &str) -> FactorResult<ProviderConfig> {
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
            .context(KubeClientSnafu)?;

        trace!("Created service account: {}", sa_name);

        // Create new config with service account name
        let mut config = self.config.clone();
        config.service_account_name = Some(sa_name);

        Ok(ProviderConfig::k8s(config))
    }

    async fn get_token(&self, audience: &str) -> FactorResult<String> {
        let client = self.get_client().await?;
        let sa_name =
            self.config
                .service_account_name
                .as_ref()
                .with_context(|| MissingConfigSnafu {
                    config: ConfigSource::provider("k8s"),
                    at: ("service_account_name", "k8s"),
                })?;

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
            .context(KubeClientSnafu)?;

        let token = token_response
            .status
            .with_context(|| KubeClientProtocolSnafu {
                message: "Token response status was empty",
            })?
            .token;

        Ok(token)
    }
}
