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
use factor_error::prelude::*;
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::identity::{IdentityProvider, ProviderConfig};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Clone)]
pub struct Provider {
    config: Config,
    client: Client,
}

impl Provider {
    /// # Errors
    ///
    /// Returns `anyhow::Error` if:
    ///
    /// - `config.issuer` is not set
    /// - `config.client_id` is not set
    /// - `config.client_secret` is not set
    pub fn new(config: Config) -> FactorResult<Self> {
        ensure!(
            config.issuer.is_some(),
            GenericSnafu {
                message: "auth0 issuer must be configured"
            }
        );
        ensure!(
            config.client_id.is_some(),
            GenericSnafu {
                message: "auth0 client_id must be configured"
            }
        );
        ensure!(
            config.client_secret.is_some(),
            GenericSnafu {
                message: "auth0 client_secret must be configured"
            }
        );

        Ok(Self {
            config,
            client: Client::new(),
        })
    }

    async fn get_management_token(&self) -> FactorResult<String> {
        let issuer = self.config.issuer.as_ref().unwrap();
        let management_token_url = format!("{issuer}/oauth/token");

        let data = json!({
            "grant_type": "client_credentials",
            "client_id": self.config.client_id.as_ref().unwrap(),
            "client_secret": self.config.client_secret.as_ref().unwrap(),
            "audience": format!("{}/api/v2/", issuer),
        });

        let management_resp: Auth0Response = self
            .client
            .post(&management_token_url)
            .json(&data)
            .send()
            .await
            .context(ReqwestSnafu)?
            .error_for_status()
            .context(ReqwestSnafu)?
            .json()
            .await
            .context(ReqwestSnafu)?;

        Ok(management_resp.access_token)
    }
}

#[derive(Debug, Serialize)]
struct Auth0APIRequest {
    name: String,
    identifier: String,
    scopes: Vec<String>,
    token_dialect: Option<String>,
    token_lifetime: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct Auth0Response {
    access_token: String,
}

#[async_trait]
impl IdentityProvider for Provider {
    async fn configure_app_identity(&self, name: &str) -> FactorResult<ProviderConfig> {
        let issuer = self.config.issuer.as_ref().unwrap();
        let management_token = self.get_management_token().await?;

        let apps_url = format!("{issuer}/api/v2/clients");
        let app_data = json!({
            "name": name,
            "app_type": "non_interactive",
            "token_endpoint_auth_method": "client_secret_post",
        });

        let app_response: Value = self
            .client
            .post(&apps_url)
            .header(header::AUTHORIZATION, format!("Bearer {management_token}"))
            .json(&app_data)
            .send()
            .await
            .context(ReqwestSnafu)?
            .error_for_status()
            .context(ReqwestSnafu)?
            .json()
            .await
            .context(ReqwestSnafu)?;

        let client_id = app_response["client_id"].as_str().unwrap();
        let scopes = vec![
            "read:resource_servers",
            "create:resource_servers",
            "update:resource_servers",
            "delete:resource_servers",
            "read:client_grants",
            "create:client_grants",
            "update:client_grants",
            "delete:client_grants",
        ];

        let client_grants_url = format!("{issuer}/api/v2/client-grants");
        let management_grant_data = json!({
            "client_id": client_id,
            "audience": format!("{}/api/v2/", issuer),
            "scope": scopes.clone()
        });

        self.client
            .post(&client_grants_url)
            .header(header::AUTHORIZATION, format!("Bearer {management_token}"))
            .json(&management_grant_data)
            .send()
            .await
            .context(ReqwestSnafu)?
            .error_for_status()
            .context(ReqwestSnafu)?;

        // After creating the client grant, verify it exists with all scopes
        let grants: Vec<Value> = self
            .client
            .get(&client_grants_url)
            .header(header::AUTHORIZATION, format!("Bearer {management_token}"))
            .send()
            .await
            .context(ReqwestSnafu)?
            .error_for_status()
            .context(ReqwestSnafu)?
            .json()
            .await
            .context(ReqwestSnafu)?;

        // Check if our grant exists with all the required scopes
        let grant_exists = grants.iter().any(|grant| {
            if grant["client_id"].as_str().unwrap() != client_id
                || grant["audience"].as_str().unwrap() != format!("{issuer}/api/v2/")
            {
                return false;
            }

            let grant_scopes: Vec<String> = grant["scope"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect();

            scopes
                .iter()
                .all(|required_scope| grant_scopes.contains(&(*required_scope).to_string()))
        });

        ensure!(
            grant_exists,
            GenericSnafu {
                message: "Client grant was not successfully created with all required scopes - check management API permissions"
            }
        );

        let mut config = self.config.clone();
        config.client_id = Some(app_response["client_id"].as_str().unwrap().to_string());
        config.client_secret = Some(app_response["client_secret"].as_str().unwrap().to_string());

        Ok(ProviderConfig::auth0(config))
    }

    async fn ensure_audience(&self, audience: &str) -> FactorResult<()> {
        let issuer = self.config.issuer.as_ref().unwrap();

        let management_token = self.get_management_token().await?;

        let resource_servers_url = format!("{issuer}/api/v2/resource-servers");
        let resource_servers: Vec<Value> = self
            .client
            .get(&resource_servers_url)
            .header(header::AUTHORIZATION, format!("Bearer {management_token}"))
            .send()
            .await
            .context(ReqwestSnafu)?
            .error_for_status()
            .context(ReqwestSnafu)?
            .json()
            .await
            .context(ReqwestSnafu)?;

        if !resource_servers
            .iter()
            .any(|server| server["identifier"] == json!(audience))
        {
            let create_api_url = format!("{issuer}/api/v2/resource-servers");
            let api_data = Auth0APIRequest {
                name: audience.to_string(),
                identifier: audience.to_string(),
                scopes: vec![],
                token_dialect: Some("rfc9068_profile".to_string()),
                token_lifetime: Some(1800),
            };

            self.client
                .post(&create_api_url)
                .header(header::AUTHORIZATION, format!("Bearer {management_token}"))
                .json(&api_data)
                .send()
                .await
                .context(ReqwestSnafu)?
                .error_for_status()
                .context(ReqwestSnafu)?;
        }

        let client_grants_url = format!("{issuer}/api/v2/client-grants");
        let client_grants: Vec<Value> = self
            .client
            .get(&client_grants_url)
            .header(header::AUTHORIZATION, format!("Bearer {management_token}"))
            .send()
            .await
            .context(ReqwestSnafu)?
            .error_for_status()
            .context(ReqwestSnafu)?
            .json()
            .await
            .context(ReqwestSnafu)?;

        if !client_grants.iter().any(|grant| {
            grant["client_id"] == json!(self.config.client_id.as_ref().unwrap())
                && grant["audience"] == json!(audience)
        }) {
            let client_grant_data = json!({
                "client_id": self.config.client_id.as_ref().unwrap(),
                "audience": audience,
                "scope": Vec::<String>::new(),
            });

            self.client
                .post(&client_grants_url)
                .header(header::AUTHORIZATION, format!("Bearer {management_token}"))
                .json(&client_grant_data)
                .send()
                .await
                .context(ReqwestSnafu)?
                .error_for_status()
                .context(ReqwestSnafu)?;
        }

        Ok(())
    }

    async fn get_token(&self, audience: &str) -> FactorResult<String> {
        let issuer = self.config.issuer.as_ref().unwrap();
        let token_url = format!("{issuer}/oauth/token");

        let data = json!({
            "grant_type": "client_credentials",
            "client_id": self.config.client_id.as_ref().unwrap(),
            "client_secret": self.config.client_secret.as_ref().unwrap(),
            "audience": audience,
        });

        let auth_resp: Auth0Response = self
            .client
            .post(&token_url)
            .json(&data)
            .send()
            .await
            .context(ReqwestSnafu)?
            .error_for_status()
            .context(ReqwestSnafu)?
            .json()
            .await
            .context(ReqwestSnafu)?;

        Ok(auth_resp.access_token)
    }
}
