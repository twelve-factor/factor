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

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use biscuit::{jwk::JWKSet, Empty};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use log::{info, trace, warn};
use pingora::{server::configuration::ServerConf, services::listening::Service};
use pingora_core::{upstreams::peer::HttpPeer, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{HttpProxy, ProxyHttp, Session};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;

use super::identity;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IdentityValidator {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<String>,
}

pub type IncomingIdentity = HashMap<String, IdentityValidator>;

pub struct AuthProxy {
    reject_unknown: bool,
    ipv6: bool,
    port: u16,
    incoming_identity: IncomingIdentity,
    key_cache: Mutex<HashMap<String, DecodingKey>>,
    client: reqwest::Client,
    provider: Arc<dyn super::identity::IdentityProvider + Send + Sync>,
}

impl AuthProxy {
    async fn handle_well_known(
        &self,
        session: &mut Session,
        iss: String,
        jwks: String,
    ) -> anyhow::Result<()> {
        let path = session.req_header().uri.path();
        let resp_str = if path.starts_with("/.well-known/openid-configuration") {
            // Generate the OIDC discovery response
            let oidc_discovery_response = json!({
                "issuer": iss,
                "authorization_endpoint": "/dummy/authorization",
                "jwks_uri": format!{"{}/.well-known/jwks.json", iss},
                "response_types_supported": [
                "implicit"
                ],
                "grant_types_supported": [
                "implicit"
                ],
                "subject_types_supported": [
                "public"
                ],
                "id_token_signing_alg_values_supported": [
                "RS256"
                ]
            });

            serde_json::to_string_pretty(&oidc_discovery_response)?
        } else if path.starts_with("/.well-known/jwks.json") {
            jwks
        } else {
            session.respond_error(404).await?;
            return Ok(());
        };

        let mut resp = ResponseHeader::build(200, None)?;
        resp.append_header(http::header::CONTENT_LENGTH, resp_str.len())?;
        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(resp_str.into()), true)
            .await?;
        session.finish_body().await?;
        Ok(())
    }

    async fn validate_token(&self, req: &RequestHeader) -> anyhow::Result<Option<String>> {
        let auth_header = req.headers.get("Authorization");
        let Some(auth_header) = auth_header else {
            return Ok(None);
        };
        let parts: Vec<&str> = auth_header.to_str()?.split(' ').collect();
        if parts.len() != 2 || parts[0] != "Bearer" {
            return Ok(None);
        }
        let token = parts[1];
        let header = decode_header(token)?;
        let unvalidated_claims = identity::get_claims(token)?;

        // Check the cache for the key
        let kid = header
            .kid
            .ok_or(anyhow::anyhow!("Missing 'kid' in token header"))?;
        let mut cache = self.key_cache.lock().await;
        let decoding_key = if let Some(key) = cache.get(&kid) {
            key.clone()
        } else {
            // handle the case where the issuer includes a trailing slash
            let iss = unvalidated_claims.iss.trim_end_matches('/');
            let openid_config_url = format!("{iss}/.well-known/openid-configuration");
            let openid_config_response = self.client.get(&openid_config_url).send().await?;
            let openid_config: serde_json::Value = openid_config_response.json().await?;
            let jwks_uri = openid_config["jwks_uri"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("'jwks_uri' not found in OpenID Configuration"))?;
            let jwks_response = self.client.get(jwks_uri).send().await?;
            let jwks: JWKSet<Empty> = jwks_response.json().await?;
            let key = jwks
                .find(&kid)
                .ok_or_else(|| anyhow::anyhow!("Key not found for kid: {}", kid))?;
            let decoding_key =
                if let biscuit::jwk::AlgorithmParameters::RSA(ref rsa_params) = key.algorithm {
                    let n_bytes = rsa_params.n.to_bytes_be();
                    let e_bytes = rsa_params.e.to_bytes_be();
                    DecodingKey::from_rsa_raw_components(&n_bytes, &e_bytes)
                } else {
                    return Err(anyhow::anyhow!("Unsupported JWK algorithm"));
                };
            cache.insert(kid.clone(), decoding_key.clone());
            decoding_key
        };

        let mut validation = Validation::new(Algorithm::RS256);
        // audience is validated manually below
        validation.validate_aud = false;
        trace!("Decoding token {token}");
        let data = decode::<identity::Claims>(token, &decoding_key, &validation)?;

        for (key, val) in &self.incoming_identity {
            let iss_match = match &val.iss {
                Some(iss) => Regex::new(iss).unwrap().is_match(&data.claims.iss),
                None => true,
            };
            let sub_match = match &val.sub {
                Some(sub) => Regex::new(sub).unwrap().is_match(&data.claims.sub),
                None => true,
            };
            let aud_match = match &val.aud {
                Some(aud) => {
                    let aud_regex = Regex::new(aud).unwrap();
                    match &data.claims.aud {
                        serde_json::Value::String(aud_str) => aud_regex.is_match(aud_str),
                        serde_json::Value::Array(aud_array) => aud_array.iter().any(|aud_val| {
                            if let serde_json::Value::String(aud_str) = aud_val {
                                aud_regex.is_match(aud_str)
                            } else {
                                false
                            }
                        }),
                        _ => false,
                    }
                }
                None => true,
            };

            if iss_match && sub_match && aud_match {
                return Ok(Some(key.to_string()));
            }
        }
        Ok(None)
    }
}

const HOST: &str = "localhost";

#[async_trait]
impl ProxyHttp for AuthProxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        if session.req_header().uri.path().starts_with("/.well-known/") {
            if let Ok(Some((iss, jwks))) = self.provider.get_iss_and_jwks().await {
                if let Err(e) = self.handle_well_known(session, iss, jwks).await {
                    info!("Failed to handle well_known {e:?}");
                    let _ = session.respond_error(500).await;
                    return Ok(true);
                }
                return Ok(true); // Indicate that the request has been handled
            }
        }
        session.req_header_mut().remove_header("X-Factor-Client-Id");
        match self.validate_token(session.req_header()).await {
            Ok(Some(client_id)) => {
                session
                    .req_header_mut()
                    .append_header("X-Factor-Client-Id", client_id)?;
                return Ok(false);
            }
            Ok(None) => {
                trace!("No token included");
            }
            Err(e) => {
                warn!("Token validation failed {e:?}");
            }
        }
        if self.reject_unknown {
            let _ = session.respond_error(403).await;
            // true: early return as the response is already written
            return Ok(true);
        }
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // TODO: wrap pingora_load_balancer so we can put in both ipv4 and ipv6 upstreams?
        let addr = if self.ipv6 {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), self.port)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), self.port)
        };

        trace!("connecting to {addr:?}");

        let peer = Box::new(HttpPeer::new(addr, false, HOST.to_owned()));
        Ok(peer)
    }
}

pub fn get_proxy_service(
    port: u16,
    child_port: u16,
    incoming_identity: IncomingIdentity,
    reject_unknown: bool,
    ipv6: bool,
    provider: Arc<dyn identity::IdentityProvider + Send + Sync>,
) -> Service<HttpProxy<AuthProxy>> {
    let conf = Arc::new(ServerConf::default());
    let mut proxy = pingora_proxy::http_proxy_service(
        &conf,
        AuthProxy {
            reject_unknown,
            ipv6,
            port: child_port,
            incoming_identity,
            key_cache: Mutex::new(HashMap::new()),
            client: reqwest::Client::new(),
            provider,
        },
    );
    proxy.add_tcp(format!("[::]:{port}").as_str());
    proxy
}

#[async_trait]
impl<T: pingora_core::services::Service + Send + Sync> super::server::Service for T {
    async fn start(&mut self, shutdown: tokio::sync::watch::Receiver<bool>) {
        self.start_service(None, shutdown).await;
    }
}
