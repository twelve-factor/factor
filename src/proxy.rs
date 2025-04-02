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
use pingora_core::{upstreams::peer::HttpPeer, Result as PingoraResult};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{HttpProxy, ProxyHttp, Session};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;

use super::identity;

pub mod credentials {
    use std::{collections::HashMap, env};

    use anyhow::Result;
    use log::{debug, warn};
    use serde::Deserialize;

    use super::IdentityValidator;

    #[derive(Debug, Deserialize)]
    pub struct ClientCredentials {
        #[serde(rename = "type")]
        cred_type: String,
        #[serde(default)]
        client_id: String,
        #[serde(default)]
        data: IdentityValidator,
    }

    /// Get a JSON-encoded environment variable and deserialize it
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The environment variable doesn't exist
    /// - The contents can't be parsed as JSON
    /// - The value can't be converted to type `T`
    pub fn var_json<T: serde::de::DeserializeOwned>(key: &str) -> Result<T> {
        let string_value = env::var(key)?;
        serde_json::from_str(&string_value).map_err(|e| {
            anyhow::anyhow!("Failed to parse JSON from environment variable {key}: {e}")
        })
    }

    fn load_incoming_identity(path: &str) -> anyhow::Result<HashMap<String, IdentityValidator>> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!("Failed to read incoming identity file at `{path}`: {e}")
        })?;
        toml::from_str(&contents).or_else(|e| {
            warn!("Failed to parse `{path}` as TOML, trying JSON: {e}");
            serde_json::from_str(&contents)
                .map_err(|e| anyhow::anyhow!("Failed to parse `{path}` as TOML or JSON: {e}"))
        })
    }

    /// Get the incoming identity configuration from various sources
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The identity file cannot be read or parsed
    /// - The `INCOMING_IDENTITY` environment variable contains invalid JSON
    /// - The identity configuration cannot be serialized back to `TOML`
    pub fn get_incoming_identity(
        incoming_identity_path: Option<&String>,
    ) -> anyhow::Result<HashMap<String, IdentityValidator>> {
        debug!("incoming identity path: {incoming_identity_path:?}");

        // Load from file if specified
        let mut incoming_identity = match incoming_identity_path {
            Some(incoming_identity_path) => load_incoming_identity(incoming_identity_path)?,
            None => HashMap::default(),
        };

        // Load from INCOMING_IDENTITY env var and merge
        if let Ok(env_identity) =
            var_json::<HashMap<String, IdentityValidator>>("INCOMING_IDENTITY")
        {
            for (key, value) in env_identity {
                incoming_identity.insert(key, value);
            }
        }

        // Store back the merged identity
        if !incoming_identity.is_empty() {
            env::set_var("INCOMING_IDENTITY", toml::to_string(&incoming_identity)?);
        }

        // Load and merge additional credentials from environment variables
        let env_creds = load_from_env();
        for (key, value) in env_creds {
            incoming_identity.insert(key, value);
        }

        Ok(incoming_identity)
    }

    /// Load identity configuration from environment variables
    ///
    /// # Returns
    ///
    /// Returns a `HashMap` mapping client IDs to their identity validators
    #[must_use]
    pub fn load_from_env() -> HashMap<String, IdentityValidator> {
        let mut incoming_identity = HashMap::new();
        for (key, _) in env::vars() {
            if key.ends_with("_CREDS") {
                let name = key.trim_end_matches("_CREDS");
                if let Ok(creds) = var_json::<ClientCredentials>(&key) {
                    let client_id = if creds.client_id.is_empty() {
                        name.to_string()
                    } else {
                        creds.client_id.clone()
                    };
                    if creds.cred_type == "oidc" {
                        incoming_identity.insert(client_id, creds.data);
                    }
                }
            }
        }
        if !incoming_identity.is_empty() {
            if let Ok(toml) = toml::to_string(&incoming_identity) {
                env::set_var("INCOMING_IDENTITY", toml);
            }
        }
        incoming_identity
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
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
    async fn handle_well_known(&self, session: &mut Session, jwks: String) -> anyhow::Result<()> {
        let iss = self.provider.get_iss().await?;
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

    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> PingoraResult<bool> {
        if session.req_header().uri.path().starts_with("/.well-known/") {
            if let Ok(Some(jwks)) = self.provider.get_jwks().await {
                if let Err(e) = self.handle_well_known(session, jwks).await {
                    info!("Failed to handle well_known {e:?}");
                    let _ = session.respond_error(500).await;
                    return Ok(true);
                }
                return Ok(true); // Indicate that the request has been handled
            }
        }
        session.req_header_mut().remove_header("X-Client-Id");
        match self.validate_token(session.req_header()).await {
            Ok(Some(client_id)) => {
                session
                    .req_header_mut()
                    .append_header("X-Client-Id", client_id)?;
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
    ) -> PingoraResult<Box<HttpPeer>> {
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
