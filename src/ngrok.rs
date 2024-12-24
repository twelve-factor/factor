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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use async_trait::async_trait;
use log::{error, info, trace, warn};
use ngrok::prelude::*;
use tokio::sync::{oneshot, watch};

use super::server::Service;

pub struct NgrokService {
    port: u16,
    token: String,
    ipv6: bool,
    tx: Option<oneshot::Sender<String>>,
}

impl NgrokService {
    #[must_use]
    pub fn new(tx: oneshot::Sender<String>, port: u16, ipv6: bool, token: String) -> Self {
        NgrokService {
            port,
            token,
            ipv6,
            tx: Some(tx),
        }
    }
}

#[async_trait]
impl Service for NgrokService {
    async fn start(&mut self, mut shutdown: watch::Receiver<bool>) {
        // Listen on ngrok ingress (i.e., https://myapp.ngrok.io)
        let mut session = match ngrok::Session::builder()
            .authtoken(self.token.clone())
            .connect()
            .await
        {
            Ok(session) => session,
            Err(e) => {
                error!("Failed to connect to ngrok: {e}");
                return;
            }
        };
        let mut listener = match session.http_endpoint().listen().await {
            Ok(listener) => listener,
            Err(e) => {
                error!("Failed to listen on ngrok: {e}");
                return;
            }
        };
        let ingress_url = listener.url().to_string();
        let addr = if self.ipv6 {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), self.port)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), self.port)
        };

        // Start forwarding in a background task
        let forward_task = tokio::spawn(async move {
            if let Err(e) = listener.forward_tcp(addr).await {
                error!("Failed to forward traffic to localhost: {e}");
            }
        });

        info!("Forwarding to: http://localhost:{}", self.port);
        info!("Ingress URL: {ingress_url}");
        if let Some(tx) = self.tx.take() {
            if let Err(e) = tx.send(ingress_url) {
                warn!("Failed to send URL: {e}");
            }
        } else {
            warn!("Sender has already been used or is not available");
        }

        // Wait for either shutdown signal or listener completion
        tokio::select! {
            _ = shutdown.changed() => {
                // Shutdown signal received, gracefully stop the listener
                if let Err(e) = session.close().await {
                    error!("Failed to close ngrok listener: {e}");
                }
            }
            _ = forward_task => {
                trace!("Forwarding task completed.");
            }
        }
    }
}
