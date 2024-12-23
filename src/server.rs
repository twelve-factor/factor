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

use std::sync::Arc;

use async_trait::async_trait;
use tokio::{runtime::Runtime, sync::watch, task::JoinHandle};

#[async_trait]
pub trait Service: Send + Sync {
    async fn start(&mut self, shutdown: watch::Receiver<bool>);
}

// TODO: remove this compatibility shim once internal traits are used
pub struct Server {
    services: Vec<Box<dyn Service>>,
    handles: Vec<JoinHandle<()>>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    runtime: Arc<Runtime>,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    pub fn new() -> Server {
        let runtime = Runtime::new().expect("Failed to create Tokio runtime");
        Server::new_from_runtime(runtime.into())
    }

    pub fn new_from_runtime(runtime: Arc<Runtime>) -> Server {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Server {
            services: vec![],
            handles: vec![],
            shutdown_tx,
            shutdown_rx,
            runtime,
        }
    }

    pub fn add_service(&mut self, service: impl Service + 'static) {
        self.services.push(Box::new(service));
    }

    pub fn run(&mut self) {
        let services = std::mem::take(&mut self.services);

        for mut service in services {
            let shutdown = self.shutdown_rx.clone();
            let handle = self.runtime.spawn(async move {
                service.start(shutdown).await;
            });
            self.handles.push(handle);
        }
    }

    pub fn shutdown(&mut self) {
        println!("Sending shutdown signal to all services...");
        self.shutdown_tx
            .send(true)
            .expect("Failed to send shutdown signal");
        self.wait_for_exit();
    }

    pub fn wait_for_exit(&mut self) {
        let handles = std::mem::take(&mut self.handles);
        self.runtime.block_on(async move {
            for handle in handles {
                handle.await.unwrap();
            }
        })
    }
}
