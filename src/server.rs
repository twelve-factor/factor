use std::sync::Arc;

use async_trait::async_trait;
use log::{error, trace};
use tokio::{runtime::Runtime, sync::watch, task::JoinSet};

#[async_trait]
pub trait Service: Send + Sync {
    async fn start(&mut self, shutdown: watch::Receiver<bool>);
}

// TODO: remove this compatibility shim once internal traits are used

pub struct Server {
    services: Vec<Box<dyn Service>>,
    handles: JoinSet<()>,
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
    /// # Panics
    ///
    /// Panics if the Tokio runtime cannot be created.
    ///
    /// TODO: Should we just expect consumers to supply their own
    /// `#[tokio::main]` entry point?
    #[must_use]
    pub fn new() -> Server {
        let runtime = Runtime::new().expect("Failed to create Tokio runtime");
        Server::new_from_runtime(runtime.into())
    }

    pub fn new_from_runtime(runtime: Arc<Runtime>) -> Server {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Server {
            services: vec![],
            handles: JoinSet::new(),
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

        // Enter the runtime context manually
        let _guard = self.runtime.enter();

        for mut service in services {
            let shutdown = self.shutdown_rx.clone();
            self.handles.spawn(async move {
                service.start(shutdown).await;
            });
        }
    }

    /// # Panics
    ///
    /// Panics if the shutdown channel is already closed.
    pub async fn shutdown(&mut self) {
        trace!("Sending shutdown signal to all services...");
        self.shutdown_tx
            .send(true)
            .expect("Failed to send shutdown signal");
        self.wait_internal().await;
    }

    async fn wait_internal(&mut self) {
        while let Some(result) = self.handles.join_next().await {
            match result {
                Ok(()) => {
                    trace!("A service task exited successfully");
                }
                Err(e) => {
                    error!("A service task exited with an error: {e}");
                }
            }
        }
        trace!("All service tasks have exited");
    }

    /// # Panics
    ///
    /// Panics if awaiting any of the join handles fails. This
    /// is most likely due to a panic in one of the services.  
    pub fn wait_for_exit(&mut self) {
        let runtime = self.runtime.clone();
        runtime.block_on(self.wait_internal());
    }

    pub async fn wait_for_any_service(&mut self) {
        if let Some(result) = self.handles.join_next().await {
            if let Err(e) = result {
                error!("A service task exited with an error: {e}");
            } else {
                trace!("A service task exited successfully");
            }
        }
    }
}
