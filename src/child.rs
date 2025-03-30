use std::env;

use async_trait::async_trait;
use log::{error, trace, warn};
use tokio::{
    process::{Child, Command},
    sync::watch,
    time::{sleep, Duration},
};

use super::server::Service;

pub struct ChildService {
    command: Vec<String>,
    port: u16,
    wait_for: Vec<String>,
}

impl ChildService {
    #[must_use]
    pub fn new(command: Vec<String>, port: u16, wait_for: Vec<String>) -> Self {
        ChildService {
            command,
            port,
            wait_for,
        }
    }
}

#[cfg(unix)]
async fn terminate(mut child: Child) {
    use libc::{kill, SIGTERM};
    use tokio::time::timeout;

    #[allow(clippy::cast_possible_wrap)]
    let pid = child.id().unwrap() as libc::pid_t; // Get the process ID of the child

    unsafe { kill(pid, SIGTERM) }; // Send SIGTERM to the process
    if let Ok(status_result) = timeout(Duration::from_secs(5), child.wait()).await {
        match status_result {
            Ok(exit_status) => {
                if exit_status.success() {
                    trace!("Child process exited successfully");
                } else {
                    warn!("Child process exited with status: {}", exit_status);
                }
            }
            Err(e) => {
                error!("Failed to wait for child process: {e}");
            }
        }
    } else {
        // Timeout expired, hard kill the process
        warn!("Timeout expired, forcefully killing the child process");
        if let Err(e) = child.start_kill() {
            error!("Failed to forcefully kill child process: {e}");
        }
    }
}

#[cfg(not(unix))]
async fn terminate(mut child: Child) {
    let _ = child.kill().await;
}

#[async_trait]
impl Service for ChildService {
    async fn start(&mut self, mut shutdown: watch::Receiver<bool>) {
        for key in &self.wait_for {
            let mut success = false;
            while !success {
                match env::var(key) {
                    Ok(val) if !val.is_empty() => success = true,
                    Ok(_) | Err(_) => {
                        warn!("Failed to get value for env var {key}: Retrying in 100ms...");
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
        trace!("starting child");
        match Command::new(&self.command[0])
            .args(&self.command[1..])
            .env("PORT", self.port.to_string())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(mut child) => {
                // Wait for shutdown signal
                tokio::select! {
                    _ = shutdown.changed() => {
                        terminate(child).await;
                    }
                    status = child.wait() => {
                        match status {
                            Ok(exit_status) => {
                                if exit_status.success() {
                                    trace!("Child process exited successfully");
                                } else {
                                    warn!("Child process exited with status: {}", exit_status);
                                }
                            }
                            Err(e) => {
                                error!("Failed to wait for child process: {e}");
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to start command: {e}");
            }
        }
    }
}
