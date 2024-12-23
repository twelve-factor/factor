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
use tokio::process::Command;

use super::env;
use super::server::Service;
use async_trait::async_trait;
use tokio::sync::watch;
use tokio::time::{sleep, Duration};

pub struct ChildService {
    command: Vec<String>,
    port: u16,
    wait_for: Vec<String>,
}

impl ChildService {
    pub fn new(command: Vec<String>, port: u16, wait_for: Vec<String>) -> Self {
        ChildService {
            command,
            port,
            wait_for,
        }
    }
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
                        eprintln!(
                            "Failed to get value for env var {key}: Retrying in 100ms..."
                        );
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
        println!("starting child");
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
                        if let Err(e) = child.kill().await {
                            eprintln!("Failed to kill child process: {e}");
                        } else {
                            println!("Child process killed successfully");
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to start command: {e}");
            }
        }
    }
}
