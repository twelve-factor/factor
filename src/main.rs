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
use clap::{Parser, Subcommand};
use dotenvy::dotenv;
use env_logger;
use factor::child;
use factor::env;
use factor::identity;
use factor::identity::IdProvider;
use factor::ngrok;
use factor::proxy;
use factor::proxy::IncomingIdentity;
use notify::{Event, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::sync::watch;
use tokio::time::sleep;

use tokio::runtime::Runtime;

#[derive(Debug, Default, Deserialize, Serialize)]
struct GlobalConfig {
    id: Option<GlobalIdConfig>,
    ngrok: Option<NgrokConfig>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct GlobalIdConfig {
    default_provider: Option<String>,
    #[serde(default)]
    providers: Vec<ProviderConfig>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
struct NgrokConfig {
    token: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ProviderConfig {
    #[serde(default)]
    name: String,
    #[serde(flatten)]
    settings: identity::ProviderConfig,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct AppConfig {
    #[serde(default = "default_app_name")]
    app: String,
    #[serde(default = "default_app_path")]
    path: String,
    id: Option<AppIdConfig>,
    ngrok: Option<NgrokConfig>,
}

fn default_app_name() -> String {
    "factor-app".to_string()
}

fn default_app_path() -> String {
    ".".to_string()
}

#[derive(Debug, Deserialize, Serialize)]
struct AppIdConfig {
    name: String,
    #[serde(flatten)]
    provider: ProviderConfig,
    #[serde(default)]
    targets: HashMap<String, String>,
}

fn load_global_config() -> Result<GlobalConfig, anyhow::Error> {
    let home_dir =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;
    let config_path = home_dir.join(".factor");

    match std::fs::read_to_string(config_path) {
        Ok(contents) => Ok(toml::from_str(&contents)?),
        Err(_) => Ok(GlobalConfig::default()),
    }
}

fn load_app_config(path: &str) -> Result<AppConfig, anyhow::Error> {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            let expanded_contents = env::expand(&contents)?;
            Ok(toml::from_str(&expanded_contents)?)
        }
        Err(_) => Ok(AppConfig::default()),
    }
}

fn load_incoming_identity(path: &str) -> Result<IncomingIdentity, anyhow::Error> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read incoming identity file at {}: {}", path, e))?;
    toml::from_str(&contents).or_else(|e| {
        eprintln!("Failed to parse {} as TOML, trying JSON: {}", path, e);
        serde_json::from_str(&contents)
            .map_err(|e| anyhow::anyhow!("Failed to parse {} as TOML or JSON: {}", path, e))
    })
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to app config file
    #[arg(long, default_value = ".factor-app", global = true)]
    config: String,

    #[command(subcommand)]
    command: Commands,
}
fn parse_target<T: AsRef<str>, U: AsRef<str>>(s: &str) -> Result<(T, U), String>
where
    T: From<String>,
    U: From<String>,
{
    let pos = s.find('=');
    match pos {
        None => Ok((T::from(s.to_string()), U::from(s.to_string()))),
        Some(pos) => {
            let key = s[..pos].to_string();
            let value = s[pos + 1..].to_string();
            Ok((T::from(key), U::from(value)))
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new application configuration
    Create {
        /// Application name
        #[arg(long, required = true)]
        app: String,

        /// Path for dynamic env var storage
        #[arg(long, default_value = ".")]
        path: String,

        /// Identity provider to use
        #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(IdProvider::variants()))]
        id_provider: Option<String>,

        /// Target ID and audience for the identity token
        #[arg(long = "id-target", action = clap::ArgAction::Append, value_parser = parse_target::<String, String>)]
        id_targets: Vec<(String, String)>,
    },
    /// Sync identities for app
    Id {
        /// Target ID and audience for the identity token
        #[arg(long = "target", action = clap::ArgAction::Append, value_parser = parse_target::<String, String>)]
        targets: Vec<(String, String)>,
    },
    /// Proxy from PORT to CHILD_PORT
    Proxy {
        /// Reject requests from unknown clients
        #[arg(long, default_value = "false")]
        reject_unknown: bool,

        /// Use IPv6 instead of IPv4
        #[arg(long, short = '6', default_value = "false")]
        ipv6: bool,

        /// File that contains incoming identity
        #[arg(long)]
        incoming_identity: Option<String>,

        /// Listening port for proxy
        #[arg(long, env = "PORT", value_parser = clap::value_parser!(u16), default_value = "5000")]
        port: u16,

        /// Forwarding port for proxy
        #[arg(long, env = "CHILD_PORT", value_parser = clap::value_parser!(u16), default_value = "5001")]
        child_port: u16,
    },
    /// Run a command with a proxy redirecting PORT
    Run {
        /// Reject requests from unknown clients
        #[arg(long, default_value = "false")]
        reject_unknown: bool,

        /// Use IPv6 instead of IPv4
        #[arg(long, short = '6', default_value = "false")]
        ipv6: bool,

        /// File that contains incoming identity
        #[arg(long)]
        incoming_identity: Option<String>,

        /// Listening port for proxy
        #[arg(long, env = "PORT", value_parser = clap::value_parser!(u16), default_value = "5000")]
        port: u16,

        /// Command to execute
        #[arg(required = true)]
        command: Vec<String>,
    },
}

fn main() -> Result<(), anyhow::Error> {
    dotenv().ok();
    // Initialize the logger from the environment
    env_logger::init();
    let global_config = load_global_config()?;

    let cli = Cli::parse();

    let mut app_config = load_app_config(&cli.config)?;
    if app_config.id.is_none() {
        if let Some(default_provider) = &global_config
            .id
            .as_ref()
            .and_then(|id| id.default_provider.as_ref())
        {
            if let Some(provider_config) = global_config
                .id
                .as_ref()
                .and_then(|id| id.providers.iter().find(|p| &p.name == *default_provider))
            {
                app_config.id = Some(AppIdConfig {
                    name: default_provider.to_string(),
                    provider: provider_config.clone(),
                    targets: vec![("default".to_string(), "default".to_string())]
                        .into_iter()
                        .collect(),
                });
            }
        }
    }

    match &cli.command {
        Commands::Create {
            app,
            id_provider,
            path,
            id_targets,
        } => {
            handle_create(
                app,
                id_provider,
                path,
                id_targets,
                &global_config,
                &cli.config,
            )?;
        }
        Commands::Id { targets } => {
            handle_id(targets, &app_config)?;
        }
        Commands::Proxy {
            port,
            reject_unknown,
            ipv6,
            incoming_identity,
            child_port,
        } => {
            handle_proxy(
                *port,
                *child_port,
                incoming_identity,
                *reject_unknown,
                *ipv6,
                &app_config,
            )?;
        }
        Commands::Run {
            command,
            port,
            reject_unknown,
            ipv6,
            incoming_identity,
        } => {
            handle_run(
                command,
                *port,
                *reject_unknown,
                *ipv6,
                incoming_identity,
                &app_config,
            )?;
        }
    }
    Ok(())
}

fn handle_create(
    app: &String,
    id_provider: &Option<String>,
    path: &String,
    id_targets: &Vec<(String, String)>,
    global_config: &GlobalConfig,
    config_path: &String,
) -> Result<(), anyhow::Error> {
    println!("Creating application configuration");

    // Ensure we have global id config
    let global_id_config = global_config.id.as_ref().ok_or_else(|| {
        anyhow::anyhow!("No identity configuration found in global config (~/.factor)")
    })?;
    // Get the provider - either from flag or default from global config
    let provider_name = match id_provider.as_ref() {
        Some(provider_str) => {
            // If provider is explicitly set, fail if not found
            if !global_id_config
                .providers
                .iter()
                .any(|p| p.name == provider_str.as_str())
            {
                anyhow::bail!("{} provider not found in global config", provider_str);
            }
            provider_str.as_str()
        }
        None => {
            // Only use default if no provider specified
            global_id_config
                .default_provider
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("No default provider specified in global config"))?
        }
    };

    // Get the provider config from global config
    let provider_config = global_id_config
        .providers
        .iter()
        .find(|p| p.name == provider_name)
        .ok_or_else(|| {
            anyhow::anyhow!("{} provider not configured in global config", provider_name)
        })?;

    let mut id_config = provider_config.clone();

    let provider = identity::create_provider(&id_config.settings)?;

    let rt = Runtime::new()?;
    id_config.settings = rt.block_on(provider.configure_app_identity(&app))?;

    let app_config = AppConfig {
        app: app.to_string(),
        path: path.to_string(),
        ngrok: global_config.ngrok.clone(),
        id: Some(AppIdConfig {
            name: provider_name.to_string(),
            provider: id_config,
            targets: id_targets.into_iter().cloned().collect(),
        }),
    };

    // Write the config to file
    let toml_string = toml::to_string_pretty(&app_config).expect("Failed to serialize config");
    let mut file = std::fs::File::create(config_path).expect("Failed to create config file");
    file.write_all(toml_string.as_bytes())
        .expect("Failed to write config file");

    println!("Configuration written to {}", config_path);
    Ok(())
}

fn handle_id(targets: &Vec<(String, String)>, app_config: &AppConfig) -> Result<(), anyhow::Error> {
    println!("Running id command");

    let mut targets_map = app_config
        .id
        .as_ref()
        .map(|id| id.targets.clone())
        .unwrap_or_default();

    for (key, value) in targets {
        targets_map.insert(key.clone(), value.clone());
    }
    if targets_map.is_empty() {
        anyhow::bail!("At least one target must be specified");
    }

    let provider_config = app_config
        .id
        .as_ref()
        .map(|id| &id.provider.settings)
        .ok_or_else(|| anyhow::anyhow!("Identity provider is required"))?;

    let provider = identity::create_provider(&provider_config)?;
    let mut server = factor::server::Server::new();
    for (target_id, audience) in targets_map {
        println!("adding identity for {}", target_id);
        let identity_service = identity::IdentitySyncService::new(
            &app_config.path,
            &target_id,
            &audience,
            provider.clone(),
        )?;
        server.add_service(identity_service);
    }

    server.run();
    server.wait_for_exit();
    Ok(())
}

fn handle_proxy(
    port: u16,
    child_port: u16,
    incoming_identity: &Option<String>,
    reject_unknown: bool,
    ipv6: bool,
    app_config: &AppConfig,
) -> Result<(), anyhow::Error> {
    println!("Running proxy command");
    let incoming_identity = get_incoming_identity(incoming_identity)?;
    let runtime: Arc<Runtime> = Runtime::new()?.into();
    maybe_run_background_ngrok(runtime.clone(), app_config, port, ipv6)?;

    let id = app_config
        .id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Identity provider is required"))?;
    let provider = identity::create_provider(&id.provider.settings)?;

    println!("Proxying port {} to {}", port, child_port);
    let mut server = factor::server::Server::new_from_runtime(runtime);
    let proxy_service = proxy::get_proxy_service(
        port,
        child_port,
        incoming_identity,
        reject_unknown,
        ipv6,
        provider.clone(),
    )?;
    server.add_service(proxy_service);
    server.run();
    server.wait_for_exit();
    Ok(())
}

fn maybe_run_background_ngrok(
    runtime: Arc<Runtime>,
    app_config: &AppConfig,
    port: u16,
    ipv6: bool,
) -> Result<Option<String>, anyhow::Error> {
    if let Some(ngrok_config) = &app_config.ngrok {
        if !ngrok_config.token.is_empty() {
            let (tx, rx) = oneshot::channel();
            let ngrok_service =
                ngrok::NgrokService::new(tx, port, ipv6, ngrok_config.token.clone())?;
            std::thread::spawn(move || {
                // ngrok needs to run in a separate thread so we create a new runtime for it.
                let ngrok_runtime: Arc<Runtime> =
                    Runtime::new().expect("failed to create runtime").into();
                let mut server = factor::server::Server::new_from_runtime(ngrok_runtime);
                server.add_service(ngrok_service);
                server.run(); // Runs ngrok service
                server.wait_for_exit();
            });

            let url = runtime.block_on(async move {
                if let Ok(url) = rx.await {
                    Some(url)
                } else {
                    None
                }
            });

            return Ok(url);
        }
    }
    Ok(None)
}

fn setup_env_watcher() -> Result<(watch::Sender<bool>, watch::Receiver<bool>), anyhow::Error> {
    let (file_tx, file_rx) = watch::channel(false);
    let file_tx_clone = file_tx.clone();
    let mut fswatcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            if event.kind.is_modify() {
                let _ = file_tx_clone.send(true);
            }
        }
    })?;
    if let Err(e) = fswatcher.watch(Path::new(".env"), RecursiveMode::NonRecursive) {
        println!("Error watching .env: {}", e);
    } else {
        // forget the watcher so it continues to function
        std::mem::forget(fswatcher);
    }
    Ok((file_tx, file_rx))
}

fn handle_run(
    command: &Vec<String>,
    port: u16,
    reject_unknown: bool,
    ipv6: bool,
    incoming_identity: &Option<String>,
    app_config: &AppConfig,
) -> Result<(), anyhow::Error> {
    if command.is_empty() {
        anyhow::bail!("run command requires a subcommand to execute");
    }
    println!("Running run command");

    let runtime: Arc<Runtime> = Runtime::new()?.into();
    let ngrok_url = maybe_run_background_ngrok(runtime.clone(), app_config, port, ipv6)?;
    if let Some(url) = ngrok_url {
        env::set_var("NGROK_URL", url);
    };

    let (file_tx, mut file_rx) = setup_env_watcher()?;
    runtime.block_on(async {
        loop {
            let mut server = factor::server::Server::new_from_runtime(runtime.clone());
            add_services(
                &mut server,
                app_config,
                incoming_identity,
                port,
                reject_unknown,
                ipv6,
                command,
            )?;

            server.run();
            while !*file_rx.borrow_and_update() {
                file_rx.changed().await.unwrap();
            }
            sleep(Duration::from_millis(300)).await;

            println!("Sending shutdown signal to all services...");
            server.shutdown();

            file_tx.send(false)?;

            println!("All services shut down. Restarting...");
        }
    })
}

fn add_services(
    server: &mut factor::server::Server,
    app_config: &AppConfig,
    incoming_identity: &Option<String>,
    port: u16,
    reject_unknown: bool,
    ipv6: bool,
    command: &Vec<String>,
) -> Result<(), anyhow::Error> {
    dotenv().ok();
    let incoming_identity = get_incoming_identity(incoming_identity)?;

    let id = app_config
        .id
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Identity provider is required"))?;
    let mut targets = id.targets.clone();

    for (key, value) in env::vars() {
        if key.ends_with("_AUDIENCE") {
            let target_id = key.trim_end_matches("_AUDIENCE");
            targets.insert(target_id.to_string(), value);
        }
    }

    let provider = identity::create_provider(&id.provider.settings)?;

    let child_port = TcpListener::bind("[::]:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    println!("Proxying port {} to {}", port, child_port);
    let proxy_service = proxy::get_proxy_service(
        port,
        child_port,
        incoming_identity,
        reject_unknown,
        ipv6,
        provider.clone(),
    )?;
    server.add_service(proxy_service);

    let mut waiters = vec![];

    for (target_id, audience) in targets {
        let identity_service = identity::IdentitySyncService::new(
            &app_config.path,
            &target_id,
            &audience,
            provider.clone(),
        )?;
        waiters.push(identity_service.key.clone());
        server.add_service(identity_service);
    }

    let child_service = child::ChildService::new(command.to_vec(), child_port, waiters.clone());
    server.add_service(child_service);

    Ok(())
}

fn get_incoming_identity(
    incoming_identity_path: &Option<String>,
) -> Result<IncomingIdentity, anyhow::Error> {
    println!("incoming identity path: {:?}", incoming_identity_path);
    let incoming_identity = match incoming_identity_path {
        Some(incoming_identity_path) => load_incoming_identity(incoming_identity_path)?,
        None => IncomingIdentity::default(),
    };
    let incoming_identity = if !incoming_identity.is_empty() {
        env::set_var("INCOMING_IDENTITY", toml::to_string(&incoming_identity)?);
        incoming_identity
    } else {
        env::var_json("INCOMING_IDENTITY").unwrap_or_else(|e| {
            println!(
                "No INCOMING_IDENTITY specified, using default. Error: {:?}",
                e
            );
            Default::default()
        })
    };
    Ok(incoming_identity)
}