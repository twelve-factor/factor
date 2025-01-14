use std::path::PathBuf;

use anyhow::Result;
use directories::ProjectDirs;
use tokio::fs::write;

const QUALIFIER: &str = "dev";
const ORGANIZATION: &str = "twelve-factor";
const APPLICATION: &str = "factor";

/// Get the application's data directory, creating it if it doesn't exist
///
/// # Errors
///
/// Returns an error if:
/// - Cannot determine project directories
/// - Cannot create data directory (e.g., insufficient permissions)
pub fn get_data_dir() -> Result<PathBuf> {
    let proj_dirs = ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION)
        .ok_or_else(|| anyhow::anyhow!("Could not determine project directories"))?;

    let data_dir = proj_dirs.data_dir();
    std::fs::create_dir_all(data_dir)?;
    Ok(data_dir.to_path_buf())
}

/// Get the user's home directory
///
/// # Errors
///
/// Returns an error if the home directory cannot be determined
pub fn home_dir() -> Result<PathBuf> {
    directories::BaseDirs::new()
        .ok_or_else(|| anyhow::anyhow!("Could not find home directory"))
        .map(|dirs| dirs.home_dir().to_path_buf())
}

const URL_FILENAME: &str = "url";
const ISS_FILENAME: &str = "issuer";

/// Get the stored url from the data directory
///
/// # Errors
///
/// Returns an error if:
/// - Cannot access data directory
/// - Url file doesn't exist or can't be read
pub fn get_stored_url() -> Result<String> {
    let url_path = get_data_dir()?.join(URL_FILENAME);
    std::fs::read_to_string(&url_path)
        .map_err(|e| anyhow::anyhow!("Failed to read url file: {}", e))
}

/// Write the url for the app to the data directory
/// # Errors
///
/// Returns an error if:
/// - Cannot access data directory
/// - `write` returns an error, which can happen if:
///     - The file cannot be created or opened.
///     - There is an error writing to the file.
///     - See [`tokio::fs::write`].
pub async fn write_url(url: String) -> Result<()> {
    let url_path = get_data_dir()?.join(URL_FILENAME);
    write(&url_path, url.as_bytes()).await?;
    Ok(())
}

/// Delete the url file from the data directory
///
/// # Errors
///
/// Returns an error if:
/// - Cannot access data directory
/// - `remove_file` returns an error, which can happen if:
///     - The file doesn't exist.
///     - The user lacks permissions to remove the file.
///     - Some other I/O error occurred.
///     - See [`tokio::fs::remove_file`].
pub async fn delete_url() -> Result<()> {
    let data_dir = get_data_dir()?;
    let url_path = data_dir.join(URL_FILENAME);
    tokio::fs::remove_file(&url_path).await?;
    Ok(())
}

/// Get the stored iss from the data directory
///
/// # Errors
///
/// Returns an error if:
/// - Cannot access data directory
/// - Iss file doesn't exist or can't be read
pub fn get_stored_iss() -> Result<String> {
    let iss_path = get_data_dir()?.join(ISS_FILENAME);
    std::fs::read_to_string(&iss_path)
        .map_err(|e| anyhow::anyhow!("Failed to read iss file: {}", e))
}

/// Write the iss for the app to the data directory
/// # Errors
///
/// Returns an error if:
/// - Cannot access data directory
/// - `write` returns an error, which can happen if:
///     - The file cannot be created or opened.
///     - There is an error writing to the file.
///     - See [`tokio::fs::write`].
pub async fn write_iss(iss: String) -> Result<()> {
    let iss_path = get_data_dir()?.join(ISS_FILENAME);
    write(&iss_path, iss.as_bytes()).await?;
    Ok(())
}

/// Delete the iss file from the data directory
///
/// # Errors
///
/// Returns an error if:
/// - Cannot access data directory
/// - `remove_file` returns an error, which can happen if:
///     - The file doesn't exist.
///     - The user lacks permissions to remove the file.
///     - Some other I/O error occurred.
///     - See [`tokio::fs::remove_file`].
pub async fn delete_iss() -> Result<()> {
    let data_dir = get_data_dir()?;
    let iss_path = data_dir.join(ISS_FILENAME);
    tokio::fs::remove_file(&iss_path).await?;
    Ok(())
}
