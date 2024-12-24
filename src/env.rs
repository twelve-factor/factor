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
    borrow::Cow,
    env,
    env::VarError,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;
use notify::{Event, RecursiveMode, Watcher};
use reqwest;
use serde::de::DeserializeOwned;
use shellexpand::LookupError;

// Callbacks can be either string or typed
pub type StringCallback = Arc<dyn Fn(String) + Send + Sync>;
pub type TypedCallback<T> = Arc<dyn Fn(T) + Send + Sync>;

/// Gets an environment variable with support for reference resolution and type conversion.
/// If `__REF__VAR_NAME` exists, it will load the value from the URI specified in that variable.
/// Supports file:// and http(s):// URIs.
///
/// # Errors
///
/// Returns `VarError::NotPresent` if:
/// - The environment variable (`__REF__{key}`) doesn't exist
///
/// Returns `VarError::InvalidReference` if:
/// - The environment variable is a reference (`__REF__` prefix) but:
///   - The URI is invalid
///   - HTTP request fails
///   - File read fails
///   - File read fails
pub fn var_json_with_on_change<K: AsRef<OsStr>, T>(
    key: K,
    on_change: Option<TypedCallback<T>>,
) -> Result<T, VarError>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    let string_callback = on_change.map(|cb| {
        let cb_clone = cb.clone();
        Arc::new(move |s: String| {
            if let Ok(val) = serde_json::from_str(&s) {
                cb_clone(val);
            }
        }) as StringCallback
    });

    let string_value = var_with_on_change(key, string_callback)?;

    let value = serde_json::from_str(&string_value).map_err(|_| VarError::NotPresent)?;
    Ok(value)
}

/// # Errors
///
/// Returns `VarError::NotPresent` if:
///
/// - The environment variable (`__REF__{key}`) doesn't exist
/// - The contents of the environment variable can't be parsed as JSON
/// - The value of the environment variable can't be converted to the desired
///   type (`T`)
pub fn var_json<K: AsRef<OsStr>, T>(key: K) -> Result<T, VarError>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    let string_value = var(key)?;
    let value = serde_json::from_str(&string_value).map_err(|_| VarError::NotPresent)?;
    Ok(value)
}

/// # Errors
///
/// Returns `VarError::NotPresent` if:
///
/// - The environment variable (`__REF__{key}`) doesn't exist
pub fn var_with_on_change<K: AsRef<OsStr>>(
    key: K,
    on_change: Option<StringCallback>,
) -> Result<String, VarError> {
    if let Some(key_str) = key.as_ref().to_str() {
        let ref_key = format!("__REF__{key_str}");
        if let Ok(ref_value) = env::var(&ref_key) {
            return resolve_reference(&ref_value, on_change);
        }
    }
    env::var(key)
}

/// # Errors
///
/// Returns `VarError::NotPresent` if:
///
/// - The environment variable (`__REF__{key}`) doesn't exist
pub fn var<K: AsRef<OsStr>>(key: K) -> Result<String, VarError> {
    var_with_on_change(key.as_ref(), None)
}

// TODO: support a non-blocking version of this
/// # Errors
///
/// Returns `VarError::NotPresent` if:
///
/// - For `file://` URIs:
///   - File doesn't exist
///   - See [`std::fs::OpenOptions::open`]
/// - For `http(s)://` URIs:
///   - Network request fails. See [`reqwest::blocking::get`]
///   - The network response had a `charset` parameter, but the content can't be
///     decoded with that encoding.
///   - The network response doesn't have a `charset` parameter, and the content
///     can't be decoded with UTF-8
///
/// Other schemes are not supported, and will return `VarError::NotPresent`.
// TODO: These should probably return `VarError::InvalidReference` instead
fn resolve_reference(uri: &str, on_change: Option<StringCallback>) -> Result<String, VarError> {
    if uri.starts_with("file://") {
        let path = uri.trim_start_matches("file://");
        let content = fs::read_to_string(path).map_err(|_| VarError::NotPresent)?;

        // If callback provided, set up file watching
        if let Some(callback) = on_change {
            watch_file(&path, callback).map_err(|_| VarError::NotPresent)?;
        }

        Ok(content.trim().to_string())
    } else if uri.starts_with("http://") || uri.starts_with("https://") {
        let content = reqwest::blocking::get(uri)
            .map_err(|_| VarError::NotPresent)?
            .text()
            .map_err(|_| VarError::NotPresent)?;
        Ok(content.trim().to_string())
    } else {
        Err(VarError::NotPresent)
    }
}

fn watch_file(path: &impl AsRef<Path>, callback: StringCallback) -> Result<()> {
    // Copy the path to an owned PathBuf so it can be shared with the watcher
    let path_buf = path.as_ref().to_path_buf();

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            if event.kind.is_modify() {
                if let Ok(content) = std::fs::read_to_string(&path_buf) {
                    callback(content.trim().to_string());
                }
            }
        }
    })?;

    watcher.watch(path.as_ref(), RecursiveMode::NonRecursive)?;

    // Store watcher to keep it alive
    std::mem::forget(watcher); // Prevent watcher from being dropped
    Ok(()) // Return Ok result
}

pub fn set_var<K: AsRef<OsStr>, V: AsRef<OsStr>>(key: K, value: V) {
    env::set_var(key.as_ref(), value.as_ref());
}

#[must_use]
pub fn vars() -> env::Vars {
    env::vars()
}

/// # Errors
///
/// Returns `anyhow::Error` in these common error conditions caused by the user:
///
/// - `path` is the root (and therefore has no parent)
/// - The parent of the path doesn't exist
///
/// See [`set_var_file_with_remap`] for more error conditions
///
/// TODO: separate user errors (which should be reported as-is to the user) from
/// permission errors.
pub fn set_var_file(
    key: impl AsRef<OsStr>,
    value: impl AsRef<OsStr>,
    path: &PathBuf,
) -> Result<()> {
    set_var_file_with_remap(key, value, path, None, None)
}

/// # Errors
///
/// Returns `anyhow::Error` in these common error conditions caused by the user:
///
/// - `path` is the root (and therefore has no parent)
/// - The parent of the path doesn't exist
///
/// Permission issues:
///
/// - A temporary file can't be created
/// - A successfully created temporary file can't be written to
/// - A successfully created temporary file can't be renamed to the specified path
///
/// More rarely:
///
/// - The key is not valid UTF-8
/// - The path is not valid UTF-8
pub fn set_var_file_with_remap(
    key: impl AsRef<OsStr>,
    value: impl AsRef<OsStr>,
    path: &PathBuf,
    from: Option<&str>,
    to: Option<&str>,
) -> Result<()> {
    let canonicalized_parent = path
        .parent()
        .ok_or(VarError::NotPresent)?
        .canonicalize()
        .map_err(|e| {
            anyhow::anyhow!("Failed to get canonical parent path from {:?}: {}", path, e)
        })?;
    let file_name = path
        .file_name()
        .ok_or(VarError::NotPresent)?
        .to_str()
        .ok_or(VarError::NotPresent)?;
    let canonical_path = canonicalized_parent.join(file_name); // Create PathBuf here
    let path_str = canonical_path.to_str().ok_or(VarError::NotPresent)?; // path_str is now derived from rename_path

    let remapped_path = match (from, to) {
        (Some(from_str), Some(to_str)) => path_str.replace(from_str, to_str),
        _ => path_str.to_string(),
    };
    let ref_key = format!(
        "__REF__{}",
        key.as_ref().to_str().ok_or(VarError::NotPresent)?
    );
    set_var(ref_key, format!("file://{}", &remapped_path));
    let temp_file = tempfile::NamedTempFile::new()
        .map_err(|e| anyhow::anyhow!("Failed to create temporary file: {}", e))?;
    let temp_path = temp_file.into_temp_path();
    fs::write(&temp_path, value.as_ref().to_string_lossy().as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to write to temporary file: {}", e))?;
    fs::rename(&temp_path, &canonical_path)
        .map_err(|e| anyhow::anyhow!("Failed to rename temporary file: {}", e))?;
    Ok(())
}

/// # Errors
///
/// Returns `anyhow::Error` if the value can't be serialized to JSON
pub fn set_var_json(key: impl AsRef<OsStr>, value: &impl serde::Serialize) -> Result<()> {
    let json_string = serde_json::to_string(value)?;
    set_var(key, &json_string);
    Ok(())
}

/// # Errors
///
/// See [`set_var_json_file_with_remap`]
pub fn set_var_json_file<K: AsRef<OsStr>, V>(key: K, value: &V, path: &PathBuf) -> Result<()>
where
    V: serde::Serialize,
{
    set_var_json_file_with_remap(key, value, path, None, None)
}

/// # Errors
///
/// Returns `anyhow::Error` if:
///
/// - the value can't be serialized to JSON
/// - the specified path is the root (and therefore has no parent)
/// - the parent of the path doesn't exist
///
/// See [`set_var_file_with_remap`] for more uncommon error conditions
pub fn set_var_json_file_with_remap<K: AsRef<OsStr>, V>(
    key: K,
    value: &V,
    path: &PathBuf,
    from: Option<&str>,
    to: Option<&str>,
) -> Result<()>
where
    V: serde::Serialize,
{
    let json_string = serde_json::to_string(value)?;
    set_var_file_with_remap(key, json_string.as_str(), path, from, to)
}

/// # Errors
///
/// Returns `anyhow::Error` if:
///
/// - The environment variable (`__REF__{key}`) doesn't exist
/// - The input string has invalid syntax (e.g., unclosed `${` braces)
pub fn expand(input: &str) -> Result<String> {
    Ok(shellexpand::env_with_context(
        input,
        |key| -> Result<Option<String>, LookupError<std::env::VarError>> {
            var(key)
                .map(Some)
                .map_err(|e| LookupError {
                    var_name: key.to_string(),
                    cause: e,
                })
                .or(Ok::<Option<String>, LookupError<std::env::VarError>>(None))
        },
    )
    .map(Cow::into_owned)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_with_file() {
        let key = "TEST_EXPAND_VAR";
        let value = "TestValue";
        let temp_file = tempfile::NamedTempFile::new().unwrap();
        let temp_path = temp_file.into_temp_path();
        assert!(set_var_file(key, value, &temp_path.to_path_buf()).is_ok());
        assert_eq!(var(key).unwrap(), value);

        let input = format!("Prefix-${key}-Suffix");

        let expected = format!("Prefix-{value}-Suffix");

        let result = expand(&input).unwrap();

        assert_eq!(result, expected);

        env::remove_var(key);
    }
}
