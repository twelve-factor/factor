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
use anyhow::Result;
use notify::{Event, RecursiveMode, Watcher};
use reqwest;
use serde::de::DeserializeOwned;
use shellexpand::LookupError;
use std::env;
use std::env::VarError;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

// Callbacks can be either string or typed
pub type StringCallback = Arc<dyn Fn(String) + Send + Sync>;
pub type TypedCallback<T> = Arc<dyn Fn(T) + Send + Sync>;

/// Gets an environment variable with support for reference resolution and type conversion.
/// If __REF__VAR_NAME exists, it will load the value from the URI specified in that variable.
/// Supports file:// and http(s):// URIs.
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

pub fn var_json<K: AsRef<OsStr>, T>(key: K) -> Result<T, VarError>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    let string_value = var(key)?;
    let value = serde_json::from_str(&string_value).map_err(|_| VarError::NotPresent)?;
    Ok(value)
}

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

pub fn var<K: AsRef<OsStr>>(key: K) -> Result<String, VarError> {
    var_with_on_change(key.as_ref(), None)
}

// TODO: support a non-blocking version of this
fn resolve_reference(uri: &str, on_change: Option<StringCallback>) -> Result<String, VarError> {
    if uri.starts_with("file://") {
        let path = uri.trim_start_matches("file://");
        let content = fs::read_to_string(path).map_err(|_| VarError::NotPresent)?;

        // If callback provided, set up file watching
        if let Some(callback) = on_change {
            watch_file(path.into(), callback).map_err(|_| VarError::NotPresent)?;
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

fn watch_file(path: PathBuf, callback: StringCallback) -> Result<()> {
    let path_clone = path.clone();
    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            if event.kind.is_modify() {
                if let Ok(content) = std::fs::read_to_string(&path_clone) {
                    callback(content.trim().to_string());
                }
            }
        }
    })?;

    watcher.watch(&path, RecursiveMode::NonRecursive)?;

    // Store watcher to keep it alive
    std::mem::forget(watcher); // Prevent watcher from being dropped
    Ok(()) // Return Ok result
}

pub fn set_var<K: AsRef<OsStr>, V: AsRef<OsStr>>(key: K, value: V) {
    env::set_var(key.as_ref(), value.as_ref());
}
pub fn vars() -> env::Vars {
    env::vars()
}

pub fn set_var_file<K: AsRef<OsStr>, V: AsRef<OsStr>>(
    key: K,
    value: V,
    path: &PathBuf,
) -> Result<()> {
    set_var_file_with_remap(key, value, path, None, None)
}

pub fn set_var_file_with_remap<K: AsRef<OsStr>, V: AsRef<OsStr>>(
    key: K,
    value: V,
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

pub fn set_var_json<K: AsRef<OsStr>, V>(key: K, value: &V) -> Result<()>
where
    V: serde::Serialize,
{
    let json_string = serde_json::to_string(value)?;
    set_var(key, &json_string);
    Ok(())
}

pub fn set_var_json_file<K: AsRef<OsStr>, V>(key: K, value: &V, path: &PathBuf) -> Result<()>
where
    V: serde::Serialize,
{
    set_var_json_file_with_remap(key, value, path, None, None)
}

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
                .or_else(|_| Ok::<Option<String>, LookupError<std::env::VarError>>(None))
        },
    )
    .map(|expanded| expanded.into_owned())?)
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
