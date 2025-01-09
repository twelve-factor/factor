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
use std::path::PathBuf;

use anyhow::Result;
use directories::ProjectDirs;

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
