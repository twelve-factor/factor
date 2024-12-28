use std::path::{Path, PathBuf};

use derive_more::derive::{Display, From};
use snafu::Snafu;

#[derive(Debug, Clone, From)]
pub enum ParseSource {
    #[from(ConfigLocation)]
    Config(ConfigLocation),
    #[from(String, &str)]
    Other(String),
    Unknown,
}

/// `ConfigError` describes an error in a configuration file used by Factor.
///
/// You generally build
#[derive(Debug, Clone, From, Snafu)]
pub struct ConfigError {
    pub location: ConfigLocation,
    pub pointer: ConfigPointer,
    pub reason: ConfigErrorReason,
}

pub struct ExpectedConfigBuilder {
    location: ConfigLocation,
    expected: ExpectedValue,
    pointer: ConfigPointer,
}

impl ExpectedConfigBuilder {
    #[must_use]
    pub fn missing(self) -> ConfigError {
        ConfigError {
            location: self.location,
            pointer: self.pointer,
            reason: ConfigErrorReason::Missing {
                expected: self.expected,
            },
        }
    }

    #[must_use]
    pub fn mismatch(self, actual: impl Into<ActualValue>) -> ConfigError {
        ConfigError {
            location: self.location,
            pointer: self.pointer,
            reason: ConfigErrorReason::Mismatch {
                expected: self.expected,
                actual: actual.into(),
            },
        }
    }
}

/// `ConfigSource` describes the location of a configuration file used by
/// Factor.
#[derive(Debug, Clone, Display)]
#[display("{purpose} - {file}")]
pub struct ConfigLocation {
    purpose: ConfigPurpose,
    file: ConfigFile,
}

impl ConfigLocation {
    #[must_use]
    pub fn not_found(self) -> ConfigLocation {
        let Self { purpose, file } = self;

        Self {
            purpose,
            file: ConfigFile::NotFound {
                default: file.into_default_path(),
            },
        }
    }
}

#[derive(Debug, Clone, Display)]
pub enum ConfigPurpose {
    #[display("app config")]
    App,
    #[display("global config")]
    Global,
    #[display("{name} provider config")]
    Provider { name: String },
}

impl ConfigPurpose {
    pub fn at(self, file: impl Into<PathBuf>) -> ConfigLocation {
        ConfigLocation {
            purpose: self,
            file: ConfigFile::default(file),
        }
    }
}

impl ConfigLocation {
    pub fn app(file: impl Into<ConfigFile>) -> Self {
        Self {
            purpose: ConfigPurpose::App,
            file: file.into(),
        }
    }

    pub fn global(file: impl Into<ConfigFile>) -> Self {
        Self {
            purpose: ConfigPurpose::Global,
            file: file.into(),
        }
    }

    pub fn provider(name: impl AsRef<str>, file: impl Into<ConfigFile>) -> Self {
        Self {
            purpose: ConfigPurpose::Provider {
                name: name.as_ref().to_string(),
            },
            file: file.into(),
        }
    }

    pub fn at_root(&self, expected: impl Into<ExpectedValue>) -> ExpectedConfigBuilder {
        self.at(ConfigPointer::Root, expected)
    }

    pub fn missing(
        &self,
        pointer: impl Into<ConfigPointer>,
        expected: impl Into<ExpectedValue>,
    ) -> ConfigError {
        self.at(pointer, expected).missing()
    }

    pub fn at(
        &self,
        pointer: impl Into<ConfigPointer>,
        expected: impl Into<ExpectedValue>,
    ) -> ExpectedConfigBuilder {
        ExpectedConfigBuilder {
            location: self.clone(),
            expected: expected.into(),
            pointer: pointer.into(),
        }
    }
}

/// `ConfigFile` is a path to a configuration file used by Factor.
///
/// `ConfigFile::Default` is the path to the default configuration file.
///
/// `ConfigFile::Configured` is a path to a configuration file that was
/// explicitly specified using the `-c` flag or the `--config` environment.
///
/// The distinction between `ConfigFile::Default` and `ConfigFile::Configured`
/// allows us to provide a more helpful error message when the default
/// configuration file is used (to help users that don't know the location
/// of the default file)
#[derive(Debug, Display, Clone)]
pub enum ConfigFile {
    #[display("at {path}, the default location", path = path.to_string_lossy())]
    Default { path: PathBuf },
    #[display("the default config (configure at {default})", default = default.to_string_lossy())]
    NotFound { default: PathBuf },
    #[display("at {path}", path = configured.at.to_string_lossy())]
    Configured { configured: ConfiguredConfigFile },
}

impl ConfigFile {
    /// Returns the path to the configuration file, if it exists. If the path is
    /// `NotFound`, the caller will need to handle the default behavior.
    ///
    /// TODO: Just put the default struct in the `ConfigFile`? It would make
    /// `ConfigFile` generic, but maybe that's fine? If we go down this path, we
    /// should definitely move `ConfigFile` from `factor-error` to
    /// `factor-core`.
    #[must_use]
    pub fn get_path(&self) -> Option<&Path> {
        match self {
            ConfigFile::Default { path } => Some(path),
            ConfigFile::Configured { configured } => Some(&configured.at),
            ConfigFile::NotFound { default } => Some(default),
        }
    }

    pub fn default(path: impl Into<PathBuf>) -> Self {
        Self::Default { path: path.into() }
    }

    pub fn none(with_default: impl Into<PathBuf>) -> Self {
        Self::NotFound {
            default: with_default.into(),
        }
    }

    pub fn configured(
        at: impl Into<PathBuf>,
        how: impl Into<String>,
        default: impl Into<PathBuf>,
    ) -> Self {
        Self::Configured {
            configured: ConfiguredConfigFile {
                how: how.into(),
                at: at.into(),
                default: default.into(),
            },
        }
    }

    fn into_default_path(self) -> PathBuf {
        match self {
            ConfigFile::Default { path } => path,
            ConfigFile::Configured { configured } => configured.default,
            ConfigFile::NotFound { default } => default,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfiguredConfigFile {
    /// How the configuration file was specified. For example, on the command
    /// line with the `-c` flag.
    pub how: String,
    /// The path to the configuration file.
    pub at: PathBuf,
    /// The default configuration file.
    pub default: PathBuf,
}

/// `ConfigPointer` is a pointer to a specific part of a configuration file
/// where an error occurred.
#[derive(Debug, Clone, From)]
pub enum ConfigPointer {
    #[from(String, &str)]
    Key { key: String },

    #[from(ConfigRoot)]
    Root,
}

#[derive(Debug, Clone)]
pub struct ConfigRoot;

/// `ConfigErrorReason` describes the reason for an error in configuration.
///
/// `ConfigError::Missing` means the expected value was not found.
///
/// `ConfigError::Mismatch` means the expected value was found, but the actual
/// value was different.
#[derive(Debug, Clone)]
pub enum ConfigErrorReason {
    Missing {
        expected: ExpectedValue,
    },
    Mismatch {
        expected: ExpectedValue,
        actual: ActualValue,
    },
}

#[derive(Debug, Clone, From, Display)]
pub enum ExpectedValue {
    #[display("one of {}", _0.iter().map(|s| format!("`{s}`")).collect::<Vec<_>>().join(", "))]
    Enum(Vec<String>),
    #[display("{_0}")]
    #[from(String, &str)]
    Kind(String),
}

/// `ActualValue` describes the actual value found in the configuration.
#[derive(Debug, Clone, From, Display)]
pub enum ActualValue {
    String(String),
}
