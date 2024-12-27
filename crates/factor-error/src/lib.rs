use derive_more::derive::{Display, From};
use snafu::{Location, Snafu};

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum FactorError
where
    Self: Send,
{
    #[snafu(transparent)]
    Expected { source: ExpectedError },

    #[snafu(transparent)]
    Unknown { source: UnknownError },

    #[snafu(transparent)]
    Unexpected { source: UnexpectedError },
}

#[derive(Debug, Display)]
pub enum ConfigSource {
    #[display("app config (.factor-app)")]
    App,
    #[display("{name} provider config")]
    Provider { name: String },
    #[display("global config (~/.factor)")]
    GlobalConfig,
}

impl ConfigSource {
    pub const GLOBAL: ConfigSource = ConfigSource::GlobalConfig;

    pub fn provider(name: impl AsRef<str>) -> Self {
        ConfigSource::Provider {
            name: name.as_ref().to_string(),
        }
    }
}

/// Expected errors are caused by a problem with the user's configuration or
/// system, and are definitely **not** bugs in our code.
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum ExpectedError {
    StdEnvVarError {
        source: std::env::VarError,
    },

    ShellexpandError {
        source: shellexpand::LookupError<std::env::VarError>,
    },

    EnvVarError {},

    MissingConfigError {
        config: ConfigSource,
        at: ConfigLocation,
        #[snafu(implicit)]
        location: Location,
    },

    MissingHomeDir {
        #[snafu(implicit)]
        location: Location,
    },

    IoError {
        reason: String,
        source: std::io::Error,
    },

    GenericError {
        reason: String,
    },

    TomlError {
        source: toml::de::Error,
    },

    KubeConfigError {
        source: kube::config::KubeconfigError,
    },

    KubeClientError {
        source: kube::Error,
    },
    JwtError {
        source: jsonwebtoken::errors::Error,
    },

    Base64Error {
        source: base64::DecodeError,
    },

    ReqwestError {
        source: reqwest::Error,
    },
}

#[derive(Debug, From)]
pub enum ConfigLocation {
    #[from(String, &str)]
    Key(String),

    #[from((String, String), (&str, &str))]
    Expected { key: String, expected: String },
}

/// Unknown errors need to be reported to users, since we're not sure whether
/// they reflect user errors or not, but we don't know enough about them to
/// give them a user-friendly error message.
///
/// As a result, they should be reported using the "Unknown error" treatment.
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum UnknownError {
    RsaError {
        source: rsa::errors::Error,
    },
    CryptoError {
        source: rsa::pkcs1::Error,
    },
    KubeClientProtocolError {
        message: String,
    },

    GenericError {
        message: String,
        #[snafu(implicit)]
        location: Location,
    },
}

/// Unexpected errors are not expected to occur in normal usage, and reflect
/// situations that **could** have been unwrapped, but we'd rather be sure
/// and report them using "Unexpected error" treatment if they **do** occur
/// so we can help users report the message as a bug.
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum UnexpectedError {
    JsonError { source: serde_json::Error },
    TokioError { source: std::io::Error },
}

pub type FactorResult<T> = std::result::Result<T, FactorError>;

#[derive(Debug, Snafu)]
pub enum UserError {}

pub mod prelude {
    pub use error_stack::{FutureExt, ResultExt};
    pub use snafu::prelude::*;

    pub use super::{
        expected_error::*, unexpected_error::*, unknown_error::*, FactorError, FactorResult,
        UserError,
    };
}
