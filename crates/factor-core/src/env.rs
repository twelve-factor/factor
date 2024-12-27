use std::{borrow::Cow, env::var};

use factor_error::{prelude::*, FactorResult};

/// # Errors
///
/// Returns `anyhow::Error` if:
///
/// - The environment variable (`__REF__{key}`) doesn't exist
/// - The input string has invalid syntax (e.g., unclosed `${` braces)
pub fn expand(input: &str) -> FactorResult<String> {
    let expanded =
        shellexpand::env_with_context(input, |key| Ok(Some(var(key)?))).context(EnvVarSnafu)?;

    Ok(Cow::into_owned(expanded))
}
