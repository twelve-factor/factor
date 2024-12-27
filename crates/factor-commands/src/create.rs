use clap::Parser;
use factor_core::IdProvider;

#[derive(Parser)]
pub struct Create {
    /// Application name
    #[arg(long, required = true)]
    pub app: String,

    /// Path for dynamic env var storage
    #[arg(long, default_value = ".")]
    pub path: String,

    /// Identity provider to use
    #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(IdProvider::variants()))]
    pub id_provider: Option<String>,

    /// Target ID and audience for the identity token
    #[arg(long = "id-target", action = clap::ArgAction::Append, value_parser = parse_target::<String, String>)]
    pub id_targets: Vec<(String, String)>,
}

/// # Errors
///
/// This function is infallible, but `parse_target` returns a Result for
/// compatibility with the `clap::value_parser!` macro
#[allow(clippy::unnecessary_wraps)]
pub fn parse_target<T, U>(s: &str) -> Result<(T, U), String>
where
    T: From<String> + AsRef<str>,
    U: From<String> + AsRef<str>,
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
