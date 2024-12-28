pub mod env;
pub mod identity;
pub mod providers;

use derive_new::new;
use factor_error::sources::ConfigLocation;
pub use identity::IdProvider;

#[derive(Debug, Clone, new)]
pub struct Config<T> {
    config: T,
    #[new(into)]
    pub location: ConfigLocation,
}

impl<T> std::ops::Deref for Config<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.config
    }
}

impl<T> std::ops::DerefMut for Config<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.config
    }
}
