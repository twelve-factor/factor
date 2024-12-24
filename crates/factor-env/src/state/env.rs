/// `Vars` is an immutable reflection of the raw environment variables supplied
/// by the operating system. It may not be changed, and will not update if the
/// environment is changed from within the process.
#[derive(Debug)]
pub struct Vars {
    inner: rustc_hash::FxHashMap<String, String>,
}

impl From<std::env::Vars> for Vars {
    fn from(vars: std::env::Vars) -> Self {
        Self {
            inner: vars.collect(),
        }
    }
}

impl Vars {
    #[cfg(feature = "physical")]
    pub fn physical() -> Self {
        Self::from(std::env::vars())
    }

    #[cfg(feature = "mock")]
    pub fn mock(map: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            inner: map.into_iter().collect(),
        }
    }

    pub fn has(&self, key: impl AsRef<str>) -> bool {
        self.inner.contains_key(key.as_ref())
    }

    pub fn get(&self, key: impl AsRef<str>) -> Option<&str> {
        self.inner.get(key.as_ref()).map(String::as_str)
    }
}
