mod env;
mod fs;
mod http;

#[cfg(feature = "mock")]
mod mock;

use env::Vars;
use http::HttpClient;
use vfs::PhysicalFS;

#[derive(Debug)]
pub struct SharedVarState {
    /// The raw [`Vars`] that should be used to resolve and parse config vars.
    vars: Vars,
    /// A representation of the file system that could be used if the raw
    /// environment variable contains a reference to a file.
    fs: Box<dyn vfs::FileSystem>,

    http: Box<dyn HttpClient>,
}

// pub struct

impl SharedVarState {
    #[cfg(feature = "physical")]
    pub fn physical() -> SharedVarState {
        Self {
            vars: Vars::physical(),
            fs: Box::new(PhysicalFS::new("/")),
            http: Box::new(reqwest::Client::new()),
        }
    }

    pub(crate) fn borrow(&self) -> VarState {
        VarState {
            vars: &self.vars,
            fs: &*self.fs,
            http: &*self.http,
        }
    }

    pub fn new(
        vars: impl Into<Vars>,
        fs: impl vfs::FileSystem,
        http: impl HttpClient + 'static,
    ) -> Self {
        Self {
            vars: vars.into(),
            fs: Box::new(fs),
            http: Box::new(http),
        }
    }
}

impl SharedVarState {
    /// Returns the raw [`Vars`] that should be used to resolve and
    /// parse config vars.
    pub fn env(&self) -> &Vars {
        &self.vars
    }
}

#[derive(Debug)]
pub struct VarState<'a> {
    vars: &'a Vars,
    fs: &'a dyn vfs::FileSystem,
    http: &'a dyn HttpClient,
}
