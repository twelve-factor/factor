use derive_more::derive::{From, Into};
use derive_new::new;

use crate::state::VarState;

#[derive(Debug, From, Into, new)]
pub struct ConfigVars<V> {
    kinds: Vec<Box<dyn TryParseVar<V>>>,
}

impl<V> ConfigVars<V> {
    pub fn detect(&self, state: &VarState, var: &RawConfigVar) -> Option<ParsedVar<V>> {
        for kind in &self.kinds {
            if let Some(parsed) = kind.get(state, var) {
                return Some(parsed);
            }
        }
        None
    }

    pub fn add(mut self, kind: impl TryParseVar<V> + 'static) -> Self {
        self.kinds.push(Box::new(kind));
        self
    }
}

/// A `ConfigVarValue` is the deserialized value of a config var
///
pub trait ConfigVarValue<Value>: std::fmt::Debug {
    fn get(&self) -> Value;
    fn serialize(&self) -> String;

    /// If a config var value has an expiration, then it should return
    /// `false` if the value has expired. This value should no longer
    /// be used, and it should be refreshed from the [`ConfigVars`].
    fn is_valid(&self) -> bool {
        true
    }
}

/// RawConfigVar is a tuple of (name, value)
///
/// If a kind of config var uses a part of the name or value to encode some
/// information, then the config var implementation should remove the extra
/// information from the `RawConfigVar`.
///
/// For example, if a `FileRef` config var stores its values under
/// `__FILEREF__<varname>`, then the `FileRef` config var implementation
/// should return a `RawConfigVar` with the `name` field set to `<varname>`.
///
/// Alternatively, if a `FileRef` config var is represented with a value
/// that looks like `%value{filepath}`, then the `FileRef` config var
/// implementation should return a `RawConfigVar` with the `value` field
/// set to `<filepath>`.
#[derive(Debug, From, Into)]
pub struct ParsedVar<T> {
    pub name: String,
    pub value: Box<dyn ConfigVarValue<T> + 'static>,
}

/// `RawConfigVar` contains the name and value of a config var
/// that came from the environment.
///
/// The name and value may contain additional encoding information
/// that would be processed by a special `ConfigVarValue` implementation.
///
///
/// The `TryParseVar` trait attempts to convert a `RawConfigVar` into
/// a `ParsedConfigVar`.
#[derive(Debug, From, Into)]
pub struct RawConfigVar {
    pub name: String,
    pub value: String,
}

/// The `ParseVar` trait determines whether a config var loaded from the
/// environment is supported by its associated `ConfigVarValue` implementation.
///
/// If a config var is supported, then the `TryParseVar` trait returns a
/// [`ParsedVar`] containing the implementation of the `ConfigVarValue`.
pub trait TryParseVar<T>: std::fmt::Debug {
    fn get(&self, state: &VarState, var: &RawConfigVar) -> Option<ParsedVar<T>>;
}
