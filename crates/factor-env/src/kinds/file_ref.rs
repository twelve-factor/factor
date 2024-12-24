use std::path::PathBuf;

use derive_more::derive::{Display, From, Into};
use serde::Deserialize;

use crate::{
    detection::{ConfigVarValue, RawConfigVar, TryParseVar},
    state::VarState,
};

#[derive(Debug, From, Into, Display)]
#[display("{}", _0.display())]
pub struct FileRef(PathBuf);

impl ConfigVarValue for FileRef {
    type Value = PathBuf;

    fn parse(&self) -> Self::Value {
        todo!()
    }

    fn serialize(&self) -> String {
        todo!()
    }
}

#[derive(Debug)]
pub struct DetectFileRef;

impl<T> TryParseVar<T> for DetectFileRef
where
    T: for<'a> Deserialize<'a>,
{
    fn get(&self, state: &VarState, var: &RawConfigVar) -> Option<crate::detection::ParsedVar<T>> {
        todo!()
    }
}
