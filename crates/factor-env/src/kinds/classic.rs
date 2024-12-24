use derive_more::derive::{Display, From, Into};

use crate::{
    detection::{ConfigVarValue, ParsedVar, RawConfigVar, TryParseVar},
    state::VarState,
};

#[derive(Debug, From, Into, Display)]
pub struct ClassicEnvVar(String);

impl ConfigVarValue<String> for ClassicEnvVar {
    fn get(&self) -> String {
        self.0.clone()
    }

    fn serialize(&self) -> String {
        self.0.clone()
    }
}

#[derive(Debug)]
pub struct DetectClassicEnvVar;

impl TryParseVar<String> for DetectClassicEnvVar {
    fn get(
        &self,
        _state: &VarState,
        RawConfigVar { name, value }: &RawConfigVar,
    ) -> Option<ParsedVar<String>> {
        Some(ParsedVar {
            name: name.clone(),
            value: Box::new(ClassicEnvVar(value.clone())),
        })
    }
}
