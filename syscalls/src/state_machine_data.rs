use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct StateMachineData {
    pub binary: String,
    pub data: HashMap<String, Vec<String>>,
}
