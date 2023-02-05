use fse::attack::AttackType;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum FSEType {
    Dte,
    Rnd,
    LpfseIhbe,
    /// Currently, we do not support it.
    LpfseBhe,
    Pfse,
    Wre,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum PerfType {
    Init,
    Query,
    Insert,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum DatasetType {
    Real,
    Zipf,
    Normal,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct AttackConfig {
    pub fse_type: FSEType,
    pub attack_type: AttackType,
    pub data_path: String,
    pub shuffle: bool,
    /// None ==> all attributes.
    pub attributes: Option<Vec<String>>,
    pub fse_params: Option<Vec<f64>>,
    pub p_norm: Option<u8>,
    pub size: Option<usize>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct PerfConfig {
    pub dataset_type: DatasetType,
    pub perf_type: PerfType,
    pub fse_type: FSEType,
    pub data_path: Option<String>,
    pub shuffle: bool,
    pub attributes: Option<Vec<String>>,
    pub fse_params: Option<Vec<f64>>,
    /// Used to generate synthetic datasets.
    /// Format: [<domain>, <dist_param>]
    pub data_params: Option<Vec<f64>>,
    pub size: Option<usize>,
    pub addr: Option<String>,
    pub db_name: Option<String>,
    pub drop: bool,
}
