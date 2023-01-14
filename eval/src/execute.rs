use std::{collections::HashMap, fs::File, hash::Hash, io::Read};

use fse::{
    attack::{AttackType, LpAttacker, MLEAttacker},
    fse::{BaseCrypto, ValueType},
    native::ContextNative,
    util::{compute_ciphertext_weight, read_csv_multiple},
};
use log::{info, warn};
use serde::Deserialize;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// A struct that contains the metadata for the attack.
#[derive(Debug)]
struct AttackMeta<T>
where
    T: Eq + Hash,
{
    correct: HashMap<T, Vec<Vec<u8>>>,
    local_table: HashMap<T, Vec<ValueType>>,
    raw_ciphertexts: Vec<Vec<u8>>,
    ciphertext_weight: HashMap<Vec<u8>, f64>,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FSEType {
    Dte,
    Rnd,
    LpfseIhbe,
    /// Currently, we do not support it.
    LpfseBhe,
    Pfse,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
struct Config {
    fse_type: FSEType,
    attack_type: AttackType,
    data_path: String,
    /// None ==> all attributes.
    attributes: Option<Vec<String>>,
    fse_params: Option<Vec<f64>>,
    p_norm: Option<u8>,
    size: Option<usize>,
}

/// Execute the attack given the CLI arguments.
pub fn execute_attack(config_path: &str) -> Result<()> {
    // Parse the toml.
    let mut file = File::open(config_path)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;
    let config = toml::from_slice::<Config>(&content)?;

    if config.attributes.is_none() {
        return Err("Unsupported feature for `all`...".into());
    }

    let dataset = read_csv_multiple(
        &config.data_path,
        config.attributes.as_ref().unwrap().as_slice(),
    )?;

    do_attack(&config, &dataset)
}

fn do_attack(config: &Config, dataset: &[Vec<String>]) -> Result<()> {
    for data in dataset.iter() {
        let rate = match config.attack_type {
            AttackType::LpOptimization => lp_optimization(config, data)?,
            AttackType::MleAttack => mle_attack(config, data)?,
        };

        warn!(
            "[+] Attack {:?} finished against {:?}. The accuracy is {}.",
            config.attack_type, config.fse_type, rate
        );
    }

    Ok(())
}

fn mle_attack(config: &Config, data: &[String]) -> Result<f64> {
    let meta = collect_meta(config, data)?;

    let mut attacker = MLEAttacker::new();
    Ok(attacker.attack(
        &meta.correct,
        &meta.local_table,
        &meta.raw_ciphertexts,
        &meta.ciphertext_weight,
    ))
}

fn lp_optimization(config: &Config, data: &[String]) -> Result<f64> {
    let meta = collect_meta(config, data)?;

    let p_norm = match config.p_norm {
        Some(p) => p,
        None => return Err("No p_norm found. Check configuration file.".into()),
    };
    let mut attacker = LpAttacker::new(p_norm as usize);
    Ok(attacker.attack(
        &meta.correct,
        &meta.local_table,
        &meta.raw_ciphertexts,
        &meta.ciphertext_weight,
    ))
}

fn collect_meta(
    config: &Config,
    data: &[String],
) -> Result<AttackMeta<String>> {
    let size = config.size.unwrap_or(data.len());

    match config.fse_type {
        FSEType::Dte | FSEType::Rnd => {
            collect_meta_native(&config.fse_type, &data[..size])
        }

        _ => {
            todo!()
        }
    }
}

fn collect_meta_native(
    fse_type: &FSEType,
    data: &[String],
) -> Result<AttackMeta<String>> {
    let rnd = (*fse_type == FSEType::Rnd);
    let mut ctx = ContextNative::new(rnd);
    ctx.key_generate();

    let mut raw_ciphertexts = Vec::new();
    let mut ciphertext_sets = Vec::new();
    let mut correct = HashMap::new();
    let mut local_table = HashMap::new();

    for message in data.iter() {
        let mut ciphertext = match ctx.encrypt(message) {
            Some(c) => c,
            None => {
                return Err(
                    "Error encrypting the message using native method.".into()
                )
            }
        };
        raw_ciphertexts.append(&mut ciphertext.clone());
        ciphertext_sets.push(ciphertext.clone());
        let entry = correct
            .entry(message.clone())
            .or_insert_with(|| ciphertext.clone());
        entry.dedup();
        let entry = local_table
            .entry(message.clone())
            .or_insert_with(|| vec![(0usize, 0usize, 0usize)]);
        entry[0].2 += 1;

        if rnd {
            entry[0].1 += 1;
        } else {
            entry[0].1 = 1;
        }
    }

    ciphertext_sets.dedup();
    Ok(AttackMeta {
        correct,
        local_table,
        raw_ciphertexts,
        ciphertext_weight: compute_ciphertext_weight(&ciphertext_sets),
    })
}
