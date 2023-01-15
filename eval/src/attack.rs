use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    hash::Hash,
    io::{Read, Write},
};

use chrono::{DateTime, Local};
use fse::{
    attack::{AttackType, LpAttacker, MLEAttacker},
    fse::{exponential, BaseCrypto, PartitionFrequencySmoothing, ValueType},
    lpfse::{ContextLPFSE, EncoderBHE, EncoderIHBE, HomophoneEncoder},
    native::ContextNative,
    pfse::ContextPFSE,
    util::{compute_ciphertext_weight, read_csv_multiple},
};
use itertools::{cloned, Itertools};
use log::{info, warn};
use rand::seq::SliceRandom;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

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

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
#[serde(rename_all = "snake_case")]
enum FSEType {
    Dte,
    Rnd,
    LpfseIhbe,
    /// Currently, we do not support it.
    LpfseBhe,
    Pfse,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
struct Config {
    fse_type: FSEType,
    attack_type: AttackType,
    data_path: String,
    shuffle: bool,
    /// None ==> all attributes.
    attributes: Option<Vec<String>>,
    fse_params: Option<Vec<f64>>,
    p_norm: Option<u8>,
    size: Option<usize>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
struct AttackResult {
    accuracy: f64,
    column_name: String,
    config: Config,
}

/// Execute the attack given the CLI arguments.
pub fn execute_attack(config_path: &str) -> Result<()> {
    // Parse the toml.
    let mut file = File::open(config_path)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;

    let date = Local::now();
    let test_suites =
        toml::from_slice::<HashMap<String, Vec<Config>>>(&content)?
            .remove("test_suites")
            .unwrap();
    let mut res = Vec::new();
    for (idx, config) in test_suites.into_iter().enumerate() {
        info!(
            "#{:<04}: Doing attack evaluations...\n{:#?}",
            idx + 1,
            config
        );

        if config.attributes.is_none() {
            return Err("Unsupported feature for `all`...".into());
        }

        let mut dataset = read_csv_multiple(
            &config.data_path,
            config.attributes.as_ref().unwrap().as_slice(),
        )?;

        if config.shuffle {
            dataset.iter_mut().for_each(|v| v.shuffle(&mut OsRng))
        }

        info!("Dataset read finished.");

        for (idx, &accuracy) in do_attack(&config, &dataset)?.iter().enumerate()
        {
            let column_name = config
                .attributes
                .as_ref()
                .unwrap()
                .get(idx)
                .unwrap()
                .clone();
            res.push(AttackResult {
                config: config.clone(),
                column_name,
                accuracy,
            })
        }
    }

    // Store the attack result.
    let mut f = File::create(format!("./data/attack_{:?}", date))?;
    let content = toml::to_vec(&res)?;
    Ok(f.write_all(&content)?)
}

fn do_attack(config: &Config, dataset: &[Vec<String>]) -> Result<Vec<f64>> {
    let mut res = Vec::new();

    for data in dataset.iter() {
        let accuracy = match config.attack_type {
            AttackType::LpOptimization => lp_optimization(config, data)?,
            AttackType::MleAttack => mle_attack(config, data)?,
        };

        warn!(
            "[+] Attack {:?} finished against {:?}. The accuracy is {}.",
            config.attack_type, &config.fse_type, accuracy
        );

        res.push(accuracy);
    }

    Ok(res)
}

fn mle_attack(config: &Config, data: &[String]) -> Result<f64> {
    let meta = collect_meta(config, data)?;

    info!("Mounting mle_attack...");
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

    info!("Mounting l{}_optimization attack...", p_norm);
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
    let data_slice = &data[..size];
    let meta = match config.fse_type {
        FSEType::Dte | FSEType::Rnd => collect_meta_native(config, data_slice),
        FSEType::Pfse => collect_meta_pfse(config, data_slice),
        FSEType::LpfseBhe | FSEType::LpfseIhbe => {
            collect_meta_lpfse(config, data_slice)
        }
    };

    info!("Meta collected.");
    meta
}

fn collect_meta_lpfse(
    config: &Config,
    data: &[String],
) -> Result<AttackMeta<String>> {
    let params = match &config.fse_params {
        Some(params) => params,
        None => return Err("Parameter not found.".into()),
    };

    if params.len() != 1 {
        return Err(format!(
            "Parameter size is not correct. Expect 1, but got {}.",
            params.len()
        )
        .into());
    }

    info!("Collecting meta for attack against LPFSE scheme...");

    let encoder: Box<dyn HomophoneEncoder<String>> = match config.fse_type {
        FSEType::LpfseIhbe => Box::new(EncoderIHBE::new()),
        FSEType::LpfseBhe => Box::new(EncoderBHE::new()),
        _ => return Err("Not an LPFSE type.".into()),
    };
    let mut ctx = ContextLPFSE::new(params[0], encoder);
    ctx.key_generate();
    ctx.initialize(data, "", "", false);

    let mut raw_ciphertexts = Vec::new();
    let mut ciphertext_sets = HashMap::new();

    for message in data.iter() {
        let ciphertext = ctx.encrypt(message).unwrap().remove(0);
        let entry = ciphertext_sets
            .entry(message.clone())
            .or_insert_with(Vec::new);
        entry.push(ciphertext.clone());
        raw_ciphertexts.push(ciphertext);
    }

    // Construct the local table.
    let mut correct = HashMap::new();
    let local_table = {
        let mut local_table = HashMap::new();
        for (message, count) in ctx.get_encoder().local_table().iter() {
            let ciphertexts = match ciphertext_sets.get(message) {
                Some(v) => v.iter().unique().cloned().collect::<Vec<_>>(),
                None => {
                    return Err(
                        "Message not found in the ciphertext sets map.".into()
                    )
                }
            };

            let size = ciphertexts.len();
            correct.insert(message.clone(), ciphertexts);
            local_table.insert(message.clone(), vec![(0, size, *count)]);
        }

        local_table
    };

    Ok(AttackMeta {
        correct,
        local_table,
        raw_ciphertexts,
        ciphertext_weight: compute_ciphertext_weight(
            ciphertext_sets
                .into_iter()
                .map(|(k, v)| v)
                .collect::<Vec<_>>()
                .as_slice(),
        ),
    })
}

fn collect_meta_pfse(
    config: &Config,
    data: &[String],
) -> Result<AttackMeta<String>> {
    let params = match &config.fse_params {
        Some(params) => params,
        None => return Err("Parameter not found.".into()),
    };

    if params.len() != 3 {
        return Err(format!(
            "Parameter size is not correct. Expect 3, but got {}.",
            params.len()
        )
        .into());
    }

    let mut ctx = ContextPFSE::default();
    ctx.key_generate();
    ctx.set_params(params[0], params[1], params[2]);

    ctx.partition(data, &exponential);
    info!("Partition finished.");

    ctx.transform();
    info!("Transform finished.");

    let mut raw_ciphertexts = Vec::new();
    let mut ciphertext_sets = Vec::new();
    let mut correct = HashMap::new();

    for message in data.iter().dedup() {
        let mut ciphertext = ctx.encrypt(message).unwrap();
        correct.insert(message.clone(), {
            ciphertext.clone().into_iter().dedup().collect::<Vec<_>>()
        });
        ciphertext_sets.push(ciphertext.clone());
        raw_ciphertexts.append(&mut ciphertext);
    }

    Ok(AttackMeta {
        correct,
        raw_ciphertexts,
        local_table: ctx.get_local_table().clone(),
        ciphertext_weight: compute_ciphertext_weight(&ciphertext_sets),
    })
}

fn collect_meta_native(
    config: &Config,
    data: &[String],
) -> Result<AttackMeta<String>> {
    let rnd = (config.fse_type == FSEType::Rnd);
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
        correct
            .entry(message.clone())
            .or_insert_with(|| ciphertext.clone())
            .iter_mut()
            .dedup();
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

    Ok(AttackMeta {
        correct,
        local_table,
        raw_ciphertexts,
        ciphertext_weight: compute_ciphertext_weight(&ciphertext_sets),
    })
}