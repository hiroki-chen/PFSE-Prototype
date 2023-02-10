use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    hash::Hash,
    io::{Read, Write},
};

use chrono::Local;
use fse::{
    attack::{AttackType, LpAttacker, MLEAttacker},
    fse::{exponential, BaseCrypto, PartitionFrequencySmoothing, ValueType},
    lpfse::{ContextLPFSE, EncoderBHE, EncoderIHBE, HomophoneEncoder},
    native::ContextNative,
    pfse::ContextPFSE,
    util::read_csv_multiple,
};
use itertools::Itertools;
use log::{debug, info, warn};
use rand::seq::SliceRandom;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::{
    config::{AttackConfig, FSEType},
    Args, Result,
};

/// A struct that contains the metadata for the attack.
#[derive(Debug)]
struct AttackMeta<T>
where
    T: Eq + Hash,
{
    correct: HashMap<T, Vec<Vec<u8>>>,
    local_table: HashMap<T, Vec<ValueType>>,
    raw_ciphertexts: Vec<Vec<u8>>,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "snake_case")]
struct MainResult {
    accuracy: f64,
    column_name: String,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "snake_case")]
struct AttackResult {
    result: MainResult,
    config: AttackConfig,
}

/// Execute the attack given the CLI arguments.
pub fn execute_attack(args: &Args) -> Result<()> {
    // Parse the toml.
    let mut file = File::open(&args.config_path)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;

    let mut test_suites =
        toml::from_slice::<HashMap<String, Vec<AttackConfig>>>(&content)?
            .remove("test_suites")
            .unwrap();
    test_suites.truncate(args.suite_num.unwrap_or(test_suites.len()));

    let mut file = match args.output_path.as_ref() {
        Some(path) => OpenOptions::new().append(true).create(true).open(path),
        None => {
            let date = Local::now();
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(format!("./perf_{:?}.toml", date))
        }
    }?;

    for (idx, config) in test_suites.into_iter().enumerate() {
        info!("#{:<04}: Doing attack evaluations...", idx + 1,);
        debug!("The configuration is {:#?}", config);

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

        for (idx, &accuracy) in
            do_attack(args.round, &config, &dataset)?.iter().enumerate()
        {
            let column_name = config
                .attributes
                .as_ref()
                .unwrap()
                .get(idx)
                .unwrap()
                .clone();
            let result = AttackResult {
                config: config.clone(),
                result: MainResult {
                    column_name,
                    accuracy,
                },
            };

            // Store the attack result.
            let mut toml = HashMap::new();
            toml.insert("attack_result".to_string(), vec![result]);
            let content = toml::to_vec(&toml)?;
            file.write_all(content.as_slice())?;
            file.write_all(b"\n")?;
        }
    }

    Ok(())
}

fn do_attack(
    round: usize,
    config: &AttackConfig,
    dataset: &[Vec<String>],
) -> Result<Vec<f64>> {
    let mut res = Vec::new();

    for data in dataset.iter() {
        let mut accuracy = 0f64;
        // Run multiple rounds.
        for idx in 1..=round {
            info!("Round #{:<04} started.", idx);
            accuracy += match config.attack_type {
                AttackType::LpOptimization => lp_optimization(config, data)?,
                AttackType::MleAttack => mle_attack(config, data)?,
            };
            info!("Round #{:<04} finished.", idx);
        }
        accuracy /= round as f64;

        warn!(
            "[+] Attack {:?} finished against {:?}. The accuracy is {}.",
            config.attack_type, &config.fse_type, accuracy
        );

        res.push(accuracy);
    }

    Ok(res)
}

fn mle_attack(config: &AttackConfig, data: &[String]) -> Result<f64> {
    let meta = collect_meta(config, data)?;

    info!("Mounting mle_attack...");
    let mut attacker = MLEAttacker::new();
    Ok(
        attacker.attack(
            &meta.correct,
            &meta.local_table,
            &meta.raw_ciphertexts,
        ),
    )
}

fn lp_optimization(config: &AttackConfig, data: &[String]) -> Result<f64> {
    let meta = collect_meta(config, data)?;

    let p_norm = match config.p_norm {
        Some(p) => p,
        None => return Err("No p_norm found. Check configuration file.".into()),
    };

    info!("Mounting l{}_optimization attack...", p_norm);
    let mut attacker = LpAttacker::new(p_norm as usize);
    Ok(
        attacker.attack(
            &meta.correct,
            &meta.local_table,
            &meta.raw_ciphertexts,
        ),
    )
}

fn collect_meta(
    config: &AttackConfig,
    data: &[String],
) -> Result<AttackMeta<String>> {
    let size = config.size.unwrap_or(data.len()).min(data.len());
    let data_slice = &data[..size];
    let meta = match config.fse_type {
        FSEType::Dte | FSEType::Rnd => collect_meta_native(config, data_slice),
        FSEType::Pfse => collect_meta_pfse(config, data_slice),
        FSEType::LpfseBhe | FSEType::LpfseIhbe => {
            collect_meta_lpfse(config, data_slice)
        }
        FSEType::Wre => todo!(),
    };

    info!("Meta collected.");
    meta
}

fn collect_meta_lpfse(
    config: &AttackConfig,
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

    let mut ciphertext_sets = HashMap::new();
    let mut raw_ciphertexts = Vec::new();
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
    })
}

fn collect_meta_pfse(
    config: &AttackConfig,
    data: &[String],
) -> Result<AttackMeta<String>> {
    let params = match &config.fse_params {
        Some(params) => params,
        None => return Err("Parameter not found.".into()),
    };

    let mut ctx = ContextPFSE::default();
    ctx.key_generate();
    ctx.set_params(params);

    ctx.partition(data, exponential);
    info!("Partition finished.");

    ctx.transform();
    info!("Transform finished.");

    let mut ciphertext_sets = HashMap::new();
    for message in data.iter().unique() {
        let mut ciphertext = ctx.encrypt(message).unwrap();
        ciphertext_sets
            .entry(message.clone())
            .or_insert_with(Vec::new)
            .append(&mut ciphertext);
    }

    let mut correct = HashMap::new();
    let mut raw_ciphertexts = Vec::new();
    for (k, v) in ciphertext_sets.iter() {
        correct.insert(k.clone(), v.clone().into_iter().unique().collect_vec());
        raw_ciphertexts.append(&mut v.clone());
    }

    // Append dummies into `raw_ciphertexts`.
    for partitions in ctx.get_partitions().iter() {
        for (message, cnt) in partitions.inner.iter() {
            if !ctx.get_local_table().contains_key(message) {
                raw_ciphertexts
                    .append(&mut vec![message.clone().into_bytes(); *cnt]);
            }
        }
    }

    Ok(AttackMeta {
        correct,
        raw_ciphertexts,
        local_table: ctx.get_local_table().clone(),
    })
}

fn collect_meta_native(
    config: &AttackConfig,
    data: &[String],
) -> Result<AttackMeta<String>> {
    let rnd = config.fse_type == FSEType::Rnd;
    let mut ctx = ContextNative::new(rnd);
    ctx.key_generate();

    let mut message_to_ciphertexts = HashMap::new();
    let mut local_table = HashMap::new();

    for message in data.iter() {
        let ciphertext = match ctx.encrypt(message) {
            Some(mut c) => c.remove(0),
            None => {
                return Err(
                    "Error encrypting the message using native method.".into()
                )
            }
        };

        message_to_ciphertexts
            .entry(message.clone())
            .or_insert_with(Vec::new)
            .push(ciphertext);

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

    // Collect meta from `ciphertext_sets`.
    let mut correct = HashMap::new();
    let mut raw_ciphertexts = Vec::new();
    for (k, v) in message_to_ciphertexts.iter() {
        correct.insert(k.clone(), v.clone().into_iter().unique().collect_vec());
        raw_ciphertexts.append(&mut v.clone());
    }

    Ok(AttackMeta {
        correct,
        local_table,
        raw_ciphertexts,
    })
}
