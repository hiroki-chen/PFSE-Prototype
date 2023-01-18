use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    time::{Duration, Instant},
};

use chrono::Local;
use fse::{
    db::{Connector, Data},
    fse::BaseCrypto,
    native::ContextNative,
    util::read_csv_multiple,
};
use log::{debug, info, warn};
use rand::{distributions::Uniform, prelude::Distribution, seq::SliceRandom};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::{
    config::{FSEType, PerfConfig, PerfType},
    Args, Result,
};

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "snake_case")]
struct MainResult {
    latency: String,
    column_name: String,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "snake_case")]
struct PerfResult {
    result: MainResult,
    config: PerfConfig,
}

/// Execute the performance evaluation given the CLI arguments.
/// Criterion has some weird issues when we want to filter benchmark groups.
pub fn execute_perf(args: &Args) -> Result<()> {
    let mut file = File::open(&args.config_path)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;

    let date = Local::now();
    let mut test_suites =
        toml::from_slice::<HashMap<String, Vec<PerfConfig>>>(&content)?
            .remove("test_suites")
            .unwrap();
    test_suites.truncate(args.suite_num.unwrap_or(test_suites.len()));

    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(format!("{}/perf_{:?}.toml", args.output_path, date))?;

    for (idx, config) in test_suites.into_iter().enumerate() {
        info!("#{:<04}: Doing perf evaluations...", idx + 1,);
        debug!("The configuration is {:#?}", config);

        if config.attributes.is_none() {
            return Err("Unsupported feature for `all`...".into());
        }

        let mut dataset = read_csv_multiple(
            &config.data_path,
            config.attributes.as_ref().unwrap().as_slice(),
        )?;

        if config.shuffle {
            dataset.iter_mut().for_each(|v| v.shuffle(&mut OsRng));
        }
        info!("Dataset read finished.");

        for (idx, &latency) in
            do_perf(args.round, &config, &dataset)?.iter().enumerate()
        {
            let column_name = config
                .attributes
                .as_ref()
                .unwrap()
                .get(idx)
                .unwrap()
                .clone();
            let result = PerfResult {
                config: config.clone(),
                result: MainResult {
                    latency: format!("{:?}", latency),
                    column_name,
                },
            };
            // Store the attack result.
            let mut toml = HashMap::new();
            toml.insert("perf_result".to_string(), vec![result]);
            let content = toml::to_vec(&toml)?;
            file.write_all(content.as_slice())?;
            file.write_all(b"\n")?;
        }
    }

    Ok(())
}

fn do_perf(
    round: usize,
    config: &PerfConfig,
    dataset: &[Vec<String>],
) -> Result<Vec<Duration>> {
    let mut res = Vec::new();

    for data in dataset.iter() {
        let mut duration = Duration::new(0, 0);
        for idx in 1..=round {
            info!("Round #{:<04} started.", idx);

            duration += match config.perf_type {
                PerfType::Init => do_init(config, data),
                PerfType::Insert => do_insert(config, data),
                PerfType::Query => do_query(config, data),
            }?;

            info!("Round #{:<04} finished.", idx);
        }
        duration /= round as u32;

        warn!(
            "[+] Perf {:?} finished against {:?}. Estimated latency is {:?}.",
            config.perf_type, config.fse_type, duration
        );

        res.push(duration);
    }

    Ok(res)
}

fn do_init(config: &PerfConfig, dataset: &[String]) -> Result<Duration> {
    let instant = Instant::now();
    match config.fse_type {
        FSEType::Dte | FSEType::Rnd => init_native(config, dataset),
        FSEType::LpfseIhbe | FSEType::LpfseBhe => init_lpfse(config, dataset),
        FSEType::Pfse => init_pfse(config, dataset),
    }?;
    Ok(instant.elapsed())
}

fn do_insert(config: &PerfConfig, dataset: &[String]) -> Result<Duration> {
    let (data, ctx) = match config.fse_type {
        FSEType::Dte | FSEType::Rnd => init_native(config, dataset),
        FSEType::LpfseIhbe | FSEType::LpfseBhe => init_lpfse(config, dataset),
        FSEType::Pfse => init_pfse(config, dataset),
    }?;
    let instant = Instant::now();
    insert(ctx.get_conn(), &data, &format!("{:?}", config.fse_type))?;
    Ok(instant.elapsed())
}

fn do_query(config: &PerfConfig, dataset: &[String]) -> Result<Duration> {
    let (data, mut ctx) = match config.fse_type {
        FSEType::Dte | FSEType::Rnd => init_native(config, dataset),
        FSEType::LpfseIhbe | FSEType::LpfseBhe => init_lpfse(config, dataset),
        FSEType::Pfse => init_pfse(config, dataset),
    }?;
    let name = format!("{:?}", config.fse_type);
    insert(ctx.get_conn(), &data, &name)?;

    let instant = Instant::now();
    for _ in 0..10 {
        let idx = Uniform::new(0, dataset.len()).sample(&mut OsRng);
        query(ctx.as_mut(), &dataset[idx], &name)?;
    }
    Ok(instant.elapsed() / 10)
}

fn init_native(
    config: &PerfConfig,
    dataset: &[String],
) -> Result<(Vec<String>, Box<dyn BaseCrypto<String>>)> {
    let rnd = config.fse_type == FSEType::Rnd;
    let mut ctx = ContextNative::new(rnd);
    ctx.key_generate();
    let ciphertexts = dataset
        .iter()
        .map(|message| {
            let ciphertext = ctx.encrypt(message).unwrap().remove(0);
            String::from_utf8(ciphertext).unwrap()
        })
        .collect::<Vec<_>>();

    if let (Some(addr), Some(name)) = (&config.addr, &config.db_name) {
        ctx.initialize_conn(addr, name, config.drop);
    }

    Ok((ciphertexts, Box::new(ctx)))
}

fn init_pfse(
    config: &PerfConfig,
    dataset: &[String],
) -> Result<(Vec<String>, Box<dyn BaseCrypto<String>>)> {
    todo!();
}

fn init_lpfse(
    config: &PerfConfig,
    dataset: &[String],
) -> Result<(Vec<String>, Box<dyn BaseCrypto<String>>)> {
    todo!();
}

fn insert(
    conn: &Connector<Data>,
    dataset: &[String],
    collection_name: &str,
) -> Result<()> {
    let docs = dataset
        .into_iter()
        .map(|data| Data { data: data.clone() })
        .collect::<Vec<_>>();
    conn.insert(docs, collection_name)?;

    Ok(())
}

fn query(
    ctx: &mut dyn BaseCrypto<String>,
    message: &String,
    name: &String,
) -> Result<()> {
    ctx.search(message, name);

    Ok(())
}
