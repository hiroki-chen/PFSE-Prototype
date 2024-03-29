use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    time::{Duration, Instant},
};

use chrono::Local;
use fse::{
    db::{Connector, Data},
    fse::{exponential, BaseCrypto, PartitionFrequencySmoothing, Random},
    lpfse::{ContextLPFSE, EncoderBHE, EncoderIHBE, HomophoneEncoder},
    native::ContextNative,
    pfse::ContextPFSE,
    util::{
        generate_synthetic_normal, generate_synthetic_zipf, read_csv_multiple,
    },
};
use log::{debug, info, warn};
use rand::{distributions::Uniform, prelude::Distribution, seq::SliceRandom};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::{
    config::{DatasetType, FSEType, PerfConfig, PerfType},
    Args, Result,
};

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "snake_case")]
struct MainResult {
    latency: String,
    client_storage: usize,
    server_storage: usize,
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

    let mut test_suites =
        toml::from_slice::<HashMap<String, Vec<PerfConfig>>>(&content)?
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
        info!("#{:<04}: Doing perf evaluations...", idx + 1,);
        debug!("The configuration is {:#?}", config);

        let dataset = match config.dataset_type {
            DatasetType::Real => {
                if config.attributes.is_none() {
                    return Err("Unsupported feature for `all`...".into());
                }

                let mut dataset = read_csv_multiple(
                    config.data_path.as_ref().unwrap(),
                    config.attributes.as_ref().unwrap().as_slice(),
                )?;

                if config.shuffle {
                    dataset.iter_mut().for_each(|v| v.shuffle(&mut OsRng));
                }
                dataset
            }

            ty => {
                let params = config.data_params.as_ref().unwrap();
                let domain = params[0] as usize;
                let support = (0..domain)
                    .into_iter()
                    .map(|_| String::random(32))
                    .collect::<Vec<_>>();
                let dataset = match ty == DatasetType::Normal {
                    true => generate_synthetic_normal(
                        &support,
                        params[1] as usize,
                        params[2],
                    ),
                    false => generate_synthetic_zipf(&support, params[1]),
                };

                vec![dataset]
            }
        };

        info!("Dataset read finished.");

        for (idx, &res) in
            do_perf(args.round, &config, &dataset)?.iter().enumerate()
        {
            let column_name = match config.dataset_type {
                DatasetType::Real => config
                    .attributes
                    .as_ref()
                    .unwrap()
                    .get(idx)
                    .unwrap()
                    .clone(),
                ty => {
                    format!("{:?}", ty)
                }
            };

            let result = PerfResult {
                config: config.clone(),
                result: MainResult {
                    latency: format!("{:?}", res.0),
                    server_storage: res.1,
                    client_storage: res.2,
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
) -> Result<Vec<(Duration, usize, usize)>> {
    let mut res = Vec::new();

    for data in dataset.iter() {
        let mut duration = Duration::new(0, 0);
        let mut server_storage = 0usize;
        let mut client_storage = 0usize;
        for idx in 1..=round {
            info!("Round #{:<04} started.", idx);

            let size = config.size.unwrap_or(data.len()).min(data.len());
            let mut data = data.clone();
            data.shuffle(&mut OsRng);
            let data_slice = &data[..size];
            let result = match config.perf_type {
                PerfType::Init => (do_init(config, data_slice), 0, 0),
                PerfType::Query => (do_query(config, data_slice), 0, 0),
                PerfType::Insert => {
                    let ans =
                        do_insert_and_get_sizes(config, data_slice).unwrap();
                    (Ok(ans.0), ans.1, ans.2)
                }
            };

            duration += result.0.unwrap();
            server_storage += result.1;
            client_storage += result.2;

            info!("Round #{:<04} finished.", idx);
        }
        duration /= round as u32;
        server_storage /= round as usize;
        client_storage /= round as usize;

        warn!(
            "[+] Perf {:?} finished against {:?}. Estimated latency is {:?}.",
            config.perf_type, config.fse_type, duration
        );

        res.push((duration, server_storage, client_storage));
    }

    Ok(res)
}

fn do_init(config: &PerfConfig, dataset: &[String]) -> Result<Duration> {
    let instant = Instant::now();
    match config.fse_type {
        FSEType::Dte | FSEType::Rnd => init_native(config, dataset),
        FSEType::LpfseIhbe | FSEType::LpfseBhe => init_lpfse(config, dataset),
        FSEType::Pfse => init_pfse(config, dataset),
        FSEType::Wre => unimplemented!(),
    }?;
    Ok(instant.elapsed())
}

fn do_insert_and_get_sizes(
    config: &PerfConfig,
    dataset: &[String],
) -> Result<(Duration, usize, usize)> {
    let instant = Instant::now();
    let (data, ctx) = match config.fse_type {
        FSEType::Dte | FSEType::Rnd => init_native(config, dataset),
        FSEType::LpfseIhbe | FSEType::LpfseBhe => init_lpfse(config, dataset),
        FSEType::Pfse => init_pfse(config, dataset),
        FSEType::Wre => unimplemented!(),
    }?;
    insert(ctx.get_conn(), &data, &format!("{:?}", config.fse_type))?;
    let server_storage = ctx.get_conn().size(&format!("{:?}", config.fse_type));
    let client_storage = ctx.size_allocated();
    Ok((instant.elapsed(), server_storage, client_storage))
}

fn do_query(config: &PerfConfig, dataset: &[String]) -> Result<Duration> {
    let (data, mut ctx) = match config.fse_type {
        FSEType::Dte | FSEType::Rnd => init_native(config, dataset),
        FSEType::LpfseIhbe | FSEType::LpfseBhe => init_lpfse(config, dataset),
        FSEType::Pfse => init_pfse(config, dataset),
        FSEType::Wre => unimplemented!(),
    }?;
    let name = format!("{:?}", config.fse_type);
    insert(ctx.get_conn(), &data, &name)?;

    let histogram = {
        let histogram = fse::util::build_histogram(dataset);
        fse::util::build_histogram_vec(&histogram)
    };
    let distribution = Uniform::new(0, histogram.len());
    let query_number = config.query_number.unwrap_or(100);

    let instant = Instant::now();
    for i in 0..query_number {
        let idx = distribution.sample(&mut OsRng);
        query(ctx.as_mut(), &histogram[idx].0, &name)?;
        debug!(
            "Query round {:<4?}: choosing {}; elapsed time {:?}",
            i,
            idx,
            instant.elapsed()
        );
    }
    Ok(instant.elapsed() / query_number as u32)
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
    if config.fse_params.is_none() {
        return Err("No FSE params found.".into());
    }

    let mut ctx = ContextPFSE::default();
    ctx.key_generate();
    ctx.set_params(config.fse_params.as_ref().unwrap());
    ctx.partition(dataset, exponential);
    ctx.transform();

    let ciphertexts = ctx
        .smooth()
        .into_iter()
        .map(|e| String::from_utf8(e).unwrap())
        .collect::<Vec<_>>();

    if let (Some(addr), Some(name)) = (&config.addr, &config.db_name) {
        ctx.initialize_conn(addr, name, config.drop);
    }

    Ok((ciphertexts, Box::new(ctx)))
}

fn init_lpfse(
    config: &PerfConfig,
    dataset: &[String],
) -> Result<(Vec<String>, Box<dyn BaseCrypto<String>>)> {
    let params = config.fse_params.as_ref().unwrap();
    let encoder: Box<dyn HomophoneEncoder<String>> =
        match config.fse_type == FSEType::LpfseBhe {
            true => Box::new(EncoderBHE::new()),
            false => Box::new(EncoderIHBE::new()),
        };
    let mut ctx = ContextLPFSE::new(params[0], encoder);
    ctx.key_generate();
    if let (Some(addr), Some(name)) = (&config.addr, &config.db_name) {
        ctx.initialize(dataset, addr, name, config.drop);
    } else {
        ctx.initialize(dataset, "", "", false);
    }

    let ciphertexts = dataset
        .iter()
        .map(|e| String::from_utf8(ctx.encrypt(e).unwrap().remove(0)).unwrap())
        .collect::<Vec<_>>();

    Ok((ciphertexts, Box::new(ctx)))
}

fn insert(
    conn: &Connector<Data>,
    dataset: &[String],
    collection_name: &str,
) -> Result<()> {
    let docs = dataset
        .iter()
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
