//! todo: Test security against inference attacks.
#![deny(clippy::needless_borrow)]
#![deny(clippy::unused_io_amount)]

mod attack;
mod config;
mod perf;

use clap::{Parser, ValueEnum};
use log::{error, info};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, ValueEnum, Clone)]
pub enum EvalType {
    Attack,
    Perf,
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
pub struct Args {
    /// The path to the configuration file.
    #[arg(short, long, default_value_t = String::from("./config.toml"))]
    config_path: String,
    /// The output path.
    #[arg(short, long, default_value_t = String::from("./data"))]
    output_path: String,
    /// The test round.
    #[arg(short, long, default_value_t = 10)]
    round: usize,
    /// How many test suites should be performed.
    #[arg(short, long)]
    suite_num: Option<usize>,
    #[arg(short, long, value_enum, default_value_t = EvalType::Attack)]
    /// The type of the evaluation you need to perform.
    evaluation_type: EvalType,
}

fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "INFO");
    }
    env_logger::init();

    let args = Args::parse();
    if let Err(e) = dispatcher(&args) {
        error!("Failed to execute the performance evaluation due to {}", e);
        return;
    }

    info!("Finished!");
}

fn dispatcher(args: &Args) -> Result<()> {
    info!("Doing {:?} evaluation.", args.evaluation_type);

    match args.evaluation_type {
        EvalType::Attack => attack::execute_attack(args),
        EvalType::Perf => perf::execute_perf(args),
    }
}
