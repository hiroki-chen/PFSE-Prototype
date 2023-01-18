//! todo: Test security against inference attacks.
#![allow(unused)]
mod attack;

use clap::Parser;
use log::{error, info};

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
    /// How many test suites should be perform.
    #[arg(short, long)]
    suite_num: Option<usize>,
}

fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "INFO");
    }
    env_logger::init();

    let args = Args::parse();
    if let Err(e) = attack::execute_attack(&args) {
        error!("Failed to execute the attack due to {}", e);
        return;
    }

    info!("Finished!");
}
