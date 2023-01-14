//! todo: Test security against inference attacks.
#![allow(unused)]
mod execute;

use clap::Parser;
use log::{error, info};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Args {
    /// The path to the configuration file.
    config_path: String,
}

fn main() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "INFO");
    }
    env_logger::init();

    let args = Args::parse();
    if let Err(e) = execute::execute_attack(&args.config_path) {
        error!("Failed to execute the attack due to {}", e);
    }

    info!("Finished!");
}
