#![feature(absolute_path)]
#![feature(exit_status_error)]

mod build;
mod debug;
mod env;
mod run;

use anyhow::Result;
use clap::Parser;
use crate::build::Build;
use crate::debug::Debug;
use crate::run::RunConfig;

#[derive(Parser)]
#[clap(name = "MOS configure")]
#[clap(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    Build {
        #[command(subcommand)]
        command: Build,
    },
    Run(RunConfig),
    Debug {
        #[command(subcommand)]
        command: Debug,
    },
    Env,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Build { command} => build::run(command),
        Commands::Env => env::run(),
        Commands::Run(config) => run::run(&config),
        Commands::Debug { command } => debug::run(command),
    }
}
