use anyhow::Result;
use std::path::PathBuf;
use std::process::Command;
use clap::{Parser, Subcommand};

#[derive(Subcommand)]
pub enum Build {
    #[clap(name = "kernel")]
    Kernel(BuildConfig),
    #[clap(name = "user")]
    User(BuildConfig),
}

#[derive(Parser)]
pub struct BuildConfig {
    #[clap(long, default_value_t = false)]
    pub offline: bool,
    #[clap(long)]
    pub release: bool,
    #[clap(long, default_value = "qemu")]
    pub board: String,
    #[clap(long)]
    pub features: Vec<String>,
}

trait CommandExt {
    fn offline(&mut self, offline: bool) -> &mut Self;
    fn release(&mut self, release: bool) -> &mut Self;
    fn features(&mut self, features: &[String]) -> &mut Self;
}

impl CommandExt for Command {
    fn offline(&mut self, offline: bool) -> &mut Self {
        if offline { self.arg("--offline"); }
        self
    }
    fn release(&mut self, release: bool) -> &mut Self {
        if release { self.arg("--release"); }
        self
    }
    fn features(&mut self, features: &[String]) -> &mut Self {
        if !features.is_empty() {
        self.arg("--no-default-features");
            for feature in features {
                self.arg("--features").arg(feature);
            }
        }
        self
    }
}

pub fn run(command: Build) -> Result<()> {
    match command {
        Build::Kernel(config) => build_kernel(&config)?,
        Build::User(config) => build_user(&config)?,
    }
    Ok(())
}

pub fn build_dir_file(name: &str, release: bool) -> Result<PathBuf> {
    let debug_or_release = if release { "release" } else { "debug" };
    let path = std::path::absolute(format!("target/riscv64gc-unknown-none-elf/{}/{}", debug_or_release, name))?;
    Ok(path)
}

fn build_kernel(config: &BuildConfig) -> Result<()> {
    Command::new("cargo")
        .current_dir("kernel")
        .env("BOARD", &config.board)
        .arg("build")
        .offline(config.offline)
        .release(config.release)
        .features(&config.features)
        .arg("--features")
        .arg(format!("board_{}", config.board))
        .spawn()?.wait()?
        .exit_ok()?;
    Command::new("rust-objcopy")
        .arg("--binary-architecture=riscv64")
        .arg(build_dir_file("kernel", config.release)?)
        .arg("--strip-all")
        .arg("-O").arg("binary")
        .arg(build_dir_file("kernel.bin", config.release)?)
        .spawn()?.wait()?
        .exit_ok()?;
    Ok(())
}

fn build_user(config: &BuildConfig) -> Result<()> {
    Command::new("cargo")
        .current_dir("user")
        .arg("build")
        .offline(config.offline)
        .release(config.release)
        .spawn()?.wait()?
        .exit_ok()?;
    Ok(())
}
