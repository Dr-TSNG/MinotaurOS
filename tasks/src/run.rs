use std::process::{Command, Stdio};
use anyhow::Result;
use clap::Parser;
use crate::build::BuildConfig;
use super::build;

#[derive(Parser)]
pub struct RunConfig {
    #[clap(long)]
    pub release: bool,
    #[clap(long, default_value = "2")]
    pub smp: u8,
    #[clap(long, default_value = "128M")]
    pub mem: String,
    #[clap(long, default_value = "prebuilts/rustsbi-qemu.bin")]
    pub bios: String,
    #[clap(long, default_value = "prebuilts/disk.img")]
    pub disk: String,
    #[clap(long)]
    pub features: Vec<String>,
}

pub fn run(config: &RunConfig) -> Result<()> {
    let build_config = BuildConfig {
        offline: false,
        release: config.release,
        features: config.features.clone(),
    };
    build::run(build::Build::Kernel(build_config))?;
    Command::new("qemu-system-riscv64")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .arg("-machine").arg("virt")
        .arg("-nographic")
        .arg("-bios").arg(&config.bios)
        .arg("-kernel").arg(build::build_dir_file("kernel.bin", config.release)?)
        .arg("-smp").arg(format!("{}", config.smp))
        .arg("-m").arg(&config.mem)
        .arg("-drive").arg(format!("file={},if=none,format=raw,id=x0", &config.disk))
        .arg("-device").arg("virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0")
        .spawn()?.wait()?
        .exit_ok()?;
    Ok(())
}
