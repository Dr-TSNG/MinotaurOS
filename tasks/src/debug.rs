use std::process::{Command, Stdio};
use anyhow::Result;
use clap::{Parser, Subcommand};
use crate::build;
use crate::build::BuildConfig;
use crate::run::RunConfig;

#[derive(Subcommand)]
pub enum Debug {
    #[clap(name = "qemu")]
    Qemu(RunConfig),
    #[clap(name = "attach")]
    Attach(AttachConfig),
}

#[derive(Parser)]
pub struct AttachConfig {
    #[clap(long)]
    pub release: bool,
}

pub fn run(command: Debug) -> Result<()> {
    match command {
        Debug::Qemu(config) => debug_qemu(&config)?,
        Debug::Attach(config) => debug_attach(&config)?,
    }
    Ok(())
}

fn debug_qemu(config: &RunConfig) -> Result<()> {
    let build_config = BuildConfig {
        offline: false,
        release: config.release,
        board: "qemu".to_string(),
        features: config.features.clone(),
    };
    build::run(build::Build::Kernel(build_config))?;
    Command::new("qemu-system-riscv64")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .arg("-machine").arg("virt")
        .arg("-nographic")
        .arg("-kernel").arg(build::build_dir_file("kernel.bin", config.release)?)
        .arg("-smp").arg(format!("{}", config.smp))
        .arg("-m").arg(&config.mem)
        .arg("-drive").arg(format!("file={},if=none,format=raw,id=x0", &config.disk))
        .arg("-device").arg("virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0")
        .arg("-s").arg("-S")
        .spawn()?.wait()?;
    Ok(())
}

fn debug_attach(config: &AttachConfig) -> Result<()> {
    let file = build::build_dir_file("kernel", config.release)?;
    Command::new("riscv64-elf-gdb")
        .arg("-ex").arg(format!("file {}", file.to_string_lossy()))
        .arg("-ex").arg("set arch riscv:rv64")
        .arg("-ex").arg("target remote localhost:1234")
        .arg("-ex").arg("b main")
        .spawn()?.wait()?;
    Ok(())
}
