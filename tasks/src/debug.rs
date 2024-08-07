use std::process::{Command, Stdio};
use anyhow::Result;
use clap::{Parser, Subcommand};
use crate::build;
use crate::build::BuildConfig;
use crate::run::RunConfig;

#[derive(Subcommand)]
pub enum Debug {
    #[clap(name = "server")]
    Server(RunConfig),
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
        Debug::Server(config) => debug_server(&config)?,
        Debug::Attach(config) => debug_attach(&config)?,
    }
    Ok(())
}

fn debug_server(config: &RunConfig) -> Result<()> {
    let build_config = BuildConfig {
        offline: false,
        release: config.release,
        features: config.features.clone(),
    };
    build::run(build::Build::Kernel(build_config))?;
    Command::new("qemu-system-riscv64")
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
        .arg("-device").arg("virtio-net-device,netdev=net")
        .arg("-netdev").arg("user,id=net")
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
