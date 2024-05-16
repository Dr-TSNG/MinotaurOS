use anyhow::Result;
use std::process::Command;

pub fn run() -> Result<()> {
    Command::new("rustup")
        .args(["override", "set", "nightly-2024-02-03"])
        .spawn()?.wait()?
        .exit_ok()?;
    Command::new("rustup")
        .args(["target", "add", "riscv64gc-unknown-none-elf"])
        .spawn()?.wait()?
        .exit_ok()?;
    Command::new("rustup")
        .args(["component", "add", "rust-src"])
        .spawn()?.wait()?
        .exit_ok()?;
    Command::new("rustup")
        .args(["component", "add", "llvm-tools-preview"])
        .spawn()?.wait()?
        .exit_ok()?;
    Ok(())
}
