use std::io::BufRead;
use anyhow::Result;
use std::process::Command;

pub fn run() -> Result<()> {
    let output = Command::new("rustup")
        .arg("target").arg("list")
        .spawn()?.wait_with_output()?;
    let targets = output.stdout.lines();
    if targets.filter(|line| line.as_ref().unwrap() == "riscv64gc-unknown-none-elf").count() == 0 {
        Command::new("rustup")
            .args(["target", "add", "riscv64gc-unknown-none-elf"])
            .spawn()?.wait()?
            .exit_ok()?;
    }
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
