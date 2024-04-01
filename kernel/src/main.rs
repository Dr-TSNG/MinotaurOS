#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![feature(asm_const)]
#![feature(btree_extract_if)]
#![feature(const_trait_impl)]
#![feature(inline_const)]
#![feature(naked_functions)]
#![feature(never_type)]
#![feature(option_take_if)]
#![feature(panic_info_message)]
#![feature(stmt_expr_attributes)]
#![feature(strict_provenance)]
#![feature(sync_unsafe_cell)]

extern crate alloc;

mod arch;
mod board;
mod builtin;
mod config;
mod debug;
mod driver;
mod fs;
mod mm;
mod process;
mod processor;
mod result;
mod sched;
mod signal;
mod sync;
mod syscall;
mod trap;

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;
use log::{error, info};
use arch::shutdown;
use config::KERNEL_ADDR_OFFSET;
use crate::config::{LINKAGE_EBSS, LINKAGE_SBSS};
use crate::process::Process;
use crate::processor::hart;
use crate::result::SyscallResult;
use crate::sched::spawn_kernel_thread;
use crate::sync::executor::run_executor;

global_asm!(include_str!("entry.asm"));

const LOGO: &str = include_str!("../../logo.txt");

fn clear_bss() {
    unsafe {
        let len = LINKAGE_EBSS.0 - LINKAGE_SBSS.0;
        core::slice::from_raw_parts_mut(LINKAGE_SBSS.as_ptr(), len).fill(0);
    }
}

fn start_main_hart() -> SyscallResult {
    clear_bss();
    hart::init(0);
    mm::allocator::init();
    debug::logger::init();
    println!("[kernel] Display Logo");
    println!("{}", LOGO);

    trap::init();
    mm::vm_init()?;
    driver::init()?;
    builtin::init();

    let data = builtin::builtin_app("init").unwrap();
    let mnt_ns = fs::init()?;
    info!("Spawn init process");
    spawn_kernel_thread(async move {
        Process::new_initproc(mnt_ns, data).await.unwrap();
    });

    sched::time::set_next_trigger();
    arch::enable_timer_interrupt();
    Ok(())
}

#[naked]
#[no_mangle]
#[allow(undefined_naked_function_abi)]
pub unsafe fn pspace_main(hart_id: usize) {
    asm! {
    "la t0, main",
    "li t1, {}",
    "add sp, sp, t1",
    "add t0, t0, t1",
    "jalr zero, 0(t0)",
    const KERNEL_ADDR_OFFSET,
    options(noreturn),
    }
}

#[no_mangle]
fn main() -> ! {
    start_main_hart().unwrap();
    run_executor();
    info!("All task finished, shutdown");
    shutdown()
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    error!("----------------------------------");
    error!("     !!!   KERNEL PANIC   !!!     ");
    error!("----------------------------------");
    if let Some(location) = info.location() {
        error!(
            "Panicked at {}:{} {}",
            location.file(),
            location.line(),
            info.message().unwrap()
        );
    } else {
        error!("Panicked: {}", info.message().unwrap());
    }
    shutdown()
}
