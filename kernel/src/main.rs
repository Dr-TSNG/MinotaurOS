#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![feature(asm_const)]
#![feature(btree_extract_if)]
#![feature(const_trait_impl)]
#![feature(extract_if)]
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
mod config;
mod board;
mod debug;
mod driver;
mod fs;
mod mm;
mod process;
mod processor;
mod result;
mod trap;
mod utils;
mod sched;
mod sync;

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;
use log::error;
use arch::shutdown;
use config::KERNEL_ADDR_OFFSET;
use crate::config::{LINKAGE_EBSS, LINKAGE_SBSS};
use crate::processor::hart;
use crate::result::MosResult;

global_asm!(include_str!("entry.asm"));

const LOGO: &str = include_str!("../../logo.txt");

fn clear_bss() {
    unsafe {
        let len = LINKAGE_EBSS.0 - LINKAGE_SBSS.0;
        core::slice::from_raw_parts_mut(LINKAGE_SBSS.0 as *mut u8, len).fill(0);
    }
}

fn start_main_hart() -> MosResult {
    clear_bss();
    mm::allocator::init();
    debug::logger::init();
    hart::init(0);
    println!("[kernel] Display Logo");
    println!("{}", LOGO);

    trap::init();
    mm::vm_init()?;
    driver::init()?;
    fs::init()?;

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
    panic!("End of execution")
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
    // debug::unwind::print_stack_trace();
    shutdown()
}
