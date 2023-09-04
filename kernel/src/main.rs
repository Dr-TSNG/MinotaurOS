#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![feature(asm_const)]
#![feature(btree_extract_if)]
#![feature(const_trait_impl)]
#![feature(naked_functions)]
#![feature(never_type)]

extern crate alloc;

mod arch;
mod boot;
pub mod config;
mod board;
mod logger;
mod mm;
mod processor;
mod result;
mod trap;
mod utils;

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use log::error;
use arch::shutdown;
use config::KERNEL_ADDR_OFFSET;
use crate::board::HART_CNT;
use crate::config::KERNEL_STACK_SIZE;
use crate::processor::hart::current_hart;

global_asm!(include_str!("entry.asm"));

const LOGO: &str = include_str!("../../logo.txt");

fn start_main_hart() {
    println!("{}", LOGO);
    mm::allocator::init();
    logger::init();
    trap::init();

    boot::init_root_task_address_space().unwrap();
}

#[naked]
#[no_mangle]
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
    start_main_hart();

    panic!("End of execution")
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    error!("----------------------------------");
    error!("     !!!   KERNEL PANIC   !!!     ");
    error!("----------------------------------");
    error!("{}", info);
    shutdown()
}
