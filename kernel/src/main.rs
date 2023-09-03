#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![feature(btree_extract_if)]
#![feature(const_trait_impl)]

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
use crate::processor::hart::current_hart;

global_asm!(include_str!("entry.asm"));

const LOGO: &str = include_str!("../../logo.txt");

static HART_READY: AtomicUsize = AtomicUsize::new(0);

static KERNEL_READY: AtomicBool = AtomicBool::new(false);

fn start_main_hart() {
    println!("{}", LOGO);
    while HART_READY.load(Ordering::Acquire) != HART_CNT - 1 {}
    println!("[kernel] All harts loaded");
    mm::allocator::init();
    logger::init();
    trap::init();

    boot::init_root_task_address_space().unwrap();
}

fn start_other_hart() {
    HART_READY.fetch_add(1, Ordering::SeqCst);
    while !KERNEL_READY.load(Ordering::Acquire) {}
    trap::init();
}

#[no_mangle]
pub unsafe fn pspace_main(hart_id: usize) {
    asm! {
    "add sp, sp, {}",
    "la t0, main",
    "add t0, t0, {}",
    "mv a0, {}",
    "jalr zero, 0(t0)",
    in(reg) KERNEL_ADDR_OFFSET,
    in(reg) KERNEL_ADDR_OFFSET,
    in(reg) hart_id,
    }
}

#[no_mangle]
fn main(hart_id: usize) -> ! {
    processor::hart::init(hart_id);
    if current_hart().id == 0 {
        start_main_hart();
    } else {
        start_other_hart();
    }

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
