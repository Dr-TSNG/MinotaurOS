#![no_std]
#![no_main]
#![feature(asm_const)]
#![feature(naked_functions)]
#![feature(alloc_error_handler)]
#![feature(btree_extract_if)]

extern crate alloc;

mod boot;
mod board;
mod logger;
mod mm;
mod result;
mod processor;


use core::arch::{asm, global_asm};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use log::error;
use common::arch::shutdown;
use common::println;
use crate::board::{HART_CNT, KERNEL_STACK_SIZE};
use crate::processor::hart::current_hart;

global_asm!(include_str!("entry.asm"));

static HART_READY: AtomicUsize = AtomicUsize::new(0);

static KERNEL_READY: AtomicBool = AtomicBool::new(false);

static mut KERNEL_STACK: [u8; HART_CNT * KERNEL_STACK_SIZE] = [0; HART_CNT * KERNEL_STACK_SIZE];

#[naked]
#[no_mangle]
#[allow(undefined_naked_function_abi)]
pub fn setup_stack(hart: usize) {
    unsafe {
        asm! {
        "la sp, {0}",
        "mv t0, a0",
        "li t1, {1}",
        "mul t0, t0, t1",
        "add sp, sp, t0",
        "add sp, sp, t1",
        "jr ra",
        sym KERNEL_STACK,
        const KERNEL_STACK_SIZE,
        options(noreturn)
        }
    }
}

fn start_main_hart() {
    println!("[kernel] Minotaur OS");
    while HART_READY.load(Ordering::Acquire) != HART_CNT - 1 {}
    println!("[kernel] All harts loaded");
    mm::allocator::init();
    logger::init();

    boot::init_root_task_address_space().unwrap();
}

fn start_other_hart() {
    HART_READY.fetch_add(1, Ordering::SeqCst);
    while !KERNEL_READY.load(Ordering::Acquire) {}
}

#[no_mangle]
pub fn rust_main() -> ! {
    processor::hart::init();
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
