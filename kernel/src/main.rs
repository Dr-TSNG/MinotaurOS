#![no_std]
#![no_main]
#![allow(unused)]
#![feature(asm_const)]
#![feature(naked_functions)]

mod board;
mod logger;

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use common::arch::shutdown;
use common::println;
use crate::board::{HART_CNT, KERNEL_STACK_SIZE};

global_asm!(include_str!("entry.asm"));

static HART_READY: AtomicUsize = AtomicUsize::new(0);

static KERNEL_READY: AtomicBool = AtomicBool::new(false);

static mut KERNEL_STACK: [u8; HART_CNT * KERNEL_STACK_SIZE] = [0; HART_CNT * KERNEL_STACK_SIZE];

#[naked]
#[no_mangle]
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

#[no_mangle]
pub fn rust_main(hart: usize) -> ! {
    if hart == 0 {
        println!("[kernel] Minotaur OS");
        while HART_READY.load(Ordering::Acquire) != HART_CNT - 1 {}
        println!("[kernel] All harts loaded");
    } else {
        println!("[kernel] Hart {} boot into kernel", hart);
        HART_READY.fetch_add(1, Ordering::SeqCst);
        while !KERNEL_READY.load(Ordering::Acquire) {}
    }

    panic!("End of execution")
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("----------------------------------");
    println!("     !!!   KERNEL PANIC   !!!     ");
    println!("----------------------------------");
    println!("{}", info);
    shutdown()
}
