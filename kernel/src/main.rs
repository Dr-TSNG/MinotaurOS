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
#![feature(step_trait)]
#![feature(stmt_expr_attributes)]
#![feature(strict_provenance)]
#![feature(sync_unsafe_cell)]
#![feature(trait_upcasting)]

extern crate alloc;

mod arch;
mod builtin;
mod config;
mod debug;
mod driver;
mod fs;
mod mm;
mod net;
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
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use log::{error, info, warn};
use sbi_spec::hsm::hart_state;
use arch::shutdown;
use config::KERNEL_ADDR_OFFSET;
use crate::arch::sbi;
use crate::config::{KERNEL_PADDR_BASE, KERNEL_STACK_SIZE, LINKAGE_EBSS, LINKAGE_SBSS};
use crate::debug::console::dmesg_flush_tty;
use crate::driver::BOARD_INFO;
use crate::fs::page_cache::PageCache;
use crate::process::monitor::PROCESS_MONITOR;
use crate::process::Process;
use crate::processor::hart;
use crate::processor::hart::{KERNEL_STACK, local_hart};
use crate::result::SyscallResult;
use crate::sched::executor::run_executor;
use crate::sched::spawn_kernel_thread;
use crate::sched::time::cpu_time;
use crate::sched::timer::TimerFuture;
use crate::sync::block_on;

global_asm!(include_str!("entry.asm"));

const LOGO: &str = include_str!("../../logo.txt");

#[link_section = ".bss.uninit"]
static MAIN_HART: AtomicBool = AtomicBool::new(false);

fn clear_bss() {
    unsafe {
        let len = LINKAGE_EBSS.0 - LINKAGE_SBSS.0;
        core::slice::from_raw_parts_mut(LINKAGE_SBSS.as_ptr(), len).fill(0);
    }
}

fn start_main_hart(hart_id: usize, dtb_paddr: usize) -> SyscallResult<!> {
    clear_bss();
    hart::init(hart_id);
    mm::allocator::init_heap();
    driver::init_dtb(dtb_paddr);
    mm::allocator::init_user();
    debug::logger::init();

    println!("{}", LOGO);
    println!("========================================");
    println!("| boot hart id         | {:13} |", hart_id);
    println!("| smp                  | {:13} |", BOARD_INFO.smp);
    println!("| cpu frequency        | {:13} |", BOARD_INFO.freq);
    println!("| dtb physical address | {:#13x} |", dtb_paddr);
    println!("----------------------------------------");

    sched::init();
    trap::init();
    mm::vm_init(true)?;
    driver::init_driver()?;
    builtin::init();
    dmesg_flush_tty();
    net::init();

    let data = builtin::builtin_app("shell").unwrap();
    let mnt_ns = fs::init()?;
    info!("Spawn init process");
    block_on(Process::new_initproc(mnt_ns, data))?;

    #[cfg(feature = "monitor")]
    spawn_kernel_thread(TimerFuture::new(Duration::from_secs(1), monitor));

    for secondary in 0..BOARD_INFO.smp {
        if secondary != hart_id {
            if sbi::hart_status(secondary).unwrap() != hart_state::STOPPED {
                warn!("Hart {} is already started?", secondary);
            } else if let Err(e) = sbi::start_hart(secondary, KERNEL_PADDR_BASE.0) {
                warn!("Failed to start hart {}: {:?}", secondary, e);
            }
        }
    }

    sched::time::set_next_trigger();
    arch::enable_timer_interrupt();
    run_executor();

    info!("Init process exited, shutdown system");
    shutdown();
}

fn start_secondary_hart(hart_id: usize) -> SyscallResult<!> {
    hart::init(hart_id);
    mm::vm_init(false)?;
    info!("Start secondary hart {}", hart_id);

    sched::time::set_next_trigger();
    arch::enable_timer_interrupt();
    run_executor();

    info!("Stop hart {}", hart_id);
    sbi::stop_hart(hart_id).unwrap();
    unreachable!()
}

#[naked]
#[no_mangle]
#[allow(undefined_naked_function_abi)]
pub unsafe fn pspace_main() {
    asm! {
    "la t0, {0}",
    "li t1, {1}",
    "mul sp, a0, t1",
    "add sp, sp, t0",
    "add sp, sp, t1",
    "la t0, main",
    "li t1, {2}",
    "add sp, sp, t1",
    "add t0, t0, t1",
    "jalr zero, 0(t0)",
    sym KERNEL_STACK,
    const KERNEL_STACK_SIZE,
    const KERNEL_ADDR_OFFSET,
    options(noreturn),
    }
}

#[no_mangle]
fn main(hart_id: usize, dtb_paddr: usize) -> ! {
    if !MAIN_HART.load(Ordering::SeqCst) {
        MAIN_HART.store(true, Ordering::SeqCst);
        start_main_hart(hart_id, dtb_paddr).unwrap()
    } else {
        start_secondary_hart(hart_id).unwrap()
    }
}

fn monitor() -> Duration {
    let pc_holder = PageCache::holders();
    let pc_alloc = PageCache::allocated();
    println!(
        "[monitor] procs {}, pc_holder {}, pc_alloc {}",
        PROCESS_MONITOR.lock().count(), pc_holder, pc_alloc,
    );
    cpu_time() + Duration::from_secs(1)
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
    let thread = local_hart().ctx.user_task.as_ref().map(|t| &t.thread);
    let pid = thread.map(|t| t.process.pid.0);
    let tid = thread.map(|t| t.tid.0);
    error!("Context: pid {:?}, tid {:?}", pid, tid);
    monitor();
    shutdown()
}
