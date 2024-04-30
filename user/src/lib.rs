#![no_std]
#![feature(linkage)]

extern crate alloc;

use alloc::vec::Vec;
use core::ffi::CStr;
use core::panic::PanicInfo;

use buddy_system_allocator::LockedHeap;

use crate::syscall::{sys_exit, sys_exit_group};

pub mod console;
pub mod syscall;

const USER_HEAP_SIZE: usize = 32768;

static mut HEAP_SPACE: [u8; USER_HEAP_SIZE] = [0; USER_HEAP_SIZE];

#[global_allocator]
static HEAP: LockedHeap<32> = LockedHeap::<32>::empty();

#[no_mangle]
#[link_section = ".text.entry"]
pub extern "C" fn _start(argc: usize, argv: *const *const i8) {
    unsafe {
        HEAP.lock().init(HEAP_SPACE.as_ptr() as usize, USER_HEAP_SIZE);
    }
    let mut v: Vec<&'static str> = Vec::new();
    for i in 0..argc {
        unsafe {
            let str = argv.add(i).read_volatile();
            let str = CStr::from_ptr(str);
            let str = str.to_str().unwrap();
            v.push(str);
        }
    }
    main(argc, v.as_slice());
    sys_exit(0);
}

#[linkage = "weak"]
#[no_mangle]
fn main(_argc: usize, _argv: &[&str]) {
    panic!("Cannot find main!");
}

#[panic_handler]
fn panic_handler(info: &PanicInfo) -> ! {
    println!("Panic: {}", info);
    sys_exit_group(-1);
}
