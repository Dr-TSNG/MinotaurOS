#![no_std]
#![no_main]

extern crate user_lib;

use user_lib::println;
use user_lib::syscall::sys_yield;

#[no_mangle]
fn main() -> i32 {
    println!("Hello World from userspace!");
    sys_yield();
    0
}
