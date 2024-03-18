#![no_std]
#![no_main]

extern crate user_lib;

use user_lib::println;
use user_lib::syscall::{OpenFlags, sys_execve, sys_open, sys_read, sys_yield};

#[no_mangle]
fn main() -> i32 {
    println!("Hello World from userspace!");
    sys_yield();

    println!("Execute busybox");
    let r = sys_execve("/busybox", &["sh"], &["ASH_STANDALONE=1"]);
    println!("execve return: {}", r);
    0
}
