#![no_std]
#![no_main]

extern crate alloc;
extern crate user_lib;

use user_lib::println;
use user_lib::syscall::{sys_exit_group, sys_fork, sys_sleep, sys_waitpid};

#[no_mangle]
fn main() {
    for i in 0..5 {
        let pid = sys_fork();
        if pid == 0 {
            println!("child process: {}", i);
            for _ in 0..2 {
                println!("child {} sleep 0.1 second", i);
                sys_sleep(0, 100_000_000);
            }
            println!("child process: {} exit", i);
            sys_exit_group(0);
        }
    }
    for _ in 0..5 {
        let mut status = 0;
        let child = sys_waitpid(-1, &mut status);
        println!("parent process: child {} exit with status {}", child, status);
    }
}
