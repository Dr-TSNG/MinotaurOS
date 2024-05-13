#![no_std]
#![no_main]

use user_lib::syscall::{sys_execve, sys_fork, sys_waitpid};

#[no_mangle]
fn main() {
    if sys_fork() == 0 {
        sys_execve(
            "/busybox",
            &["busybox", "sh"],
            &["PATH=/:/bin:", "LD_LIBRARY_PATH=/:", "TERM=screen"],
        );
    } else {
        let mut result: i32 = 0;
        sys_waitpid(-1, &mut result);
    }
}
